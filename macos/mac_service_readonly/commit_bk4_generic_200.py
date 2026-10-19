#!/usr/bin/env python3
"""Fresh BK4 snapshots, checked FL2/FL3 property commit, and independent readback."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sony-service-research"))
import mac_probe_fl23 as probe
import run_backup_snapshot_ro as identity
import p1_gate_generic_200 as p1
import cp_fl23_bk4_files_commit_200 as commit
import color_property_200 as color

TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"
SOURCE_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def snapshot(probe_json, destination):
    command = [sys.executable, str(ROOT / "run_backup_snapshot_ro.py"),
               "--probe-json", str(probe_json), "--out-dir", str(destination),
               "--execute"]
    status = subprocess.call(command)
    require(status == 0, "BK4 read-only snapshot or normal USB recovery failed")
    files = {}
    for label in ("backup_bin", "backup_bak"):
        matches = list(destination.glob(f"a7c2-readonly-{label}-*.bin"))
        require(len(matches) == 1, label + " snapshot count differs")
        files[label] = probe.bk4_report(matches[0])
    return files


def validate_backups(backups, expected_state):
    checksums = {}
    for label, item in backups.items():
        property_data = item.get("color_property") or {}
        require(item.get("size") == 2_390_264 and
                item.get("unique_color_property") is True and
                len(item.get("records", [])) == 2 and
                all(r.get("checksum_valid") is True for r in item["records"]) and
                property_data.get("id") == "0x02a40001" and
                property_data.get("attribute") == "0x8" and
                property_data.get("size") == 8192 and
                property_data.get("data_offset") == "0x1bba4c" and
                property_data.get("sha256") == (SOURCE_SHA if expected_state == "old" else TARGET_SHA),
                label + " BK4 identity, records, or color property differ")
        checksums[label] = item["records"][1]["stored_checksum"]
        if expected_state == "old":
            candidate = item.get("offline_bk4_candidate") or {}
            require(candidate.get("validated") is True and
                    candidate.get("checksum_delta") == 19569 and
                    candidate.get("changed_property_bytes") == 138,
                    label + " offline BK4 write simulation differs")
    return checksums


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-json", type=Path, required=True,
                        help="fresh MSC probe after the camera shows body version 2.00")
    parser.add_argument("--full-preflight-json", type=Path, required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--cp-runtime-receipt", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument("--action", choices=("commit", "verify"), required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    require(args.receipt_out is None or args.action == "verify",
            "BK4 receipt output is only supported for verify")
    require(sys.platform == "darwin", "macOS required")
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = identity.report_identity(report)
    manifest = p1.load_manifest(args.p1_manifest, args.full_preflight_json, camera)
    cp = json.loads(args.cp_runtime_receipt.read_text(encoding="utf-8"))
    observed = datetime.fromisoformat(cp.get("observed_utc", ""))
    age = (datetime.now(timezone.utc) - observed).total_seconds()
    require(cp.get("format") == 1 and
            cp.get("serial") == manifest["camera_usb_serial"] and
            cp.get("action") == "read-target" and
            cp.get("property_state") == "target" and
            cp.get("verified") is True and
            cp.get("normal_mode_and_driver_verified") is True and
            cp.get("marker", {}).get("complete") is True and
            cp["marker"].get("block_sha256") == TARGET_SHA and
            cp.get("p1_manifest_sha256") == hashlib.sha256(
                args.p1_manifest.read_bytes()).hexdigest() and
            0 <= age < 1200,
            "independent live CP target readback required before BK4 action")
    libusb = probe.dependencies().get("libusb_library")
    require(libusb and Path(libusb).is_file(), "probe libusb path is unavailable")
    if not args.execute:
        print(json.dumps({"camera_access": False, "action": args.action,
                          "camera_serial": manifest["camera_usb_serial"],
                          "dat4_required": "0x0200"}))
        return 0
    require(os.geteuid() == 0, "sudo with the configured Python is required")
    parent = args.p1_manifest.resolve().parent / (
        "snapshots_bk4_200_" + secrets.token_hex(8))
    parent.mkdir(mode=0o700)
    if args.action == "commit":
        before = snapshot(args.probe_json, parent / "before")
        states = [(before[label].get("color_property") or {}).get("state")
                  for label in ("backup_bin", "backup_bak")]
        if states == ["fl23_target", "fl23_target"]:
            checksums = validate_backups(before, "target")
            print("bk4_already_target_verified:", json.dumps({
                "camera_serial": manifest["camera_usb_serial"],
                "backup_sha256": {key: val["sha256"] for key, val in before.items()},
                "checksums": checksums,
                "read_only_snapshots": str(parent)}, sort_keys=True), flush=True)
            return 0
        old_checksums = validate_backups(before, "old")
        print("bk4_before_verified:", json.dumps(old_checksums, sort_keys=True), flush=True)
        sources = [Path(before[label]["path"]).resolve()
                   for label in ("backup_bin", "backup_bak")]
        require(all(source.is_relative_to(parent.resolve()) for source in sources) and
                color.from_backup(sources[0]) == color.from_backup(sources[1]),
                "two fresh BK4 source color properties differ")
        commit.base.ELF = color.materialize_named_worker(
            "bk4", ROOT / "p1_gate_200" / "libcodex_cp_fl23_bk4_files_200.so",
            parent / "libcodex_cp_fl23_bk4_files_200.so", sources[0])
        commit.base.pinned_elf()
        identity.ensure_camera_volumes_unmounted(camera, card, pmhome)
        status = commit.base.main(["--execute", "--msc-volumes-unmounted",
                                   "--card-and-pmhome-verified", "--msc-pid", "0e8a",
                                   "--pmca-path", str(ROOT), "--libusb", libusb])
        require(status == 0, "BK4 commit marker or normal USB recovery failed")
        after = snapshot(args.probe_json, parent / "after")
        new_checksums = validate_backups(after, "target")
        for label in old_checksums:
            require(int(new_checksums[label], 16) ==
                    ((int(old_checksums[label], 16) + 19569) & 0xffffffff),
                    label + " independent new BK4 checksum differs")
        print("bk4_commit_verified:", json.dumps({
            "camera_serial": manifest["camera_usb_serial"], "source_backup_sha256":
            {key: val["sha256"] for key, val in before.items()},
            "new_backup_sha256": {key: val["sha256"] for key, val in after.items()},
            "new_checksums": new_checksums,
            "read_only_snapshots": str(parent)}, sort_keys=True), flush=True)
    else:
        after = snapshot(args.probe_json, parent / "after")
        checksums = validate_backups(after, "target")
        if args.receipt_out is not None:
            output = args.receipt_out.resolve()
            require(output.is_relative_to(ROOT.resolve()) and
                    not output.exists(), "new BK4 verification receipt required")
            payload = {"format": 1, "camera_serial": manifest["camera_usb_serial"],
                       "action": "verify", "cp_runtime_receipt": str(args.cp_runtime_receipt),
                       "bk4_property_sha256": TARGET_SHA,
                       "backup_sha256": {key: val["sha256"] for key, val in after.items()},
                       "checksums": checksums, "both_bk4_verified": True}
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchown(fd, int(os.environ.get("SUDO_UID", os.geteuid())),
                          int(os.environ.get("SUDO_GID", os.getegid())))
                with os.fdopen(fd, "w", closefd=False, encoding="utf-8") as stream:
                    json.dump(payload, stream, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
        print("bk4_target_verified:", json.dumps({
            "camera_serial": manifest["camera_usb_serial"],
            "backup_sha256": {key: val["sha256"] for key, val in after.items()},
            "checksums": checksums,
            "read_only_snapshots": str(parent)}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
