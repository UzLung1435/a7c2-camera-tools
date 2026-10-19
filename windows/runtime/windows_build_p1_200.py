#!/usr/bin/env python3
"""Offline per-camera p1 gates for the verified 2.01-to-FL23-2.00 path."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
import build_p1_gate_200 as builder
import mac_probe_fl23 as probe
import windows_p1_cleanup as capture

PROPERTY_OFFICIAL_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--bk4-dir", type=Path, required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    capture_dir, bk4_dir = args.capture_dir.resolve(), args.bk4_dir.resolve()
    out_dir, version_report = args.out_dir.resolve(), args.version_report.resolve()
    require(all(path.is_relative_to(ROOT.resolve()) for path in
                (capture_dir, bk4_dir, out_dir, version_report)) and
            not out_dir.exists(),
            "input/output paths must be inside workspace; output must be new")
    state, _ = capture.host_proof(capture_dir, args.serial)
    cleanup = json.loads((capture_dir / "p1-final-tmpfs-cleanup.json").read_text(
        encoding="utf-8"))
    require(cleanup.get("serial") == args.serial and
            cleanup.get("capture_id") == state["capture_id"] and
            cleanup.get("normal_mode_and_driver_verified_after_child_exit") is True and
            (cleanup.get("cleanup_complete") or cleanup.get("camera_manifest_absent")),
            "p1 final camera temporary window not proven cleaned")
    version = json.loads(version_report.read_text(encoding="utf-8"))
    require(version.get("serial") == args.serial and
            version.get("dat4_hex") == "0102" and
            version.get("updater_library_matches_official_201") is True and
            version.get("normal_mode_and_driver_verified_after_child_exit") is True,
            "camera version 2.01 or updater library not verified")
    bk4 = json.loads((bk4_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    require(bk4.get("serial") == args.serial and
            bk4.get("normal_mode_and_driver_verified_after_child_exit") is True and
            set(bk4.get("results", {})) == {"backup_bin", "backup_bak"},
            "both BK4 baseline snapshots required")
    for item in bk4["results"].values():
        path = bk4_dir / item["private_snapshot"]
        require(path.is_file() and not path.is_symlink() and
                hashlib.sha256(path.read_bytes()).hexdigest() ==
                item["file_sha256"] and
                item["property_sha256"] == PROPERTY_OFFICIAL_SHA and
                item["bk4_record_checksum_verified"] is True,
                "BK4 baseline property or file hash differs")
    source = Path(state["image"])
    fat = builder.validate_fat(source, state["sha256"])
    source_bytes = source.read_bytes()
    candidate, stages = builder.make_candidates(source_bytes)
    require(len(stages) == 2 and stages[0]["stage"] == "dual" and
            stages[1]["stage"] == "triple", "p1 gate stages differ")
    out_dir.mkdir(parents=True)
    image = out_dir / "p1_triple_gate_200_candidate.img"
    builder.private_file(image, candidate)
    result = probe.p1_report(image)
    require(result["sha256"] == hashlib.sha256(candidate).hexdigest() and
            result["p1chksum"]["initrd_md5_matches"] is True,
            "2.00 gate candidate readback differs")
    workers = builder.build_worker_templates(out_dir, stages,
                                             source_bytes, candidate)
    manifest = {"format": 1, "camera": "ILCE-7CM2",
                "source_camera_version": "2.01", "target_package_version": "2.00",
                "camera_usb_serial": args.serial,
                "source_p1_sha256": state["sha256"],
                "source_p1_path": str(source),
                "target_p1_sha256": result["sha256"],
                "target_p1_path": str(image),
                "source_initrd_sha256": fat["initrd"]["sha256"],
                "target_initrd_sha256": result["initrd"]["sha256"],
                "stages": stages, "workers": workers,
                "camera_access": False, "candidate_readback_verified": True,
                "p1_capture_id": state["capture_id"],
                "bk4_baseline_snapshot_dir": str(bk4_dir)}
    path = out_dir / "p1_gate_200_windows_manifest.json"
    builder.private_file(path, (json.dumps(manifest, indent=2) + "\n").encode())
    print(json.dumps({"event": "p1_200_offline_built",
                      "serial": args.serial, "source_sha256": state["sha256"],
                      "candidate_sha256": result["sha256"],
                      "manifest": str(path), "camera_access": False}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
