#!/usr/bin/env python3
"""Commit the verified FL2/FL3 BK4 property on an installed A7C II 2.00."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as service
import jiritsu_version_probe as version
from jiritsu_libjit_read_probe import ReadBudget
import cp_fl23_bk4_files_commit_200 as commit
import color_property_200 as color
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb

SOURCE_PROPERTY_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
TARGET_PROPERTY_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def preflight(args):
    require_winusb(args.serial)
    manifest = json.loads(args.p1_manifest.read_text(encoding="utf-8"))
    version_report = json.loads(args.version_report.read_text(encoding="utf-8"))
    before = json.loads((args.before_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    restored = json.loads((args.p1_manifest.parent /
                           "windows_p1_200_restore_state.json").read_text(
                               encoding="utf-8"))
    require(manifest.get("camera_usb_serial") == args.serial and
            manifest.get("target_package_version") == "2.00" and
            version_report.get("serial") == args.serial and
            version_report.get("dat4_hex") == "0002" and
            version_report.get("normal_mode_and_driver_verified_after_child_exit") is True and
            restored.get("serial") == args.serial and
            restored.get("action") == "restore" and restored.get("complete") is True and
            before.get("serial") == args.serial and
            before.get("normal_mode_and_driver_verified_after_child_exit") is True and
            set(before.get("results", {})) == {"backup_bin", "backup_bak"},
            "installed 2.00, restored p1 and two fresh BK4 snapshots required")
    for item in before["results"].values():
        require(item["property_sha256"] == SOURCE_PROPERTY_SHA and
                item["bk4_record_checksum_verified"] is True and
                item["property_length"] == 8192 and
                item["property_attr"] == "0x8",
                "BK4 source property differs")
    if args.after_ram_report is not None:
        ram = json.loads(args.after_ram_report.read_text(encoding="utf-8"))
        require(ram.get("serial") == args.serial and
                ram.get("marker", {}).get("complete") is True and
                ram["marker"].get("dat4") == "0x200" and
                ram["marker"].get("before_kind") == 1 and
                ram["marker"].get("after_kind") == 2 and
                ram.get("normal_mode_and_driver_verified_after_child_exit") is True,
                "verified live CP color RAM write required")
    sources = []
    for item in before["results"].values():
        source = args.before_dir / item["private_snapshot"]
        require(source.is_file() and not source.is_symlink() and
                hashlib.sha256(source.read_bytes()).hexdigest() ==
                item["file_sha256"], "saved BK4 source hash differs")
        sources.append(source)
    require(color.from_backup(sources[0]) == color.from_backup(sources[1]),
            "saved BK4 source properties differ")
    commit.base.ELF = color.materialize_named_worker(
        "bk4", ROOT / "core" / "p1_gate_200" /
        "libcodex_cp_fl23_bk4_files_200.so",
        args.p1_manifest.parent / "libcodex_cp_fl23_bk4_files_200.so",
        sources[0])
    commit.base.pinned_elf()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--before-dir", type=Path, required=True)
    parser.add_argument("--after-ram-report", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    args.p1_manifest = args.p1_manifest.resolve()
    args.version_report = args.version_report.resolve()
    args.before_dir = args.before_dir.resolve()
    if args.after_ram_report is not None:
        args.after_ram_report = args.after_ram_report.resolve()
    require(all(path.is_relative_to(ROOT.resolve()) for path in
                (args.p1_manifest, args.version_report, args.before_dir,
                 *((args.after_ram_report,) if args.after_ram_report else ()))),
            "input reports must be inside research workspace")
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     installed_dat4_required="2.00",
                     target_property_sha256=TARGET_PROPERTY_SHA)
        return 0
    preflight(args)
    if not args.child:
        suffix = "_after_ram" if args.after_ram_report else ""
        output = args.p1_manifest.parent / f"windows_bk4_commit_200{suffix}_receipt.json"
        require(not output.exists(), "BK4 commit receipt already exists")
        command = [sys.executable, str(Path(__file__).resolve()),
                   "--serial", args.serial,
                   "--p1-manifest", str(args.p1_manifest),
                   "--version-report", str(args.version_report),
                   "--before-dir", str(args.before_dir),
                   "--execute", "--child"]
        if args.after_ram_report is not None:
            command += ["--after-ram-report", str(args.after_ram_report)]
        child = subprocess.run(command, capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=300)
        (args.p1_manifest.parent / f"windows_bk4_commit_200{suffix}.log").write_text(
            child.stdout + child.stderr, encoding="utf-8")
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events
                       if item.get("event") == "target_verified"), None)
        receipt = next((item for item in reversed(events)
                        if item.get("event") == "windows_bk4_commit_200"), None)
        require(target is not None and receipt is not None,
                "BK4 commit child returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(receipt["product_verified"] and receipt["baseline_verified"] and
                receipt["payload_verified"] and receipt["arm_verified"] and
                receipt["trigger_ack"] and receipt["marker"]["complete"] and
                receipt["preload_cleanup"] == "verified_absent",
                "BK4 commit marker or USB cleanup did not verify")
        receipt["normal_mode_and_driver_verified_after_child_exit"] = True
        output.write_text(json.dumps(receipt, indent=2) + "\n",
                          encoding="utf-8")
        service.emit("windows_bk4_commit_verified", serial=args.serial,
                     marker=receipt["marker"], receipt=str(output))
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import windows_usb_adapter as adapter

    backend = commit.base.Backend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=ReadBudget(), usb_backend=windows_libusb.get_backend(),
        logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    receipt = {"event": "windows_bk4_commit_200", "serial": args.serial,
               "product_verified": backend.product_verified,
               "baseline_verified": backend.baseline_verified,
               "payload_verified": backend.payload_verified,
               "arm_verified": backend.arm_verified,
               "trigger_ack": backend.trigger_ack,
               "marker": backend.marker,
               "preload_cleanup": backend.cleanup,
               "stop_reason": backend.stop_reason,
               "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
               "child_code": code}
    print(json.dumps(receipt), flush=True)
    return 0 if backend.marker and backend.marker["complete"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
