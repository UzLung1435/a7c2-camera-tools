#!/usr/bin/env python3
"""Start the 600-second 1.99-to-2.00 menu confirmation on installed 2.01."""

import argparse
from datetime import datetime, timezone
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
import update_code_hold_200 as hold
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb
sys.path.insert(0, str(ROOT / "release"))
import feature_package_200 as feature_package


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def preflight(serial, manifest_path, version_path, package_manifest):
    require_winusb(serial)
    _, selected_sha = feature_package.selected(package_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version_report = json.loads(version_path.read_text(encoding="utf-8"))
    card = json.loads((manifest_path.parent / "package_200_card_stage_receipt.json").read_text(
        encoding="utf-8"))
    p1 = json.loads((manifest_path.parent / "windows_p1_200_install_state.json").read_text(
        encoding="utf-8"))
    require(manifest.get("camera_usb_serial") == serial and
            manifest.get("source_camera_version") == "2.01" and
            manifest.get("target_package_version") == "2.00" and
            version_report.get("serial") == serial and
            version_report.get("dat4_hex") == "0102" and
            version_report.get("normal_mode_and_driver_verified_after_child_exit") is True and
            card.get("serial") == serial and card.get("active_sha256") ==
            selected_sha and
            p1.get("serial") == serial and p1.get("action") == "install" and
            p1.get("complete") is True,
            "signed source, selected card and p1 2.00 gate receipts required")
    hold.base.pinned_elf()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    manifest_path = args.p1_manifest.resolve()
    version_path = args.version_report.resolve()
    require(manifest_path.is_relative_to(ROOT.resolve()) and
            version_path.is_relative_to(ROOT.resolve()),
            "input reports must be inside Windows research workspace")
    hold.base.pinned_elf()
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     dat4_required="2.01", menu_version_during="1.99",
                     hold_seconds=600, elf_sha256=hold.base.ELF_SHA256)
        return 0
    preflight(args.serial, manifest_path, version_path, args.package_manifest)
    if not args.child:
        receipt_path = manifest_path.parent / "update_hold200_start_receipt.json"
        require(not receipt_path.exists(), "2.00 version hold receipt already exists")
        command = [sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial,
                                "--p1-manifest", str(manifest_path),
                                "--version-report", str(version_path),
                                "--execute", "--child"]
        command += ["--package-manifest", str(args.package_manifest)]
        child = subprocess.run(command, capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=300)
        (manifest_path.parent / "update_hold200_start.log").write_text(
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
                        if item.get("event") == "update_hold200_start"), None)
        require(target is not None and receipt is not None,
                "2.00 version hold child returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(receipt["product_verified"] and receipt["baseline_verified"] and
                receipt["payload_verified"] and receipt["arm_verified"] and
                receipt["trigger_ack"] and receipt["marker"]["complete"] and
                receipt["preload_cleanup"] == "verified_absent",
                "600-second 2.00 MENU version window not verified")
        receipt["normal_mode_and_driver_verified_after_child_exit"] = True
        receipt["host_receipt_utc"] = datetime.now(timezone.utc).isoformat()
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n",
                                encoding="utf-8")
        service.emit("update_hold200_verified", serial=args.serial,
                     marker=receipt["marker"], receipt=str(receipt_path))
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import windows_usb_adapter as adapter

    backend = hold.base.Backend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=ReadBudget(), usb_backend=windows_libusb.get_backend(),
        logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    receipt = {"event": "update_hold200_start", "serial": args.serial,
               "product_verified": backend.product_verified,
               "baseline_verified": backend.baseline_verified,
               "payload_verified": backend.payload_verified,
               "arm_verified": backend.arm_verified,
               "trigger_ack": backend.trigger_ack,
               "marker": backend.marker, "preload_cleanup": backend.cleanup,
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
