#!/usr/bin/env python3
"""Remove only the final verified p1 capture's temporary camera Work files."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as service
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_p1_capture as capture
import windows_libusb


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def host_proof(out_dir, serial):
    import p1_block_window_protocol_201 as wire
    state = json.loads((out_dir / "p1-capture-state.json").read_text(encoding="utf-8"))
    require(state.get("complete") is True and state.get("serial") == serial and
            re.fullmatch(r"[0-9a-f]{32}", state.get("capture_id", "")),
            "completed p1 state for this camera required")
    previous = None
    for index in range(wire.CN1.windows):
        meta = capture.validate_window(out_dir, index, state["capture_id"], previous)
        require(meta["serial"] == serial, "p1 window belongs to another camera")
        previous = meta["manifest"]["manifest_sha256"]
    image = Path(state["image"])
    require(image.resolve().parent == out_dir and image.is_file() and
            image.stat().st_size == wire.CN1.bytes and
            capture.file_sha(image) == state["sha256"],
            "saved whole p1 image changed")
    return state, meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    out_dir = args.out_dir.resolve()
    require(out_dir.is_relative_to(ROOT.resolve()),
            "p1 directory must be inside the Windows research workspace")
    state, final = host_proof(out_dir, args.serial)
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     final_window=2, capture_id=state["capture_id"])
        return 0
    require_winusb(args.serial)
    if not args.child:
        receipt_path = out_dir / "p1-final-tmpfs-cleanup.json"
        require(not receipt_path.exists(), "p1 cleanup receipt already exists")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--out-dir", str(out_dir),
                                "--execute", "--child"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=360)
        (out_dir / "p1-cleanup.log").write_text(child.stdout + child.stderr,
                                                 encoding="utf-8")
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events
                       if item.get("event") == "target_verified"), None)
        receipt = next((item for item in reversed(events)
                        if item.get("event") == "windows_p1_cleanup"), None)
        require(target is not None and receipt is not None,
                "cleanup child returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(receipt["product_verified"] and
                (receipt["cleanup_complete"] or receipt["camera_manifest_absent"]),
                "final camera tmpfs window was not cleaned")
        receipt["normal_mode_and_driver_verified_after_child_exit"] = True
        capture.save_json(receipt_path, receipt)
        service.emit("windows_p1_cleanup_verified", receipt=str(receipt_path),
                     deleted_chunks=receipt["deleted_chunks"])
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import p1_block_window_protocol_201 as wire
    import p1_final_tmpfs_cleanup_201 as cleanup
    import jiritsu_version_probe as version
    from jiritsu_libjit_read_probe import ReadBudget
    import windows_usb_adapter as adapter

    expected = [{"offset": item["offset"], "sha256": item["sha256"],
                 "camera_crc32": item["crc32"]} for item in final["chunks"]]
    usb_backend = windows_libusb.get_backend()
    require(usb_backend is not None, "libusb backend unavailable")
    backend = cleanup.CleanupBackend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=ReadBudget(), usb_backend=usb_backend,
        logger=version.safe_logger(), profile=wire.CN1,
        capture_id=state["capture_id"], window_index=2,
        expected_manifest_sha256=final["manifest"]["manifest_sha256"],
        expected_chunks=expected)
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    receipt = {"event": "windows_p1_cleanup", "serial": args.serial,
               "capture_id": state["capture_id"],
               "product_verified": backend.product_verified,
               "camera_manifest_verified": backend.camera_manifest_verified,
               "camera_manifest_absent": backend.camera_manifest_absent,
               "deleted_chunks": backend.deleted_chunks,
               "already_absent_chunks": backend.already_absent_chunks,
               "cleanup_complete": backend.cleanup_complete,
               "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
               "child_code": code}
    print(json.dumps(receipt), flush=True)
    return 0 if receipt["product_verified"] and (
        receipt["cleanup_complete"] or receipt["camera_manifest_absent"]) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
