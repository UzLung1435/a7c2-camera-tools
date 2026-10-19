#!/usr/bin/env python3
"""Read the two fixed A7C II BK4 backup paths using Windows WinUSB."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as service
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb


def require(condition, message):
    if not condition:
        raise service.ProbeError(message)


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
            "snapshot directory must be inside the Windows research workspace")
    if not args.execute:
        print(json.dumps({"camera_access": False, "serial": args.serial,
                          "paths": ["/setting/Backup.bin", "/setting/Backup.bak"]}))
        return 0
    require_winusb(args.serial)
    if not args.child:
        out_dir.mkdir(parents=True, exist_ok=True)
        require(not any(out_dir.glob("a7c2-readonly-backup_*.bin")),
                "BK4 snapshots already exist in output directory")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--out-dir", str(out_dir),
                                "--execute", "--child"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=360)
        print(child.stdout, end="", flush=True)
        if child.stderr:
            print(child.stderr, file=sys.stderr, end="", flush=True)
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((event for event in events
                       if event.get("event") == "target_verified"), None)
        receipt = next((event for event in reversed(events)
                        if event.get("event") == "windows_bk4_snapshot"), None)
        require(target is not None and receipt is not None,
                "BK4 child returned no complete receipt")
        require(receipt["product_verified"] and receipt["query_observed"] and
                set(receipt["results"]) == {"backup_bin", "backup_bak"},
                "both BK4 reads did not complete")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        for item in receipt["results"].values():
            path = out_dir / item["private_snapshot"]
            require(path.is_file() and not path.is_symlink() and
                    path.stat().st_size == item["file_size"] and
                    file_sha(path) == item["file_sha256"],
                    "BK4 saved file hash or size differs")
        output = out_dir / "windows-bk4-receipt.json"
        require(not output.exists(), "BK4 receipt already exists")
        receipt["normal_mode_and_driver_verified_after_child_exit"] = True
        output.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        service.emit("windows_bk4_postflight_verified", serial=args.serial,
                     receipt=str(output))
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import cp_backup_color_snapshot_ro_205 as snapshot
    from jiritsu_libjit_read_probe import ReadBudget
    import jiritsu_version_probe as version
    import windows_usb_adapter as adapter

    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot.OUTPUT_DIR = out_dir

    original_product_info = snapshot.Session.product_info

    def diagnosed_product_info(self):
        try:
            return original_product_info(self)
        except AttributeError as exc:
            frames = traceback.extract_tb(exc.__traceback__)[-4:]
            service.emit("bk4_python_attribute_diagnostic",
                         attribute=getattr(exc, "name", None),
                         detail=str(exc)[:180],
                         frames=[{"file": Path(row.filename).name,
                                  "line": row.lineno, "function": row.name}
                                 for row in frames])
            raise

    snapshot.Session.product_info = diagnosed_product_info
    usb_backend = windows_libusb.get_backend()
    require(usb_backend is not None, "libusb backend unavailable")
    backend = snapshot.Backend(usb.core, usb.util, SonySenserAuthDevice,
                               SonySenserDevice, SonySenserCamera,
                               version.MSC_PID, version.PRODUCT,
                               budget=ReadBudget(), usb_backend=usb_backend,
                               logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    receipt = {"event": "windows_bk4_snapshot",
               "serial": args.serial,
               "product_verified": backend.product_verified,
               "query_observed": backend.query_observed,
               "results": backend.results,
               "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
               "child_code": code}
    print(json.dumps(receipt, ensure_ascii=False), flush=True)
    return 0 if backend.product_verified and backend.query_observed else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
