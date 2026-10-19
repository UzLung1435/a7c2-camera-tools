#!/usr/bin/env python3
"""Read-only CP live FL2/FL3 color block on installed A7C II 2.00."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
sys.path.insert(0, str(ROOT / "service_reference"))
import service_probe as service
import jiritsu_version_probe as version
from jiritsu_libjit_read_probe import ReadBudget
import cp_color_block_ro_205a as original
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb

ELF = ROOT / "cp_color_200" / "libcodex_cp_color_block_ro200.so"
ELF_SHA = "bf16bfa2f06fb1a5381cced6c70ff52f3771921ad2e661baf0e96ca21db2cfff"
MAGIC = b"A7C2CPBLK205A\0\0\0"
RESULT = struct.Struct("<16s7IQ3i16s8192sI")
assert RESULT.size == 8276 and len(MAGIC) == 16


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def parse_marker(raw):
    require(isinstance(raw, bytes) and len(raw) == RESULT.size,
            "CP read-only marker length differs")
    (magic, version_no, stage, checks, pid, error, dat4, handle,
     phys, mode, first, second, name, block, crc) = RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    require(magic == MAGIC and version_no == 1 and zlib.crc32(copy) == crc,
            "CP read-only marker identity or CRC differs")
    digest = hashlib.sha256(block).hexdigest()
    return {"stage": stage, "checks": checks, "pid": pid, "error": error,
            "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
            "transfer_status": [mode, first, second],
            "block_sha256": digest,
            "selected_indices": {hex(k): block[0x1200 + k]
                                 for k in (0x0f, 0x29, 0x34, 0x35,
                                           0x36, 0x37, 0x38, 0x39)},
            "complete": (stage == 9 and checks == 0x7ff and pid > 1 and
                         error == 0 and dat4 == 0x200 and handle > 0 and
                         phys > 0 and phys % 16 == 0 and
                         mode == first == second == 0)}


def configure():
    report = json.loads((ROOT / "cp_color_200" / "manifest.json").read_text(
        encoding="utf-8"))
    entry = next((item for item in report["workers"]
                  if item["output_file"] == ELF.name), None)
    require(entry is not None and entry["output_sha256"] == ELF_SHA and
            entry["changed_file_offsets"] == ["0xc59"] and
            ELF.is_file() and ELF.stat().st_size == 19768 and
            hashlib.sha256(ELF.read_bytes()).hexdigest() == ELF_SHA,
            "2.00 read-only CP worker audit differs")
    base = original.base
    base.ELF = ELF
    base.ELF_SIZE = 19768
    base.ELF_SHA256 = ELF_SHA
    base.RESULT = RESULT
    base.MAGIC = MAGIC
    base.parse_marker = parse_marker
    base.pinned_elf()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    args.version_report = args.version_report.resolve()
    args.out = args.out.resolve()
    require(args.version_report.is_relative_to(ROOT.resolve()) and
            args.out.is_relative_to(ROOT.resolve()),
            "reports must stay inside research workspace")
    configure()
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     CP_color_VA="0x01793bb0", bytes=8192)
        return 0
    version_report = json.loads(args.version_report.read_text(encoding="utf-8"))
    require(version_report.get("serial") == args.serial and
            version_report.get("dat4_hex") == "0002" and
            version_report.get("normal_mode_and_driver_verified_after_child_exit") is True,
            "camera version 2.00 not verified")
    require_winusb(args.serial)
    if not args.child:
        require(not args.out.exists(), "CP read-only report already exists")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial,
                                "--version-report", str(args.version_report),
                                "--out", str(args.out), "--execute", "--child"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=300)
        (args.out.parent / (args.out.stem + ".log")).write_text(
            child.stdout + child.stderr, encoding="utf-8")
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((x for x in events if x.get("event") == "target_verified"), None)
        result = next((x for x in reversed(events)
                       if x.get("event") == "windows_cp_color_ro_200"), None)
        require(target is not None and result is not None,
                "CP read-only probe returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(result["product_verified"] and result["marker"]["complete"] and
                result["preload_cleanup"] == "verified_absent",
                "CP live color block readback not verified")
        result["normal_mode_and_driver_verified_after_child_exit"] = True
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        service.emit("windows_cp_color_ro_verified", serial=args.serial,
                     block_sha256=result["marker"]["block_sha256"],
                     selected_indices=result["marker"]["selected_indices"],
                     report=str(args.out))
        return 0

    import usb.core
    import usb.util
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import windows_usb_adapter as adapter

    base = original.base
    backend = base.Backend(usb.core, usb.util, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera,
                           version.MSC_PID, version.PRODUCT,
                           budget=ReadBudget(), usb_backend=windows_libusb.get_backend(),
                           logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    result = {"event": "windows_cp_color_ro_200", "serial": args.serial,
              "product_verified": backend.product_verified,
              "marker": backend.marker, "preload_cleanup": backend.cleanup,
              "stop_reason": backend.stop_reason,
              "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
              "child_code": code}
    print(json.dumps(result), flush=True)
    return 0 if backend.marker and backend.marker["complete"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
