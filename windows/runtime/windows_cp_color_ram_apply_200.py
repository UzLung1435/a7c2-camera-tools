#!/usr/bin/env python3
"""Apply the tested FL2/FL3 8 KiB CP color table in live RAM on A7C II 2.00."""

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
import cp_fl23_color_ram_apply_205 as original
import color_property_200 as color
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb

ELF = ROOT / "cp_color_200" / "libcodex_cp_fl23_color_ram_apply200.so"
ELF_SHA = "cb340b31cb5fccb564da61c14b03c609e82ba0c901aaf5ee2da541e8a5a8987f"
SOURCE_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"
MAGIC = b"A7C2CPCLR205A\0\0\0"
RESULT = struct.Struct("<16s8IQ11i5I")
assert RESULT.size == 120 and len(MAGIC) == 16


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def parse_marker(raw):
    require(isinstance(raw, bytes) and len(raw) == RESULT.size,
            "CP RAM marker length differs")
    (magic, version_no, stage, checks, pid, error, dat4, handle, mode,
     phys, before0, before1, cache0, cache1, write0, write1,
     postcache0, postcache1, after0, after1, emergency,
     before_kind, after_kind, crc_before, crc_after, crc) = RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    require(magic == MAGIC and version_no == 1 and zlib.crc32(copy) == crc,
            "CP RAM marker identity or CRC differs")
    statuses = [before0, before1, cache0, cache1, write0, write1,
                postcache0, postcache1, after0, after1]
    complete = (stage == 9 and checks == 0x7ff and pid > 1 and error == 0 and
                dat4 == 0x200 and handle > 0 and phys > 0 and phys % 16 == 0 and
                mode == 0 and statuses == [0] * 10 and
                emergency == -2147483648 and before_kind == 1 and after_kind == 2 and
                crc_before == 0xbcc3f1af and crc_after == 0x080b1a7d)
    return {"stage": stage, "checks": checks, "pid": pid, "error": error,
            "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
            "mode": mode, "statuses": statuses,
            "emergency_restore": emergency,
            "before_kind": before_kind, "after_kind": after_kind,
            "crc_before": hex(crc_before), "crc_after": hex(crc_after),
            "complete": complete}


def configure(args):
    manifest = json.loads((ROOT / "cp_color_200" / "manifest.json").read_text(
        encoding="utf-8"))
    entry = next((item for item in manifest["workers"]
                  if item["output_file"] == ELF.name), None)
    require(entry is not None and entry["output_sha256"] == ELF_SHA and
            entry["changed_file_offsets"] == ["0x4db1"] and
            manifest["source_property_sha256"] == SOURCE_SHA and
            manifest["target_property_sha256"] == TARGET_SHA,
            "2.00 CP RAM worker audit differs")
    receipt = json.loads((args.bk4_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    require(receipt.get("serial") == args.serial and
            set(receipt.get("results", {})) == {"backup_bin", "backup_bak"},
            "two saved source BK4 files required for CP worker")
    sources = []
    for item in receipt["results"].values():
        source = args.bk4_dir / item["private_snapshot"]
        require(source.is_file() and not source.is_symlink() and
                hashlib.sha256(source.read_bytes()).hexdigest() ==
                item["file_sha256"], "saved BK4 file hash differs")
        sources.append(source)
    require(color.from_backup(sources[0]) == color.from_backup(sources[1]),
            "saved BK4 color properties differ")
    private_elf = color.materialize_named_worker(
        "ram", ELF, args.out.parent / ELF.name, sources[0])
    base = original.base
    base.ELF = private_elf
    base.ELF_SIZE = 41296
    base.ELF_SHA256 = ELF_SHA
    base.RESULT = RESULT
    base.MAGIC = MAGIC
    base.parse_marker = parse_marker
    base.pinned_elf()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--before-cp-report", type=Path, required=True)
    parser.add_argument("--bk4-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    for field in ("version_report", "before_cp_report", "bk4_dir", "out"):
        path = getattr(args, field).resolve()
        require(path.is_relative_to(ROOT.resolve()),
                "CP RAM input/output path outside research workspace")
        setattr(args, field, path)
    configure(args)
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     before_property_sha256=SOURCE_SHA,
                     target_property_sha256=TARGET_SHA)
        return 0
    version_report = json.loads(args.version_report.read_text(encoding="utf-8"))
    cp_before = json.loads(args.before_cp_report.read_text(encoding="utf-8"))
    bk4 = json.loads((args.bk4_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    require(version_report.get("serial") == args.serial and
            version_report.get("dat4_hex") == "0002" and
            cp_before.get("serial") == args.serial and
            cp_before.get("marker", {}).get("complete") is True and
            cp_before["marker"].get("block_sha256") == SOURCE_SHA and
            cp_before.get("normal_mode_and_driver_verified_after_child_exit") is True and
            bk4.get("serial") == args.serial and
            bk4.get("normal_mode_and_driver_verified_after_child_exit") is True and
            set(bk4.get("results", {})) == {"backup_bin", "backup_bak"} and
            all(item.get("property_sha256") == SOURCE_SHA for item in
                bk4["results"].values()),
            "live CP and both BK4 files must contain the exact original property")
    require_winusb(args.serial)
    if not args.child:
        require(not args.out.exists(), "CP RAM apply receipt already exists")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial,
                                "--version-report", str(args.version_report),
                                "--before-cp-report", str(args.before_cp_report),
                                "--bk4-dir", str(args.bk4_dir),
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
                       if x.get("event") == "windows_cp_color_ram_apply_200"), None)
        require(target is not None and result is not None,
                "CP RAM apply returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(result["product_verified"] and result["marker"]["complete"] and
                result["preload_cleanup"] == "verified_absent",
                "CP RAM target write/readback not verified")
        result["normal_mode_and_driver_verified_after_child_exit"] = True
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        service.emit("windows_cp_color_ram_verified", serial=args.serial,
                     marker=result["marker"], receipt=str(args.out))
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
    result = {"event": "windows_cp_color_ram_apply_200", "serial": args.serial,
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
