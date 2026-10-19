#!/usr/bin/env python3
"""Guarded Mac CP FL2/FL3 runtime read and RAM apply for A7C II 2.00."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "sony-service-research"))
import fl23_state_ro_201 as worker
import mac_probe_fl23 as probe
import p1_gate_generic_200 as gate
import run_backup_snapshot_ro as identity
import color_property_200 as color

OLD_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"
READ_ELF = "libcodex_cp_color_block_ro200.so"
READ_SHA = "bf16bfa2f06fb1a5381cced6c70ff52f3771921ad2e661baf0e96ca21db2cfff"
APPLY_ELF = "libcodex_cp_fl23_color_ram_apply200.so"
APPLY_SHA = "cb340b31cb5fccb564da61c14b03c609e82ba0c901aaf5ee2da541e8a5a8987f"
READ_RESULT = struct.Struct("<16s7IQ3i16s8192sI")
APPLY_RESULT = struct.Struct("<16s8IQ11i5I")
READ_MAGIC = b"A7C2CPBLK205A\0\0\0"
APPLY_MAGIC = b"A7C2CPCLR205A\0\0\0"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_marker(raw):
    require(len(raw) == READ_RESULT.size, "CP read marker length differs")
    (magic, version, stage, checks, pid, error, dat4, handle, phys,
     mode, first, second, _name, block, crc) = READ_RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    require(magic == READ_MAGIC and version == 1 and zlib.crc32(copy) == crc,
            "CP read marker identity or CRC differs")
    return {"stage": stage, "checks": checks, "pid": pid, "error": error,
            "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
            "transfer_status": [mode, first, second],
            "block_sha256": hashlib.sha256(block).hexdigest(),
            "selected_indices": {hex(k): block[0x1200 + k]
                                 for k in (0x36, 0x37, 0x38, 0x39)},
            "complete": (stage == 9 and checks == 0x7ff and pid > 1 and
                         error == 0 and dat4 == 0x200 and handle > 0 and
                         phys > 0 and phys % 16 == 0 and
                         mode == first == second == 0)}


def apply_marker(raw):
    require(len(raw) == APPLY_RESULT.size, "CP apply marker length differs")
    (magic, version, stage, checks, pid, error, dat4, handle, mode, phys,
     before0, before1, cache0, cache1, write0, write1,
     postcache0, postcache1, after0, after1, emergency,
     before_kind, after_kind, crc_before, crc_after, crc) = APPLY_RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    require(magic == APPLY_MAGIC and version == 1 and zlib.crc32(copy) == crc,
            "CP apply marker identity or CRC differs")
    statuses = [before0, before1, cache0, cache1, write0, write1,
                postcache0, postcache1, after0, after1]
    return {"stage": stage, "checks": checks, "pid": pid, "error": error,
            "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
            "mode": mode, "statuses": statuses,
            "emergency_restore": emergency,
            "before_kind": before_kind, "after_kind": after_kind,
            "crc_before": hex(crc_before), "crc_after": hex(crc_after),
            "complete": (stage == 9 and checks == 0x7ff and pid > 1 and
                         error == 0 and dat4 == 0x200 and handle > 0 and
                         phys > 0 and phys % 16 == 0 and mode == 0 and
                         statuses == [0] * 10 and emergency == -2147483648 and
                         before_kind == 1 and after_kind == 2 and
                         crc_before == 0xbcc3f1af and crc_after == 0x080b1a7d)}


def configure(action, full_preflight_json, output):
    manifest = json.loads((ROOT / "cp_color_200" / "manifest.json").read_text(
        encoding="utf-8"))
    require(manifest.get("source_property_sha256") == OLD_SHA and
            manifest.get("target_property_sha256") == TARGET_SHA and
            manifest.get("target_dat4_required") == "0x0200",
            "CP worker manifest differs")
    is_apply = action == "apply"
    name, expected, changed, size = ((APPLY_ELF, APPLY_SHA, "0x4db1", 41296)
                                     if is_apply else
                                     (READ_ELF, READ_SHA, "0xc59", 19768))
    entry = next((x for x in manifest["workers"] if x["output_file"] == name), None)
    path = ROOT / "cp_color_200" / name
    require(entry is not None and entry["output_sha256"] == expected and
            entry["changed_file_offsets"] == [changed],
            "CP 2.00 worker SHA or one-byte version patch differs")
    if is_apply:
        report = json.loads(full_preflight_json.read_text(encoding="utf-8"))
        backups = report.get("backups", {})
        require(set(backups) == {"backup_bin", "backup_bak"},
                "two saved official BK4 files required for CP worker")
        sources = [Path(backups[label]["path"]).resolve()
                   for label in ("backup_bin", "backup_bak")]
        require(all(source.is_relative_to(ROOT.resolve()) for source in sources) and
                color.from_backup(sources[0]) == color.from_backup(sources[1]),
                "saved BK4 source color properties differ")
        path = color.materialize_named_worker(
            "ram", path, output.parent / APPLY_ELF, sources[0])
    else:
        require(path.is_file() and not path.is_symlink() and
                path.stat().st_size == size and
                hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "CP read worker SHA differs")
    source_name = ("libcodex_cp_fl23_color_ram_apply205.so" if is_apply else
                   "libcodex_cp_color_block_ro205a.so")
    marker_name = ("codex_cp_fl23_color_ram_apply205.bin" if is_apply else
                   "codex_cp_color_block_ro205a.bin")
    worker.ELF = path
    worker.ELF_SIZE = size
    worker.ELF_SHA256 = expected
    worker.RAM = worker.PREFIX + b"/tmp_wbshd/" + source_name.encode()
    worker.MARKER = worker.PREFIX + b"/tmp_wbshd/" + marker_name.encode()
    worker.ARM = ("/tmp_wbshd/" + source_name + "\n").encode()
    worker.RESULT = APPLY_RESULT if is_apply else READ_RESULT
    worker.MAGIC = APPLY_MAGIC if is_apply else READ_MAGIC
    worker.parse_marker = apply_marker if is_apply else read_marker
    worker.pinned_elf()


def verify_old_receipt(path, serial):
    item = json.loads(path.read_text(encoding="utf-8"))
    require(item.get("format") == 1 and item.get("serial") == serial and
            item.get("action") in ("read-old", "read-current") and
            item.get("property_state") == "old" and
            item.get("verified") is True and
            item.get("normal_mode_and_driver_verified") is True and
            item.get("marker", {}).get("block_sha256") == OLD_SHA,
            "verified live CP original read receipt required before RAM write")


def save_private(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("read-old", "read-current",
                                            "read-target", "apply"), required=True)
    parser.add_argument("--probe-json", type=Path, required=True)
    parser.add_argument("--full-preflight-json", type=Path, required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--read-receipt", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.platform == "darwin", "macOS required")
    require(args.out.resolve().is_relative_to(ROOT.resolve()),
            "private CP output must be in the package workspace")
    configure(args.action, args.full_preflight_json, args.out)
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = identity.report_identity(report)
    gate.load_manifest(args.p1_manifest, args.full_preflight_json, camera)
    serial = camera["serial_num"]
    require(re.fullmatch(r"[0-9A-Fa-f]{12}", serial), "camera serial differs")
    if args.action == "apply":
        require(args.read_receipt is not None, "old CP read receipt required")
        verify_old_receipt(args.read_receipt, serial)
    else:
        require(args.read_receipt is None, "read action takes no prior receipt")
    if not args.execute:
        print(json.dumps({"camera_access": False, "action": args.action,
                          "serial": serial, "elf_sha256": worker.ELF_SHA256}))
        return 0
    require(args.out.resolve().is_relative_to(ROOT.resolve()) and
            not args.out.exists(), "new private CP receipt path required")
    libusb = probe.dependencies().get("libusb_library")
    require(libusb and Path(libusb).is_file(), "libusb unavailable")
    identity.ensure_camera_volumes_unmounted(camera, card, pmhome)
    command = [sys.executable, str(Path(__file__).resolve()),
               "--action", args.action, "--probe-json", str(args.probe_json),
               "--full-preflight-json", str(args.full_preflight_json),
               "--p1-manifest", str(args.p1_manifest), "--out", str(args.out),
               "--execute", "--child"]
    if args.read_receipt:
        command += ["--read-receipt", str(args.read_receipt)]
    if args.child:
        require(os.geteuid() == 0 and
                not identity.live_preflight(camera, card, pmhome),
                "root and two verified unmounted camera volumes required")
        return worker.main(["--execute", "--msc-volumes-unmounted",
                            "--card-and-pmhome-verified", "--msc-pid", "0e8a",
                            "--pmca-path", str(ROOT), "--libusb", str(libusb)])
    if os.geteuid() != 0:
        command.insert(0, "sudo")
    child = subprocess.run(command, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=360)
    log = args.out.with_suffix(".log")
    log.write_text(child.stdout + child.stderr, encoding="utf-8")
    events = []
    for line in child.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    summary = next((x for x in reversed(events)
                    if x.get("event") == "fl23_state_ro_201_summary"), None)
    require(child.returncode == 0 and summary is not None and
             summary.get("read_only_probe_verified") is True and
             summary.get("normal_mode_and_driver_verified") is True and
             summary.get("preload_cleanup") == "verified_absent" and
             summary.get("stage_cleanup") == "verified_absent" and
             summary.get("marker", {}).get("complete") is True,
            "CP service step or normal USB recovery failed; see " + str(log))
    marker = summary["marker"]
    state = None
    if args.action != "apply":
        state = ({OLD_SHA: "old", TARGET_SHA: "target"}.get(
            marker["block_sha256"]))
        expected = {"read-old": "old", "read-target": "target"}.get(args.action)
        require(state is not None and (expected is None or state == expected),
                "live CP table is outside the expected original/target state")
    result = {"format": 1, "serial": serial, "action": args.action,
              "property_state": state if state else "target_after_ram_apply",
              "marker": marker, "verified": True,
              "normal_mode_and_driver_verified": True,
              "p1_manifest_sha256": hashlib.sha256(
                  args.p1_manifest.read_bytes()).hexdigest(),
              "observed_utc": datetime.now(timezone.utc).isoformat(),
              "log": str(log)}
    save_private(args.out, result)
    print(json.dumps({"event": "mac_cp_color_200_verified", "serial": serial,
                      "action": args.action, "property_state": result["property_state"],
                      "receipt": str(args.out)}), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
