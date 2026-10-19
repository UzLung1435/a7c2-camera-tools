"""RAM-only 2.05 CP FL2/FL3 color-table trial; no BK4 or firmware write."""

from pathlib import Path
import struct
import zlib

import fl23_state_ro_201 as base

ROOT = Path(__file__).resolve().parents[1]
base.ELF = ROOT / "sony-firmware-research/libcodex_cp_fl23_color_ram_apply205.so"
base.ELF_SIZE = 41296
base.ELF_SHA256 = "98bb261f77dad30d97744dba46f8fabb803633139af4d829a923563b2b0952e6"
base.RAM = base.PREFIX + b"/tmp_wbshd/libcodex_cp_fl23_color_ram_apply205.so"
base.MARKER = base.PREFIX + b"/tmp_wbshd/codex_cp_fl23_color_ram_apply205.bin"
base.ARM = b"/tmp_wbshd/libcodex_cp_fl23_color_ram_apply205.so\n"
base.RESULT = struct.Struct("<16s8IQ11i5I")
base.MAGIC = b"A7C2CPCLR205A\0\0\0"
assert base.RESULT.size == 120 and len(base.MAGIC) == 16


def parse_marker(raw):
    if not isinstance(raw, bytes) or len(raw) != base.RESULT.size:
        raise base.base.ProbeError("CP color RAM marker size mismatch")
    (magic, version_no, stage, checks, pid, error, dat4, handle, mode,
     phys, before0, before1, cache0, cache1, write0, write1,
     postcache0, postcache1, after0, after1, emergency,
     before_kind, after_kind, crc_before, crc_after, crc) = base.RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    if magic != base.MAGIC or version_no != 1 or zlib.crc32(copy) != crc:
        raise base.base.ProbeError("CP color RAM identity/CRC mismatch")
    statuses = [before0, before1, cache0, cache1, write0, write1,
                postcache0, postcache1, after0, after1]
    return {
        "stage": stage, "checks": checks, "pid": pid, "error": error,
        "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
        "mode": mode, "statuses": statuses,
        "emergency_restore": emergency,
        "before_kind": before_kind, "after_kind": after_kind,
        "crc_before": hex(crc_before), "crc_after": hex(crc_after),
        "complete": (stage == 9 and checks == 0x7ff and pid > 1
                     and error == 0 and dat4 == 0x205 and handle > 0
                     and phys > 0 and phys % 16 == 0 and mode == 0
                     and statuses == [0] * 10 and
                     emergency == -2147483648 and
                     before_kind == 1 and after_kind == 2 and
                     crc_before == 0xBCC3F1AF and crc_after == 0x080B1A7D),
    }


base.parse_marker = parse_marker

if __name__ == "__main__":
    raise SystemExit(base.main())
