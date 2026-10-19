"""A7C II 2.01 MENU version reader: temporary 1.99 return for a 2.00 DAT."""

from pathlib import Path
import struct
import zlib

import fl23_state_ro_201 as base

ROOT = Path(__file__).resolve().parents[1]
base.ELF = ROOT / "p1_gate_200/libcodex_update_code_hold200.so"
base.ELF_SIZE = 8760
base.ELF_SHA256 = "1d2508c75340a1261d386f9ca427a13f58375ef30aaeb28b81260131cf33c3b9"
base.RAM = base.PREFIX + b"/tmp_wbshd/libcodex_update_code_hold200.so"
base.MARKER = base.PREFIX + b"/tmp_wbshd/codex_update_code_hold200_start.bin"
base.ARM = b"/tmp_wbshd/libcodex_update_code_hold200.so\n"
base.RESULT = struct.Struct("<16sQ8I2HI")
base.MAGIC = b"A7C2UPCODE200\0\0\0"
assert base.RESULT.size == 64 and len(base.MAGIC) == 16


def parse_marker(raw):
    if not isinstance(raw, bytes) or len(raw) != base.RESULT.size:
        raise base.base.ProbeError("version window marker length differs")
    value = base.RESULT.unpack(raw)
    magic, lib_base, version_no, stage, checks, pid, error = value[:7]
    before, during, after, file_dat4, reserved, crc = value[7:]
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    if magic != base.MAGIC or version_no != 1 or zlib.crc32(copy) != crc:
        raise base.base.ProbeError("version window marker identity/CRC differs")
    return {"stage": stage, "checks": checks, "im_pid": pid,
            "lib_base": hex(lib_base), "error": error,
            "before": hex(before), "during": hex(during),
            "after": hex(after), "file_dat4": hex(file_dat4),
            "reserved": reserved,
            "complete": (stage == 13 and checks == 0x1ff and error == 0
                         and before == 0x79407fa0 and during == 0x52803320
                         and after == 0xffffffff and file_dat4 == 0x201
                         and reserved == 0 and pid > 1 and lib_base != 0)}


base.parse_marker = parse_marker

if __name__ == "__main__":
    raise SystemExit(base.main())
