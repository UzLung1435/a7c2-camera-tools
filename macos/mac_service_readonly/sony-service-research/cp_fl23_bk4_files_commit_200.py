"""Guarded A7 C II 2.00 BK4 FL2/FL3 property commit for the verified layout.

Checks both live file records before writing the 8 KiB property and each
current second-record checksum. The service entry requires current USB identity.
"""

from pathlib import Path
import struct
import zlib

import fl23_state_ro_201 as base

ROOT = Path(__file__).resolve().parents[1]
base.ELF = ROOT / "p1_gate_200/libcodex_cp_fl23_bk4_files_200.so"
base.ELF_SIZE = 24824
base.ELF_SHA256 = "b597993bc9a04ad0a53fbd4f259db185e5d15411ae4d0592026aa70e2acf9a47"
base.RAM = base.PREFIX + b"/tmp_wbshd/libcodex_cp_fl23_bk4_files_200.so"
base.MARKER = base.PREFIX + b"/tmp_wbshd/codex_cp_fl23_bk4_files_200.bin"
base.ARM = b"/tmp_wbshd/libcodex_cp_fl23_bk4_files_200.so\n"
base.RESULT = struct.Struct("<16s10I8iI")
base.MAGIC = b"A7C2BK4GEN200\0\0\0"
assert base.RESULT.size == 92 and len(base.MAGIC) == 16


def parse_marker(raw):
    if not isinstance(raw, bytes) or len(raw) != base.RESULT.size:
        raise base.base.ProbeError("generic BK4 commit marker size mismatch")
    (magic, version_no, stage, checks, pid, error, dat4,
     old0, old1, new0, new1,
     v0, v1, w0, w1, r0, r1, e0, e1, crc) = base.RESULT.unpack(raw)
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    if magic != base.MAGIC or version_no != 1 or zlib.crc32(copy) != crc:
        raise base.base.ProbeError("generic BK4 commit identity/CRC mismatch")
    return {
        "stage": stage, "checks": checks, "pid": pid, "error": error,
        "dat4": hex(dat4),
        "old_checksum": [hex(old0), hex(old1)],
        "new_checksum": [hex(new0), hex(new1)],
        "validate": [v0, v1], "write": [w0, w1],
        "verify": [r0, r1], "emergency": [e0, e1],
        "complete": (stage == 6 and checks == 0xff and pid > 1
                     and error == 0 and dat4 == 0x200
                     and old0 > 0 and old1 > 0
                     and new0 == ((old0 + 19569) & 0xffffffff)
                     and new1 == ((old1 + 19569) & 0xffffffff)
                     and [v0, v1, w0, w1, r0, r1] == [0] * 6
                     and [e0, e1] == [-2147483648] * 2),
    }


base.parse_marker = parse_marker

if __name__ == "__main__":
    raise SystemExit(base.main())
