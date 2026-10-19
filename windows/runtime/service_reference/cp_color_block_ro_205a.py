"""Read-only full 0x2000-byte CP color configuration block snapshot."""

from pathlib import Path
import hashlib
import struct
import zlib

import fl23_state_ro_201 as base

ROOT = Path(__file__).resolve().parents[1]
base.ELF = ROOT / "sony-firmware-research/libcodex_cp_color_block_ro205a.so"
base.ELF_SIZE = 19768
base.ELF_SHA256 = "7f8d8a072df6824938af5e2586353cc9e3b48ee0c07dcfb868b9befdb2f83706"
base.RAM = base.PREFIX + b"/tmp_wbshd/libcodex_cp_color_block_ro205a.so"
base.MARKER = base.PREFIX + b"/tmp_wbshd/codex_cp_color_block_ro205a.bin"
base.ARM = b"/tmp_wbshd/libcodex_cp_color_block_ro205a.so\n"
base.RESULT = struct.Struct("<16s7IQ3i16s8192sI")
base.MAGIC = b"A7C2CPBLK205A\0\0\0"
assert base.RESULT.size == 8276 and len(base.MAGIC) == 16


def parse_marker(raw):
    if not isinstance(raw, bytes) or len(raw) != base.RESULT.size:
        raise base.base.ProbeError("CP color block marker length mismatch")
    values = base.RESULT.unpack(raw)
    (magic, version_no, stage, checks, pid, error, dat4, handle,
     phys, transfer_mode, transfer_first, transfer_second,
     mode, block, crc) = values
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    if magic != base.MAGIC or version_no != 1 or zlib.crc32(copy) != crc:
        raise base.base.ProbeError("CP color block marker identity/CRC mismatch")
    index_map = block[0x1200:0x1240]
    curve_pool = block[0x1250:0x1C50]
    selected = {hex(k): index_map[k] for k in
                (0x0f, 0x29, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39)}
    row_sha = [hashlib.sha256(curve_pool[i * 64:(i + 1) * 64]).hexdigest()
               for i in range(40)]
    return {
        "stage": stage, "checks": checks, "pid": pid, "error": error,
        "dat4": hex(dat4), "handle": handle, "phys": hex(phys),
        "transfer_mode": transfer_mode, "transfer_first": transfer_first,
        "transfer_second": transfer_second,
        "mode_word": mode[4:8].hex(), "mode_value": int.from_bytes(mode[4:8], "little"),
        "selected_indices": selected,
        "block_sha256": hashlib.sha256(block).hexdigest(),
        "map_sha256": hashlib.sha256(index_map).hexdigest(),
        "pool_sha256": hashlib.sha256(curve_pool).hexdigest(),
        "pool_nonzero_rows": [i for i in range(40)
                              if any(curve_pool[i * 64:(i + 1) * 64])],
        "pool_row_sha256": row_sha,
        "block_hex": block.hex(),
        "complete": (stage == 9 and checks == 0x7FF and pid > 1
                     and error == 0 and dat4 == 0x205 and handle > 0
                     and phys > 0 and phys % 16 == 0
                     and transfer_mode == transfer_first == transfer_second == 0),
    }


base.parse_marker = parse_marker

if __name__ == "__main__":
    raise SystemExit(base.main())
