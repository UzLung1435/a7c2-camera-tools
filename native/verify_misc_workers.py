#!/usr/bin/env python3
"""Compare compiled AArch64 workers with the pinned installation workers."""

import argparse
import hashlib
from pathlib import Path
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "windows" / "runtime" / "core"))
import color_property_200 as color


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def loaded_segments(raw):
    if raw[:4] != b"\x7fELF" or raw[4] != 2 or raw[5] != 1:
        raise ValueError("AArch64 ELF format differs")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phsize, count = struct.unpack_from("<HH", raw, 54)
    if phsize != 56 or count > 32:
        raise ValueError("AArch64 ELF program headers differ")
    result = []
    for index in range(count):
        header = phoff + phsize * index
        kind, _, offset, _, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", raw, header)
        if kind != 1:
            continue
        data = bytearray(raw[offset:offset + size])
        if len(data) != size:
            raise ValueError("AArch64 ELF load segment truncated")
        if offset == 0:
            data[40:48] = bytes(8)
        result.append(bytes(data))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-dir", type=Path, required=True)
    parser.add_argument("--bk4", type=Path, required=True)
    args = parser.parse_args()
    compiled = args.compiled_dir
    exact = {
        "update_hold.so": (ROOT / "windows/runtime/core/p1_gate_200/"
                           "libcodex_update_code_hold200.so",
                           "1d2508c75340a1261d386f9ca427a13f58375ef30aaeb28b81260131cf33c3b9"),
        "bk4_full.so": (None,
                        "b597993bc9a04ad0a53fbd4f259db185e5d15411ae4d0592026aa70e2acf9a47"),
    }
    for name, (reference, expected_sha) in exact.items():
        actual = (compiled / name).read_bytes()
        if sha(actual) != expected_sha or (reference and actual != reference.read_bytes()):
            raise ValueError(name + " does not reproduce the pinned worker")
        print(name, "byte-exact")
    read_expected = (ROOT / "windows/runtime/cp_color_200/"
                     "libcodex_cp_color_block_ro200.so").read_bytes()
    read_actual = (compiled / "cp_read.so").read_bytes()
    if loaded_segments(read_expected) != loaded_segments(read_actual):
        raise ValueError("CP read worker loaded code/data differs")
    print("cp_read.so", "loaded code/data exact")
    with tempfile.TemporaryDirectory() as temporary:
        expected_path = color.materialize_named_worker(
            "ram", ROOT / "windows/runtime/cp_color_200/"
            "libcodex_cp_fl23_color_ram_apply200.so",
            Path(temporary) / "cp_apply_full.so", args.bk4)
        if loaded_segments(expected_path.read_bytes()) != loaded_segments(
                (compiled / "cp_apply_full.so").read_bytes()):
            raise ValueError("CP RAM worker loaded code/data differs")
    print("cp_apply_full.so", "loaded code/data exact")


if __name__ == "__main__":
    main()
