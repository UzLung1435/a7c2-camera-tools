#!/usr/bin/env python3
"""Check that compiled p1 workers reproduce the shipped empty templates."""

import argparse
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "windows" / "runtime" / "core"))
import build_p1_gate_200 as p1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiled-dir", type=Path, required=True)
    args = parser.parse_args()
    for stage in p1.FRAGMENTS:
        label = stage["stage"]
        for mode, (size, expected_sha, _, slot, _) in p1.TEMPLATES[label].items():
            name = f"libcodex_p1_{label}_gate_{mode}_template_200.so"
            raw = bytearray((args.compiled_dir / name).read_bytes())
            if len(raw) != size:
                raise ValueError(name + " compiled size differs")
            raw[slot:slot + stage["size"]] = bytes(stage["size"])
            for sites in p1.CONSTANT_SITES[label][mode]:
                for at in sites:
                    word = struct.unpack_from("<I", raw, at)[0]
                    struct.pack_into("<I", raw, at, word & ~(0xffff << 5))
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                raise ValueError(name + " differs from the shipped template")
            print(name, "verified")


if __name__ == "__main__":
    main()
