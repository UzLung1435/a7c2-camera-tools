#!/usr/bin/env python3
"""Generate private AArch64 worker inputs from this camera's saved data."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "windows" / "runtime" / "core"))
import build_p1_gate_200 as p1
import color_property_200 as color

OUT = Path(__file__).resolve().parent / "generated"


def write_private(path, symbol, raw):
    lines = [f"static const unsigned char {symbol}[{len(raw)}] = {{"]
    for at in range(0, len(raw), 16):
        lines.append("    " + ", ".join(f"0x{value:02x}" for value in raw[at:at + 16]) + ",")
    lines.append("};")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p1", type=Path, required=True)
    parser.add_argument("--bk4", type=Path, required=True)
    args = parser.parse_args()
    if OUT.exists():
        raise ValueError("private generated header directory already exists")
    source_p1 = args.p1.read_bytes()
    if len(source_p1) != p1.P1_SIZE:
        raise ValueError("source p1 size differs")
    target_p1, stages = p1.make_candidates(source_p1)
    if [item["stage"] for item in stages] != ["dual", "triple"]:
        raise ValueError("p1 gate stages differ")
    source_color = color.source_from_backup(args.bk4)
    target_color = color.from_source(source_color)
    OUT.mkdir(mode=0o700)
    names = {
        "dual": ("p1_frag40_original.h", "p1_frag40_dual.h"),
        "triple": ("p1_frag45_dual.h", "p1_frag45_triple.h"),
    }
    for stage in stages:
        start, size = stage["offset"], stage["bytes"]
        before = source_p1[start:start + size]
        after = target_p1[start:start + size]
        if (hashlib.sha256(before).hexdigest() != stage["source_fragment_sha256"] or
                hashlib.sha256(after).hexdigest() != stage["target_fragment_sha256"]):
            raise ValueError("p1 fragment differs from candidate proof")
        first, second = names[stage["stage"]]
        write_private(OUT / first, "p1_patch_blob", before)
        write_private(OUT / second, "p1_patch_blob", after)
    header = OUT / "color_property_slots.h"
    write_private(OUT / "original_property.h", "original_property", source_color)
    write_private(OUT / "fl23_property.h", "fl23_property", target_color)
    header.write_text('#include "original_property.h"\n#include "fl23_property.h"\n',
                      encoding="utf-8")
    os.chmod(header, 0o600)
    print(json.dumps({"camera_access": False,
                      "p1_sha256": hashlib.sha256(source_p1).hexdigest(),
                      "target_color_sha256": color.TARGET_SHA,
                      "private_headers": str(OUT)}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        raise SystemExit("error: " + str(exc))
