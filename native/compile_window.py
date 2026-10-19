#!/usr/bin/env python3
"""Rebuild the fixed read-only A7C II p1 window worker with Zig 0.14.1."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


SOURCE_SHA = "7ab0177c8c1d7e45a7b9d399e40e3ea37004acea08117d66938fb2a78dbdb742"
WORKER_SHA = "2adbcbc2a2eca3fe262e0aac2db475a0cf524de8c3e8a67b6ead24aebda0af78"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() or hashlib.sha256(args.source.read_bytes()).hexdigest() != SOURCE_SHA:
        raise ValueError("window worker source or output path differs")
    values = {
        "TARGET_PARTITION_ID": 1,
        "TARGET_EXPECTED_KIB": 24512,
        "TARGET_MINOR": 129,
        "TARGET_TOTAL_CHUNKS": 383,
        "TARGET_NAME": "cnflasha1",
        "TARGET_P_NAME": "pnflasha1",
        "TARGET_C_NAME": "cnflasha1",
        "TARGET_TAG": "CN1",
        "TARGET_DEVICE_PATH": "/dev/cnflasha1",
        "TARGET_REQUEST_PATH": "/tmp_wbshd/codex_cn1_request_201.bin",
        "TARGET_OUTPUT_PREFIX": "/tmp_wbshd/codex_cn1_",
        "TARGET_WHOLE": 0,
    }
    command = [str(args.zig), "cc", "-target", "aarch64-linux-gnu", "-O2",
               "-fPIC", "-ffreestanding", "-fno-stack-protector",
               "-fno-builtin", "-nostdlib", "-shared"]
    command.extend(f"-D{key}={json.dumps(value) if isinstance(value, str) else value}"
                   for key, value in values.items())
    command.extend(["-Wl,-soname,libcodex_cn1_window_201.so", "-s",
                    "-o", str(args.out), str(args.source)])
    subprocess.run(command, check=True)
    if hashlib.sha256(args.out.read_bytes()).hexdigest() != WORKER_SHA:
        raise ValueError("compiled p1 window worker differs")
    print("p1 window worker byte-exact")


if __name__ == "__main__":
    main()
