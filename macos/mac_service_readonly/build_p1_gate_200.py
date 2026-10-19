#!/usr/bin/env python3
"""Derive this body's temporary 2.00 p1 gate from its read-only 2.01 image."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import mac_probe_fl23 as probe

ASSETS = ROOT / "p1_gate_200"
INITRD_SIZE = 9_519_104
P1_SIZE = 25_100_288
CHECKSUM_SIZE = 105
PROPERTY_SOURCE_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
FRAGMENTS = (
    {"stage": "dual", "size": 45172, "plain_size": 124728,
     "source_sha256": "c8728be900184dc1fb81f79a147de31af510ff88d2bd6bd15b5aa0d418785fea",
     "target_plain_sha256": "55110e993a8f2cdbb4232f07bd13eb6edeb73ddc0e2fd2c05e2dfcce70f10be8",
     "sync_at": 1536, "library_at": 64128,
     "library_size": 60600,
     "library_sha256": "1a6a3226993ce7c25659bd58e20871d91869083b31440650eec555a06d592d2f",
     "patches": ((0xA0CC, "220440b900008052", "20008052c0035fd6"),
                 (0xACE8, "fd7bbba9fd030091", "00008052c0035fd6"))},
    {"stage": "triple", "size": 37542, "plain_size": 126096,
     "source_sha256": "10fe72a716680a05c46a55f7ae61bebeba3968a27283efa02862253bb9bf3b57",
     "target_plain_sha256": "71f1c0a0e13481baabfc632f237681c507591cc33872866c87b8f41cd28d828d",
     "sync_at": 71936, "library_at": 0,
     "library_size": 72864,
     "library_sha256": "b2b066b963a42d96556f811a773579eb16a0358de1b3a9206a1845c0df99bb74",
     "patches": ((0xD208, "13008012", "13008052"),
                 (0xD27C, "f3c39f5a", "13008052"))},
)
PARAM_MAGIC = b"A7C2P1PARAM200\0\0"
PARAM_STRUCT = struct.Struct("<16sQ105s105sI")
TEMPLATES = {
    "dual": {
        "verify_orig": (53128, "8f3de30d28f5e72745b4a7421aba7f5592261dca4ba280eece0bad0a35158e49", 51272, 859, "target"),
        "apply": (55040, "71e72bb3398b1703c2a2685dbc19ebf8f74978a084343d868843e5ba2cd3a948", 53184, 883, "target"),
        "verify_patch": (53128, "795a759c8db77f35b2d01ee5d5403f57b8ed94f2684b8f303b68cf7221babd0d", 51272, 859, "source"),
        "restore": (55040, "7bfdf344ea84ca3321325917fff4aebee451b3670f38b98b0d51256f5eb01da5", 53184, 883, "source"),
    },
    "triple": {
        "verify_orig": (45504, "244273e374e98a65eacfe711f169f2bfbbfd370ae3ac6c8f9ed851f3b7c780b6", 43648, 859, "target"),
        "apply": (47408, "fd4d13a3d3f00c2d089cc7178b575aa81b6b76b0ec094538afd903bceb3d6d98", 45552, 883, "target"),
        "verify_patch": (45504, "d8bad63fd0e5bc3136550d67ebf584d2f27bf54c7396695f8db38c81839cd820", 43648, 859, "source"),
        "restore": (47408, "e5ce9a1138725f09a950b6656cc461c69133a576ec6df492ddbc976e20631559", 45552, 883, "source"),
    },
}

CONSTANT_SITES = {
    "dual": {
        "verify_orig": ((0xbb28, 0xbb2c), (0xbb74, 0xbb78, 0xbb7c, 0xbb80), ()),
        "apply": ((0xbb84, 0xbb88), (0xbbd0, 0xbbd4, 0xbbd8, 0xbbdc),
                  (0xc1b0, 0xc1bc)),
        "verify_patch": ((0xbe1c, 0xbe20), (0xbe4c, 0xbe50, 0xbe54, 0xbe58),
                         (0xbf18, 0xbf24)),
        "restore": ((0xbe8c, 0xbe90), (0xbed8, 0xbee0, 0xbee4, 0xbee8),
                    (0xbfb0, 0xbfb8)),
    },
    "triple": {
        "verify_orig": ((0x9d60, 0x9d64), (0x9dac, 0x9db0, 0x9db4, 0x9db8), ()),
        "apply": ((0x9db4, 0x9db8), (0x9e00, 0x9e04, 0x9e08, 0x9e0c),
                  (0xa3e0, 0xa3ec)),
        "verify_patch": ((0xa054, 0xa058), (0xa084, 0xa088, 0xa08c, 0xa090),
                         (0xa150, 0xa15c)),
        "restore": ((0xa0bc, 0xa0c0), (0xa108, 0xa110, 0xa114, 0xa118),
                    (0xa1e0, 0xa1e8)),
    },
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fnv(data):
    result = 0xcbf29ce484222325
    for item in data:
        result = ((result ^ item) * 0x100000001b3) & 0xffffffffffffffff
    return result


def source_fragment(initrd, spec):
    matches = []
    start = 0
    while True:
        at = initrd.find(b"\x78\xda", start)
        if at < 0:
            break
        raw = initrd[at:at + spec["size"]]
        if len(raw) == spec["size"] and sha(raw) == spec["source_sha256"]:
            matches.append((at, raw))
        start = at + 1
    require(len(matches) == 1,
            spec["stage"] + " source fragment absent or ambiguous in this p1")
    return matches[0]


def compress_fragment(plain, spec):
    def packed_at(at):
        compressor = zlib.compressobj(level=9)
        return (compressor.compress(plain[:at]) +
                compressor.flush(zlib.Z_SYNC_FLUSH) +
                compressor.compress(plain[at:]) +
                compressor.flush(zlib.Z_FINISH))

    positions = (spec["sync_at"],) + tuple(
        at for at in range(0, len(plain) + 1, 128) if at != spec["sync_at"])
    for at in positions:
        packed = packed_at(at)
        if len(packed) != spec["size"]:
            continue
        decoder = zlib.decompressobj()
        restored = decoder.decompress(packed) + decoder.flush()
        require(decoder.eof and not decoder.unused_data and
                not decoder.unconsumed_tail and restored == plain,
                spec["stage"] + " generated fragment did not fully decompress")
        return packed
    raise ValueError(spec["stage"] + " cannot be compressed to the original size")


def verify_fragment_pair(initrd, spec):
    location, before = source_fragment(initrd, spec)
    plain_before = zlib.decompress(before)
    require(len(plain_before) == spec["plain_size"],
            spec["stage"] + " source plaintext length differs")
    at = spec["library_at"]
    size = spec["library_size"]
    require(sha(plain_before[at:at + size]) == spec["library_sha256"],
            spec["stage"] + " updater library differs")
    expected = bytearray(plain_before)
    for offset, old_hex, new_hex in spec["patches"]:
        old, new = bytes.fromhex(old_hex), bytes.fromhex(new_hex)
        start = at + offset
        require(len(old) == len(new) and expected[start:start + len(old)] == old,
                spec["stage"] + " updater instruction differs")
        expected[start:start + len(old)] = new
    require(sha(expected) == spec["target_plain_sha256"],
            spec["stage"] + " generated plaintext differs from the reviewed patch")
    after = compress_fragment(bytes(expected), spec)
    return location, before, after


def verify_source_report(path, source_path):
    report = json.loads(path.read_text(encoding="utf-8"))
    p1 = report.get("p1") or {}
    require(report.get("format") == 1 and report.get("camera") == "ILCE-7CM2" and
            report.get("installed_version") == "2.01" and
            isinstance(report.get("camera_usb_serial"), str) and
            report.get("camera_usb_serial") and
            report.get("p1_all_windows_verified") is True and
            report.get("p1_window_count") == 3 and
            report.get("final_tmpfs_window_cleanup_pending") is False and
            (report.get("final_tmpfs_cleanup") or {}).get("result") == "cleaned" and
            report.get("p1_block_device_written") is False and
            p1.get("size") == P1_SIZE and
            re.fullmatch(r"[0-9a-f]{64}", p1.get("sha256", "")) is not None and
            Path(p1.get("path", "")).resolve() == source_path.resolve(),
            "full preflight does not match this 2.01 p1 snapshot")
    for name in ("backup_bin", "backup_bak"):
        backup = (report.get("backups") or {}).get(name) or {}
        color = backup.get("color_property") or {}
        require(backup.get("size") == 2_390_264 and
                all(row.get("checksum_valid") is True for row in backup.get("records", [])) and
                len(backup.get("records", [])) == 2 and
                color.get("sha256") == PROPERTY_SOURCE_SHA and
                color.get("attribute") == "0x8" and color.get("size") == 8192 and
                (backup.get("offline_bk4_candidate") or {}).get("validated") is True,
                name + " BK4 preflight differs")
    return report


def validate_fat(path, expected_sha):
    report = probe.p1_report(path)
    require(report["sha256"] == expected_sha and report["size"] == P1_SIZE,
            "source p1 SHA-256 or size differs from full preflight")
    fat = report.get("fat") or {}
    chains = report.get("fat_chains") or {}
    require(fat.get("matches_research_geometry") is True and
            fat.get("fat_copies_equal") is True and fat.get("signature_55aa") is True,
            "unsupported p1 FAT geometry")
    for name, count in (("boot", 1), ("initrd", 581), ("p1chksum", 1)):
        chain = chains.get(name) or {}
        require(chain.get("count") == count and chain.get("contiguous") is True and
                chain.get("terminated") is True,
                name + " p1 FAT chain differs")
    require((report.get("initrd") or {}).get("offset") == 82432 and
            (report.get("initrd") or {}).get("size") == INITRD_SIZE and
            (report.get("p1chksum") or {}).get("offset") == 16253440 and
            (report.get("p1chksum") or {}).get("initrd_md5_matches") is True,
            "unsupported p1 initrd or checksum placement")
    return report


def checksum_text(source, initrd):
    old = source[16253440:16253440 + CHECKSUM_SIZE]
    require(re.fullmatch(rb"[0-9a-f]{32}  \./boot/vmlinux\.bin\n"
                         rb"[0-9a-f]{32}  \./boot/initrd\.img\n", old) is not None,
            "p1chksum text format differs")
    old_md5 = hashlib.md5(source[82432:82432 + INITRD_SIZE]).hexdigest().encode()
    require(old.splitlines()[1][:32] == old_md5, "original p1 initrd MD5 differs")
    new_md5 = hashlib.md5(initrd).hexdigest().encode()
    result = old.replace(old_md5 + b"  ./boot/initrd.img\n",
                         new_md5 + b"  ./boot/initrd.img\n")
    require(len(result) == CHECKSUM_SIZE and result != old,
            "modified p1chksum size or MD5 differs")
    return old, result


def make_candidates(source):
    current = bytearray(source)
    stage_reports = []
    for spec in FRAGMENTS:
        old_initrd = bytes(current[82432:82432 + INITRD_SIZE])
        location, old_fragment, new_fragment = verify_fragment_pair(old_initrd, spec)
        absolute = 82432 + location
        require(location + spec["size"] <= INITRD_SIZE and
                current[absolute:absolute + spec["size"]] == old_fragment,
                spec["stage"] + " fragment escapes initrd")
        before_sha, before_crc = sha(current), zlib.crc32(current) & 0xffffffff
        old_checksum = bytes(current[16253440:16253440 + CHECKSUM_SIZE])
        current[absolute:absolute + spec["size"]] = new_fragment
        _, new_checksum = checksum_text(bytes(current[:absolute] + old_fragment +
                                              current[absolute + spec["size"]:]),
                                        current[82432:82432 + INITRD_SIZE])
        current[16253440:16253440 + CHECKSUM_SIZE] = new_checksum
        require(len(current) == P1_SIZE, "candidate p1 size changed")
        stage_reports.append({
            "stage": spec["stage"], "offset": absolute, "bytes": spec["size"],
            "source_p1_sha256": before_sha, "target_p1_sha256": sha(current),
            "source_p1_crc32": f"{before_crc:08x}",
            "target_p1_crc32": f"{zlib.crc32(current) & 0xffffffff:08x}",
            "source_fragment_sha256": sha(old_fragment),
            "target_fragment_sha256": sha(new_fragment),
            "source_fragment_crc32": f"{zlib.crc32(old_fragment) & 0xffffffff:08x}",
            "target_fragment_crc32": f"{zlib.crc32(new_fragment) & 0xffffffff:08x}",
            "source_fragment_fnv64": f"{fnv(old_fragment):016x}",
            "target_fragment_fnv64": f"{fnv(new_fragment):016x}",
            "source_p1chksum": old_checksum.decode("ascii"),
            "target_p1chksum": new_checksum.decode("ascii"),
            "candidate_initrd_sha256": sha(current[82432:82432 + INITRD_SIZE]),
        })
    return bytes(current), stage_reports


def private_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def set_fragment_constant(output, sites, value):
    for index, at in enumerate(sites):
        word = struct.unpack_from("<I", output, at)[0]
        require((word >> 5) & 0xffff == 0,
                "template fragment constant slot is not empty")
        immediate = (value >> (16 * index)) & 0xffff
        struct.pack_into("<I", output, at,
                         (word & ~(0xffff << 5)) | (immediate << 5))


def build_worker_templates(out_dir, stages, source_p1, target_p1):
    require(len(source_p1) == len(target_p1) == P1_SIZE,
            "p1 worker source or target size differs")
    workers = out_dir / "workers"
    workers.mkdir(mode=0o700)
    blank_old = ("a" * 32 + "  ./boot/vmlinux.bin\n" +
                 "b" * 32 + "  ./boot/initrd.img\n").encode()
    blank_new = ("c" * 32 + "  ./boot/vmlinux.bin\n" +
                 "d" * 32 + "  ./boot/initrd.img\n").encode()
    placeholder = PARAM_STRUCT.pack(PARAM_MAGIC, 0x1122334455667788,
                                    blank_old, blank_new, 0)
    require(PARAM_STRUCT.size == 238 and len(placeholder) == 238,
            "p1 parameter ABI differs")
    result = {}
    for stage in stages:
        label = stage["stage"]
        fragment_at = stage["offset"]
        fragment_end = fragment_at + stage["bytes"]
        source_fragment = source_p1[fragment_at:fragment_end]
        target_fragment = target_p1[fragment_at:fragment_end]
        require(sha(source_fragment) == stage["source_fragment_sha256"] and
                sha(target_fragment) == stage["target_fragment_sha256"],
                label + " p1 fragment bytes differ from candidate proof")
        target_crc = int(stage["target_fragment_crc32"], 16)
        target_fnv = int(stage["target_fragment_fnv64"], 16)
        require(zlib.crc32(target_fragment) & 0xffffffff == target_crc and
                fnv(target_fragment) == target_fnv,
                label + " target fragment checksums differ")
        result[label] = {}
        old = stage["source_p1chksum"].encode()
        new = stage["target_p1chksum"].encode()
        require(len(old) == len(new) == 105, label + " p1chksum size differs")
        initial = PARAM_STRUCT.pack(PARAM_MAGIC, stage["offset"], old, new, 0)
        parameters = PARAM_STRUCT.pack(PARAM_MAGIC, stage["offset"], old, new,
                                        zlib.crc32(initial[:-4]) & 0xffffffff)
        for mode, (size, expected_sha, at, slot, fragment_kind) in TEMPLATES[label].items():
            template_name = f"libcodex_p1_{label}_gate_{mode}_template_200.so"
            template = (ASSETS / "templates" / template_name).read_bytes()
            require(len(template) == size and sha(template) == expected_sha and
                    template[at:at + PARAM_STRUCT.size] == placeholder and
                    slot + stage["bytes"] <= at and
                    template[slot:slot + stage["bytes"]] == bytes(stage["bytes"]),
                    template_name + " ELF or parameter section differs")
            fragment = (target_fragment if fragment_kind == "target" else
                        source_fragment)
            output = bytearray(template)
            output[slot:slot + stage["bytes"]] = fragment
            output[at:at + PARAM_STRUCT.size] = parameters
            complement_sites, fnv_sites, direct_sites = CONSTANT_SITES[label][mode]
            set_fragment_constant(output, complement_sites,
                                  (~target_crc) & 0xffffffff)
            set_fragment_constant(output, fnv_sites, target_fnv)
            set_fragment_constant(output, direct_sites, target_crc)
            require(len(output) == size and
                    output[slot:slot + stage["bytes"]] == fragment and
                    output[at:at + PARAM_STRUCT.size] == parameters and
                    output[:7] == b"\x7fELF\x02\x01\x01" and
                    output[18:20] == b"\xb7\0",
                    template_name + " candidate ELF escaped parameter section")
            name = f"libcodex_p1_{label}_gate_{mode}_200.so"
            private_file(workers / name, bytes(output))
            result[label][mode] = {"filename": name, "size": size,
                                   "sha256": sha(output),
                                   "params_crc32": f"{zlib.crc32(initial[:-4]) & 0xffffffff:08x}"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full-preflight-json", type=Path, required=True)
    parser.add_argument("--source-p1", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    info = args.source_p1.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size == P1_SIZE,
            "source p1 image absent, linked, or wrong size")
    preflight = verify_source_report(args.full_preflight_json, args.source_p1)
    fat = validate_fat(args.source_p1, preflight["p1"]["sha256"])
    source = args.source_p1.read_bytes()
    candidate, stages = make_candidates(source)
    require(len(stages) == 2 and stages[0]["stage"] == "dual" and
            stages[1]["stage"] == "triple" and
            stages[0]["source_p1_sha256"] == fat["sha256"],
            "p1 stage linkage differs")
    require(not args.out_dir.exists(), "p1 output directory already exists")
    args.out_dir.mkdir(mode=0o700, parents=True)
    image = args.out_dir / "p1_triple_gate_candidate_200.img"
    private_file(image, candidate)
    readback = probe.p1_report(image)
    require(readback["sha256"] == stages[-1]["target_p1_sha256"] and
            readback["p1chksum"]["initrd_md5_matches"] is True and
            readback["fat"]["fat_copies_equal"] is True,
            "candidate p1 full readback differs")
    worker_config = build_worker_templates(args.out_dir, stages, source, candidate)
    manifest = {"format": 1, "camera": "ILCE-7CM2", "installed_version": "2.01",
                "camera_usb_serial": preflight["camera_usb_serial"],
                "source_p1_sha256": fat["sha256"],
                "source_p1_path": str(args.source_p1.resolve()),
                "target_p1_sha256": readback["sha256"],
                "target_p1_path": str(image.resolve()),
                "source_initrd_sha256": fat["initrd"]["sha256"],
                "target_initrd_sha256": readback["initrd"]["sha256"],
                "stages": stages, "workers": worker_config, "camera_access": False,
                "full_candidate_readback_verified": True}
    private_file(args.out_dir / "p1_gate_200_manifest.json",
                 (json.dumps(manifest, indent=2) + "\n").encode())
    print(json.dumps({"event": "p1_gate_200_offline_built",
                      "camera_serial": manifest["camera_usb_serial"],
                      "source_p1_sha256": manifest["source_p1_sha256"],
                      "target_p1_sha256": manifest["target_p1_sha256"],
                      "stage_offsets": [entry["offset"] for entry in stages],
                      "manifest": str((args.out_dir / "p1_gate_200_manifest.json").resolve()),
                      "camera_access": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
