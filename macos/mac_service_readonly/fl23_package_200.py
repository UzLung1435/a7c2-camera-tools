#!/usr/bin/env python3
"""Build and verify a minimal ILCE-7CM2 FL2/FL3 2.00 DAT from official 2.01.

This is an offline packager and card copier. Camera-side updater and BK4 writes
need a separate, body-specific read-only preflight; this program never opens a
camera USB service or writes its internal storage.
"""

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import zlib

try:
    import numpy as np
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit("Missing Python packages. Run: py -3 -m pip install numpy pycryptodome") from exc

ROOT = Path(__file__).resolve().parent
SOURCE_SHA = "eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31"
SOURCE_NAME = "ILCE-7CM2-v2.01-BODYDATA.DAT"
OUT_NAME = "BODYDATA_FL23_200.DAT"
PATCH_DATA = ROOT / "patches_fl23.json"
FW_OFF = 0x132200
CP_IN_P8 = 0x230000
ECB_KEY = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb924")
CBC_KEY = bytes.fromhex("434589432d319010f1132727353286ce4d7ede8b9c4f7217a0e0226e0f0edc69")
GROUP_BLOCKS = 4096
APP_SOURCE_SHA = "2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b"
WBI_SOURCE_SHA = "db3730c8dbb2de71cfb7a66c343ba8e752e0f374a3a4104196ceac1e9d1b08dc"
CP_SOURCE_SHA = "f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428"
TARGET_200_PLAIN_SHA = "aade37951b67c35225b5fe27964793742e00f9fae6f6ec2962e6872c12715f59"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def crc_window(view, offset, size):
    value = 0
    for at in range(offset, offset + size, 8 << 20):
        value = zlib.crc32(view[at:min(at + (8 << 20), offset + size)], value)
    return value & 0xffffffff


def parse_dat(path):
    size = path.stat().st_size
    with path.open("rb") as stream:
        require(stream.read(8) == b"\x89UFU\r\n\x1a\n", "DAT magic mismatch")
        chunks = {}
        while stream.tell() < size:
            header = stream.read(8)
            require(len(header) == 8, "truncated DAT chunk header")
            length, kind = struct.unpack(">I4s", header)
            require(length <= size - stream.tell(), "DAT chunk length exceeds file")
            require(kind not in chunks, "duplicate DAT chunk")
            chunks[kind] = (stream.tell(), length)
            stream.seek(length, 1)
            if kind == b"DEND":
                break
        require(stream.tell() == size and chunks.get(b"DEND") == (size - 4, 4),
                "DAT trailer mismatch")
        require(b"FDAT" in chunks, "FDAT missing")
        fdat_at, fdat_size = chunks[b"FDAT"]
        require(fdat_size > 0x110 and (fdat_size - 0x110) % 1024 == 0,
                "FDAT cipher geometry mismatch")
        stream.seek(fdat_at + fdat_size - 0x110)
        trailer = stream.read(0x110)
        require(len(trailer) == 0x110, "FDAT trailer short")
        stream.seek(size - 4)
        recorded_crc = struct.unpack(">I", stream.read(4))[0]
        stream.seek(0)
        remaining, actual_crc = size - 12, 0
        while remaining:
            block = stream.read(min(8 << 20, remaining))
            require(block, "short DAT CRC read")
            actual_crc = zlib.crc32(block, actual_crc)
            remaining -= len(block)
        require(recorded_crc == actual_crc & 0xffffffff, "DAT DEND CRC mismatch")
    return fdat_at, fdat_size, trailer


def decoded_blocks(path, layout):
    fdat_at, fdat_size, trailer = layout
    blocks = (fdat_size - 0x110) // 1024
    ecb = AES.new(ECB_KEY, AES.MODE_ECB)
    cbc = AES.new(CBC_KEY, AES.MODE_CBC, trailer[:16])
    with path.open("rb") as stream:
        stream.seek(fdat_at)
        for start in range(0, blocks, GROUP_BLOCKS):
            count = min(GROUP_BLOCKS, blocks - start)
            cipher = stream.read(count * 1024)
            require(len(cipher) == count * 1024, "short FDAT cipher read")
            if start == 0:
                raw = ecb.decrypt(cipher[:512]) + cbc.decrypt(cipher[512:])
            else:
                raw = cbc.decrypt(cipher)
            words = np.frombuffer(raw, dtype="<u2").reshape(count, 512)
            checksums = words[:, 1:].sum(axis=1, dtype=np.uint64) & 0xffff
            require(bool(np.all(checksums == words[:, 0])), "FDAT block checksum mismatch")
            lengths = words[:, 1]
            last = start + count == blocks
            if last:
                require(bool(np.all(lengths[:-1] == 1020)), "nonfinal FDAT block length")
                require(0x8000 < int(lengths[-1]) <= 0x8000 + 1020,
                        "final FDAT block flag/length")
            else:
                require(bool(np.all(lengths == 1020)), "FDAT block length/flag mismatch")
            payload = np.frombuffer(raw, dtype=np.uint8).reshape(count, 1024)[:, 4:].tobytes()
            if last:
                payload = payload[:(count - 1) * 1020 + (int(lengths[-1]) & 0x7fff)]
            yield payload


def decrypt_to(source, plain, layout):
    with plain.open("xb") as output:
        for number, block in enumerate(decoded_blocks(source, layout)):
            output.write(block)
            if number % 32 == 0:
                print("Decrypting:", output.tell() >> 20, "MiB", flush=True)
        output.flush()
        os.fsync(output.fileno())
    with plain.open("rb") as stream:
        require(stream.read(8) == b"UDTRFIRM", "FDAT plaintext magic mismatch")
        stream.seek(0x20)
        require(stream.read(2) == b"\x01\x02", "source version is not 2.01")
    require(plain.stat().st_size == 1_135_475_712, "unexpected FDAT plaintext size")


def tar_parts(plain):
    with plain.open("rb") as stream:
        stream.seek(FW_OFF)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            entries = {item.name: item for item in archive.getmembers()}
    names = ("0700_part_image/dev/nflasha15", "0700_part_image/dev/nflasha5",
             "0700_part_image/dev/nflasha8", "0701_part_image_sum/part_image.sum")
    require(all(name in entries for name in names), "required tar entries missing")
    p15, p5, p8, listing = (entries[name] for name in names)
    require((p15.size, p5.size, p8.size, listing.size) ==
            (770_030_592, 267_171_648, 25_102_336, 454),
            "official 2.01 partition geometry differs")
    return p15, p5, p8, listing


def patch_span(mm, at, old_sha256, new_hex, label):
    new = bytes.fromhex(new_hex)
    old = bytes(mm[at:at + len(new)])
    require(len(old) == len(new) and old != new, label + " invalid byte span")
    require(hashlib.sha256(old).hexdigest() == old_sha256,
            label + " original bytes differ")
    mm[at:at + len(new)] = new
    require(mm[at:at + len(new)] == new, label + " writeback differs")
    return sum(a != b for a, b in zip(old, new))


def patch_plain(plain, data):
    p15, p5, p8, listing = tar_parts(plain)
    require(data["app"]["source_sha256"] == APP_SOURCE_SHA and
            data["wbi2"]["source_sha256"] == WBI_SOURCE_SHA and
            data["cp"]["source_sha256"] == CP_SOURCE_SHA,
            "patch data source identity differs")
    with plain.open("r+b") as stream:
        mm = mmap.mmap(stream.fileno(), 0)
        try:
            app_positions = []
            for span in data["app"]["spans"]:
                at = p15.offset_data + span["partition_relative_offset"]
                marker_at = at - 64
                marker_end = marker_at + span["source_context_size"]
                require(p15.offset_data <= marker_at and
                        marker_end <= p15.offset_data + p15.size and
                        hashlib.sha256(mm[marker_at:marker_end]).hexdigest() ==
                        span["source_context_sha256"],
                        span["name"] + " original appFw context differs")
                app_positions.append(at)
            cp_at = p8.offset_data + CP_IN_P8
            require(hashlib.sha256(mm[p5.offset_data:p5.offset_data + p5.size]).hexdigest() == WBI_SOURCE_SHA,
                    "official WBI2 hash mismatch")
            require(hashlib.sha256(mm[cp_at:cp_at + data["cp"]["length"]]).hexdigest() == CP_SOURCE_SHA,
                    "official CP hash mismatch")
            changes = {"AP": 0, "WBI2": 0, "CP": 0}
            for span, at in zip(data["app"]["spans"], app_positions):
                changes["AP"] += patch_span(mm, at, span["old_sha256"],
                                            span["new"], span["name"])
            for offset in data["wbi2"]["offsets"]:
                changes["WBI2"] += patch_span(mm, p5.offset_data + offset,
                                               hashlib.sha256(b"\0").hexdigest(),
                                               "01", "WBI2")
            for span in data["cp"]["spans"]:
                changes["CP"] += patch_span(mm, cp_at + span["offset"],
                                            span["old_sha256"],
                                            span["new"], "CP")
            require(changes == {"AP": 86, "WBI2": 4, "CP": 155},
                    "unexpected number of executable/feature changes")
            for name, at, size, target in (
                ("WBI2", p5.offset_data, p5.size, data["wbi2"]["target_sha256"]),
                ("CP", cp_at, data["cp"]["length"], data["cp"]["target_sha256"])):
                require(hashlib.sha256(mm[at:at + size]).hexdigest() == target,
                        name + " target hash mismatch")
            listed = bytes(mm[listing.offset_data:listing.offset_data + listing.size])
            crc_updates = {}
            for suffix, part in ((b"dev/nflasha15,", p15), (b"dev/nflasha5,", p5),
                                 (b"dev/nflasha8,", p8)):
                lines = [line for line in listed.splitlines() if line.endswith(suffix)]
                require(len(lines) == 1 and len(lines[0]) >= 10 and lines[0].startswith(b"0,"),
                        "partition CRC entry missing/ambiguous")
                line = lines[0]
                require(listed.count(line) == 1, "duplicate partition CRC entry")
                old_crc = int(line[2:10], 16)
                # Source CRC is reconstructed by undoing only the reviewed spans in
                # a small temporary copy of each changed partition window.
                target_crc = crc_window(mm, part.offset_data, part.size)
                crc_at = listing.offset_data + listed.find(line) + 2
                mm[crc_at:crc_at + 8] = f"{target_crc:08x}".encode("ascii")
                crc_updates[suffix.decode()] = {"source_listing": f"{old_crc:08x}",
                                                "target": f"{target_crc:08x}"}
            require(mm[0x20:0x22] == b"\x01\x02", "FDAT source version changed")
            mm[0x20:0x22] = b"\x00\x02"  # 2.00, shown as Ver.2.00
            header_crc = zlib.crc32(mm[12:0x200]) & 0xffffffff
            mm[8:12] = struct.pack("<I", header_crc)
            mm.flush()
            return {"byte_changes": changes, "partition_crc32": crc_updates,
                    "fdat_header_crc32": f"{header_crc:08x}"}
        finally:
            mm.close()


def encrypt_from(plain, source, output, layout):
    fdat_at, fdat_size, trailer = layout
    plain_size = plain.stat().st_size
    blocks = (plain_size + 1019) // 1020
    require(blocks * 1024 == fdat_size - 0x110, "target FDAT geometry differs")
    shutil.copyfile(source, output)
    ecb = AES.new(ECB_KEY, AES.MODE_ECB)
    cbc = AES.new(CBC_KEY, AES.MODE_CBC, trailer[:16])
    with plain.open("rb") as input_file, output.open("r+b") as output_file:
        output_file.seek(fdat_at)
        for start in range(0, blocks, GROUP_BLOCKS):
            count = min(GROUP_BLOCKS, blocks - start)
            payload = input_file.read(count * 1020)
            require(payload, "short target plaintext")
            final = start + count == blocks
            if final:
                final_size = len(payload) - (count - 1) * 1020
                require(1 <= final_size <= 1020, "bad last plaintext block")
            else:
                require(len(payload) == count * 1020, "short nonfinal plaintext group")
            padded = payload + b"\xff" * (count * 1020 - len(payload))
            raw = np.empty((count, 1024), dtype=np.uint8)
            raw[:, 4:] = np.frombuffer(padded, dtype=np.uint8).reshape(count, 1020)
            words = raw.view("<u2").reshape(count, 512)
            words[:, 1] = 1020
            if final:
                words[-1, 1] = final_size | 0x8000
            words[:, 0] = words[:, 1:].sum(axis=1, dtype=np.uint64) & 0xffff
            packed = raw.tobytes()
            if start == 0:
                cipher = ecb.encrypt(packed[:512]) + cbc.encrypt(packed[512:])
            else:
                cipher = cbc.encrypt(packed)
            output_file.write(cipher)
            if start % (GROUP_BLOCKS * 32) == 0:
                print("Encrypting:", start * 1020 >> 20, "MiB", flush=True)
        require(input_file.read(1) == b"", "target plaintext not exhausted")
        require(output_file.tell() == fdat_at + fdat_size - 0x110,
                "cipher write ended at wrong offset")
        output_file.flush()
        os.fsync(output_file.fileno())
        total = output_file.seek(0, os.SEEK_END)
        output_file.seek(0)
        remaining, value = total - 12, 0
        while remaining:
            block = output_file.read(min(8 << 20, remaining))
            require(block, "short target DEND CRC read")
            value = zlib.crc32(block, value)
            remaining -= len(block)
        value &= 0xffffffff
        output_file.seek(total - 4)
        output_file.write(struct.pack(">I", value))
        output_file.flush()
        os.fsync(output_file.fileno())
    return f"{value:08x}"


def verify_output(output, plain, layout):
    require(parse_dat(output) == layout, "output DAT chunk layout or trailer changed")
    target_digest = hashlib.sha256()
    with plain.open("rb") as expected:
        for block in decoded_blocks(output, layout):
            require(expected.read(len(block)) == block, "output full decrypt differs from target")
            target_digest.update(block)
        require(expected.read(1) == b"", "output decoded length differs")
    require(target_digest.hexdigest() == TARGET_200_PLAIN_SHA,
            "2.00 plaintext differs from the verified target")


def verify_reference_only(output):
    layout = parse_dat(output)
    target_digest = hashlib.sha256()
    for block in decoded_blocks(output, layout):
        target_digest.update(block)
    require(target_digest.hexdigest() == TARGET_200_PLAIN_SHA,
            "existing output differs from proven FL2/FL3 target code")


def build(source):
    require(source.is_file(), "official 2.01 DAT missing: " + str(source))
    output = source.with_name(OUT_NAME)
    manifest = source.with_name("BODYDATA_FL23_200_manifest.json")
    if output.exists() or manifest.exists():
        require(output.is_file() and manifest.is_file(), "existing incomplete build; inspect it first")
        report = json.loads(manifest.read_text(encoding="utf-8"))
        require(report.get("full_decrypt_verified") and sha_file(output) == report.get("output_sha256"),
                "existing output does not match its manifest")
        verify_reference_only(output)
        if not report.get("pinned_200_plain_verified"):
            report["pinned_200_plain_verified"] = True
            manifest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                encoding="utf-8")
        print("Verified existing output:", output, report["output_sha256"])
        return output
    require(sha_file(source) == SOURCE_SHA, "input must be untouched official ILCE-7CM2 2.01")
    data = json.loads(PATCH_DATA.read_text(encoding="utf-8"))
    layout = parse_dat(source)
    plain = source.with_name(".fl23_plain_building.bin")
    temporary = source.with_name(".fl23_dat_building.bin")
    require(not plain.exists() and not temporary.exists(), "stale build files present; inspect them first")
    try:
        decrypt_to(source, plain, layout)
        change_report = patch_plain(plain, data)
        target_plain_sha = sha_file(plain)
        dend_crc = encrypt_from(plain, source, temporary, layout)
        verify_output(temporary, plain, layout)
        out_sha = sha_file(temporary)
        report = {"source_sha256": SOURCE_SHA, "output_sha256": out_sha,
                  "output_size": temporary.stat().st_size,
                  "output_plain_sha256": target_plain_sha,
                  "package_version": "2.00", "source_version": "2.01",
                  "fdat_cipher": "CXD90057_k8", "dend_crc32": dend_crc,
                  "full_decrypt_verified": True,
                  "pinned_200_plain_verified": True,
                  "post_install_bk4_required": True,
                  "camera_side_gates_in_DAT": False,
                  "camera_access": False, **change_report}
        temporary.replace(output)
        manifest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print("Verified package:", output)
        print("SHA-256:", out_sha)
        return output
    finally:
        if plain.exists():
            plain.unlink()


def find_official_source(explicit):
    if explicit is not None:
        require(explicit.is_file(), "official DAT missing: " + str(explicit))
        require(sha_file(explicit) == SOURCE_SHA, "selected DAT is not untouched official 2.01")
        return explicit.resolve()
    preferred = ROOT / SOURCE_NAME
    if preferred.is_file() and sha_file(preferred) == SOURCE_SHA:
        return preferred
    matches = [path for path in ROOT.glob("*.DAT")
               if path.name != OUT_NAME and sha_file(path) == SOURCE_SHA]
    require(len(matches) == 1, "place exactly one official ILCE-7CM2 2.01 DAT in the package directory")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build",))
    parser.add_argument("--source", type=Path, help="official 2.01 DAT; autodetected by SHA-256 if omitted")
    args = parser.parse_args()
    try:
        source = find_official_source(args.source)
        build(source)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
