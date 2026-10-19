"""Derive the FL2/FL3 color property from a saved official 2.01 BK4 file."""

import hashlib
import os
from pathlib import Path


SOURCE_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"
PROPERTY_OFFSET = 0x1bba4c
PROPERTY_SIZE = 8192
WORKERS = {
    "bk4": (2174, 10366,
            "6a80da4a78a7912772d1803a83d98ad25847ae31c4e02399ee11ed1d2add68bb",
            "b597993bc9a04ad0a53fbd4f259db185e5d15411ae4d0592026aa70e2acf9a47"),
    "ram": (2250, 10442,
            "51d2466b78de035120233dc1b7570543d2c07faca5c89143c1c2992021e7d537",
            "cb340b31cb5fccb564da61c14b03c609e82ba0c901aaf5ee2da541e8a5a8987f"),
}

PATCHES = (
    (0x1232, bytes.fromhex("1618000016181719")),
    (0x17d0, bytes.fromhex(
        "48fff9fe80fef3fe640104013302fd0014fe970031017b00620087ff0000d6ff"
        "f2ff7600010000008a00b4ff0000d3ff00000000000000000000000000000000")),
    (0x1810, bytes.fromhex(
        "30ff29ff48fff4fe6101070133020501daff2000a4ffffff2500deff0000ebff"
        "7aff7b000000c9003d00c9ff0000daff00000000000000000000000000000000")),
    (0x1850, bytes.fromhex(
        "43ffcdff40fef3fe85011b0133021d0105000000000000002200fcff00000500"
        "31ff00000800000062002f000000f9ff00000000000000000000000000000000")),
    (0x1890, bytes.fromhex(
        "48ffcdff24fff3fe6d0133023302c70100000000bcff00001f0070ff000095ff"
        "ceff0000fcff00001d006fff0000acff00000000000000000000000000000000")),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def from_source(source):
    if len(source) != PROPERTY_SIZE or sha(source) != SOURCE_SHA:
        raise ValueError("official 2.01 color property differs")
    target = bytearray(source)
    for offset, replacement in PATCHES:
        if source[offset:offset + len(replacement)] != bytes(len(replacement)):
            raise ValueError("official color property target rows are not empty")
        target[offset:offset + len(replacement)] = replacement
    target = bytes(target)
    if (sha(target) != TARGET_SHA or
            sum(a != b for a, b in zip(source, target)) != 138 or
            sum(target) - sum(source) != 19569):
        raise ValueError("derived FL2/FL3 color property differs")
    return target


def from_backup(path):
    return from_source(source_from_backup(path))


def source_from_backup(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size != 2_390_264:
        raise ValueError("saved BK4 file identity differs")
    raw = path.read_bytes()
    if len(raw) != 2_390_264:
        raise ValueError("saved BK4 file length changed")
    source = raw[PROPERTY_OFFSET:PROPERTY_OFFSET + PROPERTY_SIZE]
    if sha(source) != SOURCE_SHA:
        raise ValueError("official 2.01 color property differs")
    return source


def materialize_named_worker(kind, blank, output, source_backup):
    source_offset, target_offset, blank_sha, full_sha = WORKERS[kind]
    source = source_from_backup(source_backup)
    return materialize_worker(blank, output, source_offset, target_offset,
                              blank_sha, full_sha, source, from_source(source))


def materialize_worker(blank, output, source_offset, target_offset,
                       blank_sha, full_sha, source, target):
    blank, output = Path(blank), Path(output)
    raw = blank.read_bytes()
    if (sha(raw) != blank_sha or
            raw[source_offset:source_offset + PROPERTY_SIZE] != bytes(PROPERTY_SIZE) or
            raw[target_offset:target_offset + PROPERTY_SIZE] != bytes(PROPERTY_SIZE) or
            len(source) != PROPERTY_SIZE or sha(source) != SOURCE_SHA or
            len(target) != PROPERTY_SIZE or sha(target) != TARGET_SHA):
        raise ValueError("blank color worker or target property differs")
    worker = bytearray(raw)
    worker[source_offset:source_offset + PROPERTY_SIZE] = source
    worker[target_offset:target_offset + PROPERTY_SIZE] = target
    worker = bytes(worker)
    if sha(worker) != full_sha:
        raise ValueError("reconstituted color worker differs from tested bytes")
    if output.exists() or output.is_symlink():
        if not output.is_file() or output.is_symlink() or output.read_bytes() != worker:
            raise ValueError("existing private color worker differs")
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(worker)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(output, 0o600)
    return output
