"""Pure ILCE-7CM2 2.01 p1 block-window wire format; no camera access."""

from dataclasses import dataclass
import hashlib
import re
import struct
import zlib


BLOCK = 65536
WINDOW = 128
REQUEST = struct.Struct("<16s16sIIIIIIII")
MANIFEST = struct.Struct("<16sIIQIIIIII16siIQQ16sIIII")
CHUNK = struct.Struct("<16sIIQQIIIiQII16sII16sIIQ")
assert REQUEST.size == 64 and MANIFEST.size == CHUNK.size == 128
CAPTURE = re.compile(r"[0-9a-f]{32}\Z")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Profile:
    tag: str
    partition: int
    source: str
    minor: int
    bytes: int
    candidate_count: int = 2

    def __post_init__(self):
        whole = (self.source == "pnflasha" and self.partition == 0
                 and self.minor == 0 and self.candidate_count == 1)
        numbered = (re.fullmatch(r"[pc]nflasha(?:[1-9]|[12][0-9]|30)",
                                   self.source) is not None
                    and self.partition in range(1, 31)
                    and self.source == f"{self.source[0]}nflasha{self.partition}"
                    and self.minor == self.partition +
                        (128 if self.source[0] == "c" else 0)
                    and self.candidate_count == 2)
        if (not re.fullmatch(r"[A-Z0-9]{3,5}", self.tag)
                or self.bytes <= 0 or self.bytes % BLOCK
                or not (whole or numbered)):
            raise ProtocolError("invalid fixed-node profile")

    @property
    def chunks(self):
        return self.bytes // BLOCK

    @property
    def windows(self):
        return (self.chunks + WINDOW - 1) // WINDOW

    def magic(self, suffix: str) -> bytes:
        if suffix not in ("REQV1", "CHUNKV1", "WINMAN1"):
            raise ProtocolError("unknown wire magic")
        raw = ("CXD" + self.tag + suffix).encode("ascii")
        if len(raw) > 16:
            raise ProtocolError("wire magic too long")
        return raw.ljust(16, b"\0")

    def nonce(self, kind: str, index: int) -> int:
        if kind not in ("chunk", "manifest") or index < 0:
            raise ProtocolError("invalid nonce")
        return (0xa7c2102000001000 if kind == "chunk"
                else 0xa7c210200000f000) + self.partition * 0x10000 + index


CN2 = Profile("CN2", 2, "cnflasha2", 130, 20 * 1024 * 1024)
PNALL = Profile("PNALL", 0, "pnflasha", 0, 1_954_545_664, 1)
CN1 = Profile("CN1", 1, "cnflasha1", 129, 25_100_288)


def capture_bytes(capture_id: str) -> bytes:
    if (not isinstance(capture_id, str) or not CAPTURE.fullmatch(capture_id)
            or capture_id == "0" * 32):
        raise ProtocolError("capture ID must be 16 nonzero lowercase-hex bytes")
    return bytes.fromhex(capture_id)


def window_shape(profile: Profile, index: int) -> tuple[int, int]:
    if type(index) is not int or not 0 <= index < profile.windows:
        raise ProtocolError("window outside fixed partition")
    start = index * WINDOW
    return start, min(WINDOW, profile.chunks - start)


def request_bytes(profile: Profile, capture_id: str, index: int) -> bytes:
    start, count = window_shape(profile, index)
    raw = REQUEST.pack(profile.magic("REQV1"), capture_bytes(capture_id),
                       1, profile.partition, index, start, count, BLOCK, 0, 0)
    return raw[:56] + struct.pack("<II", zlib.crc32(raw[:56]), 0)


def output_dir(profile: Profile, capture_id: str, index: int) -> bytes:
    window_shape(profile, index)
    capture_bytes(capture_id)
    return (b"/tmp_wbshd/codex_" + profile.tag.lower().encode() + b"_"
            + capture_id.encode() + b"_w" + str(index).encode() + b"_201")


def manifest_path(profile: Profile, capture_id: str, index: int) -> bytes:
    return output_dir(profile, capture_id, index) + b"/manifest.bin"


def chunk_path(profile: Profile, capture_id: str,
               index: int, global_index: int) -> bytes:
    start, count = window_shape(profile, index)
    if type(global_index) is not int or not start <= global_index < start + count:
        raise ProtocolError("chunk index outside window")
    return (output_dir(profile, capture_id, index) + b"/chunk_"
            + f"{global_index-start:02x}".encode() + b".bin")


def parse_manifest(profile: Profile, raw: bytes,
                   capture_id: str, index: int) -> dict:
    if not isinstance(raw, bytes) or len(raw) != MANIFEST.size:
        raise ProtocolError("manifest length mismatch")
    start, count = window_shape(profile, index)
    (magic, version, partition, part_bytes, block_bytes, window_count,
     produced, crc, major, minor, name, status, reserved, nonce, reserved2,
     capture, wire_window, wire_start, total_chunks, reserved3) = MANIFEST.unpack(raw)
    if (magic != profile.magic("WINMAN1") or version != 1
            or partition != profile.partition or part_bytes != profile.bytes
            or block_bytes != BLOCK or window_count != count or produced != count
            or major != 252 or minor != profile.minor
            or name != profile.source.encode().ljust(16, b"\0")
            or status != 0 or reserved or reserved2 or reserved3
            or nonce != profile.nonce("manifest", index)
            or capture != capture_bytes(capture_id)
            or wire_window != index or wire_start != start
            or total_chunks != profile.chunks):
        raise ProtocolError("manifest source, capture or status mismatch")
    return {"capture_id": capture_id, "window_index": index,
            "window_start": start, "window_count": count,
            "window_crc32": crc, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "partition_bytes": part_bytes, "selected_major": major,
            "selected_minor": minor, "selected_kernel_name": profile.source}


def parse_chunk(profile: Profile, raw: bytes,
                global_index: int, manifest: dict) -> dict:
    if not isinstance(raw, bytes) or len(raw) != CHUNK.size + BLOCK:
        raise ProtocolError("chunk length mismatch")
    (magic, version, partition, offset, part_bytes, requested, actual,
     crc, status, nonce, major, minor, name, candidates, reserved,
     capture, window, wire_index, reserved2) = CHUNK.unpack_from(raw)
    start = manifest["window_start"]
    if (type(global_index) is not int or not start <= global_index <
            start + manifest["window_count"] or magic != profile.magic("CHUNKV1")
            or version != 1 or partition != profile.partition
            or offset != global_index * BLOCK or part_bytes != profile.bytes
            or requested != BLOCK or actual != BLOCK or status != 0
            or nonce != profile.nonce("chunk", global_index)
            or major != manifest["selected_major"] or minor != manifest["selected_minor"]
            or name != profile.source.encode().ljust(16, b"\0")
            or candidates != profile.candidate_count or reserved or reserved2
            or capture != capture_bytes(manifest["capture_id"])
            or window != manifest["window_index"] or wire_index != global_index):
        raise ProtocolError("chunk source, capture or offset mismatch")
    body = raw[CHUNK.size:]
    if zlib.crc32(body) != crc:
        raise ProtocolError("chunk CRC mismatch")
    return {"index": global_index, "offset": offset, "data": body,
            "crc32": crc, "sha256": hashlib.sha256(body).hexdigest()}


def verify_window(profile: Profile, rows: list[dict], manifest: dict) -> None:
    start = manifest["window_start"]
    count = manifest["window_count"]
    if len(rows) != count or [r["index"] for r in rows] != list(range(start, start + count)):
        raise ProtocolError("window missing, duplicate or unordered chunk")
    crc = 0
    for row in rows:
        crc = zlib.crc32(row["data"], crc)
    if crc != manifest["window_crc32"]:
        raise ProtocolError("whole-window CRC mismatch")
