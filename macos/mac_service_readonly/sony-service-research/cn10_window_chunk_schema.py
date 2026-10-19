"""Pure fixed-wire cnflasha10 window/chunk schema; no USB or camera access."""

import hashlib
from pathlib import Path
import zlib

import service_probe as base
import cn10_window_producer_probe as producer


BACKUP_DIR = Path(
    "/Users/luoyu/Library/Application Support/CodexCameraResearch/ILCE-7CM2-102")
BODY_SIZE = producer.CHUNK.size + producer.CHUNK_BYTES
MAX_USB_FRAGMENT = 4096
DATA_TIMEOUT_MS = 5000
assert BODY_SIZE == 65664 and producer.TOTAL_CHUNKS == 192


def path_for_index(index, capture_id, window_index):
    start, count = producer.window_shape(window_index)
    if type(index) is not int or not start <= index < start + count:
        raise base.ProbeError("cn10 chunk index outside fixed window")
    local = index - start
    return (producer.PREFIX + producer.output_directory(capture_id, window_index)
            + b"/chunk_" + f"{local:02x}".encode("ascii") + b".bin")


def parse_chunk(raw, index, manifest):
    if not isinstance(raw, bytes) or len(raw) != BODY_SIZE:
        raise base.ProbeError("cn10 chunk length mismatch")
    (magic, generation, partition, offset, part_bytes, requested, actual,
     crc, status, nonce, major, minor, name_raw, candidate_count, reserved,
     capture_raw, window_index, global_index, reserved2) = (
         producer.CHUNK.unpack_from(raw))
    name = name_raw.split(b"\0", 1)[0]
    if (magic != producer.CHUNK_MAGIC or generation != 1 or partition != 10
            or offset != index * producer.CHUNK_BYTES
            or part_bytes != producer.PARTITION_BYTES
            or requested != producer.CHUNK_BYTES
            or actual != producer.CHUNK_BYTES or status != 0
            or nonce != 0xa7c21020000a1000 + index
            or major != manifest["selected_major"]
            or minor != manifest["selected_minor"]
            or name != b"cnflasha10" or name_raw != name.ljust(16, b"\0")
            or candidate_count != 2 or reserved != 0 or reserved2 != 0
            or capture_raw.hex() != manifest["capture_id"]
            or window_index != manifest["window_index"]
            or global_index != index):
        raise base.ProbeError("cn10 chunk header/capture/devt mismatch")
    data = raw[producer.CHUNK.size:]
    if zlib.crc32(data) != crc:
        raise base.ProbeError("cn10 chunk CRC mismatch")
    return {"index": index, "offset": offset, "data": data,
            "crc32": crc, "sha256": hashlib.sha256(data).hexdigest()}
