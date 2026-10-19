"""Minimal read-only BK4 color-property parser for the USB snapshot probe."""

import hashlib
import struct

PROPERTY_ID = 0x02A40001
PROPERTY_SIZE = 8192


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_property(raw):
    candidates = []
    cursor = 0
    while True:
        magic = raw.find(b"BK4\0", cursor)
        if magic < 0:
            break
        cursor = magic + 4
        base = magic - 12
        if base < 0 or base + 0x100 > len(raw):
            continue
        _, _, _, _, subs, props, data_off, data_size, checksum = struct.unpack_from(
            "<9I", raw, base)
        total = data_off + data_size
        if total < 0x100 or base + total > len(raw) or subs > 4096 or props > 100000:
            continue
        record = raw[base:base + total]
        actual = (sum(record[:0x20]) + sum(record[0x24:])) & 0xffffffff
        if actual != checksum:
            continue
        subsystem, index = PROPERTY_ID >> 16, PROPERTY_ID & 0xffff
        if subsystem >= subs:
            continue
        count, first = struct.unpack_from("<HI", record, 0x100 + 6 * subsystem)
        if index >= count or first + index >= props:
            continue
        entry = 0x100 + 6 * subs + 6 * (first + index)
        if entry + 6 > total:
            continue
        attr, pointer = struct.unpack_from("<HI", record, entry)
        if pointer == 0xffffffff:
            continue
        size, start = pointer >> 24, pointer & 0xffffff
        if size == 0xff:
            if start + 2 > total:
                continue
            size = struct.unpack_from("<H", record, start)[0]
            start += 2
        elif size == 0:
            if start + 4 > total:
                continue
            size, maximum = struct.unpack_from("<HH", record, start)
            if size > maximum:
                continue
            start += 4
        if size != PROPERTY_SIZE or start < data_off or start + size > total:
            continue
        candidates.append((record[start:start + size], {
            "record_file_offset": hex(base),
            "record_length": total,
            "record_checksum_verified": True,
            "property_id": hex(PROPERTY_ID),
            "property_attribute": hex(attr),
            "property_table_offset": hex(base + entry),
            "property_data_offset": hex(base + start),
            "property_length": size,
        }))
    if len(candidates) != 1:
        raise ValueError(f"expected one valid BK4 color property, got {len(candidates)}")
    return candidates[0]
