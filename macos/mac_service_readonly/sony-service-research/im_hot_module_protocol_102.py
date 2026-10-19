#!/usr/bin/env python3
"""Powered-session im.elf hot-module records for ILCE-7CM2 1.02.

This module only packs and validates bytes. Importing it never accesses USB.
The dispatcher, not Jiritsu SET_FILE2, opens each uniquely named module.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib


READY_MAGIC = b"A7C2MODREADY0102"
COMMAND_MAGIC = b"A7C2MODCOMMAND01"
RESULT_MAGIC = b"A7C2MODRESULT102"
READY_BYTES = RESULT_BYTES = 128
COMMAND_BYTES = 256
MODULE_MAX_BYTES = 4 * 1024 * 1024
READY_PATH = b"/tmp_wbshd/codex_mod_ready_102"
COMMAND_PATH = b"/tmp_wbshd/codex_mod_command_102"
MODULE_DIR = b"/tmp_wbshd/"
VERSION = 1
_BASENAME = re.compile(rb"codex_mod_[0-9a-f]{16}_[0-9a-f]{8}\.so\Z")

assert all(len(x) == 16 for x in (READY_MAGIC, COMMAND_MAGIC, RESULT_MAGIC))


def module_basename(nonce: int, seq: int) -> bytes:
    if not 1 <= nonce <= 0xffffffffffffffff or not 1 <= seq <= 0xffffffff:
        raise ValueError("invalid session nonce or sequence")
    return f"codex_mod_{nonce:016x}_{seq:08x}.so".encode("ascii")


def module_path(nonce: int, seq: int) -> bytes:
    return MODULE_DIR + module_basename(nonce, seq)


def result_path(nonce: int, seq: int) -> bytes:
    module_basename(nonce, seq)
    return MODULE_DIR + f"codex_mod_result_{nonce:016x}_{seq:08x}_102".encode("ascii")


def _checked_crc(raw: bytes, expected_length: int, crc_offset: int) -> None:
    if len(raw) != expected_length or struct.unpack_from("<I", raw, crc_offset)[0] != zlib.crc32(raw[:crc_offset]):
        raise ValueError("record length or CRC mismatch")


def parse_ready(raw: bytes) -> dict:
    _checked_crc(raw, READY_BYTES, 124)
    magic, version, nbytes, nonce, pid, status, checks = struct.unpack_from("<16sIIQIII", raw)
    if (magic != READY_MAGIC or version != VERSION or nbytes != READY_BYTES
            or not 1 <= nonce <= 0xffffffffffffffff or not 1 <= pid <= 0x7fffffff
            or status != 1 or raw[44:124] != b"\0" * 80):
        raise ValueError("invalid dispatcher READY record")
    return {"nonce": nonce, "pid": pid, "status": status, "checks": checks,
            "sha256": hashlib.sha256(raw).hexdigest()}


def build_command(nonce: int, seq: int, module: bytes, config: bytes = b"",
                  *, grants: int = 0) -> bytes:
    basename = module_basename(nonce, seq)
    if (not isinstance(module, bytes) or not 1 <= len(module) <= MODULE_MAX_BYTES
            or not isinstance(config, bytes) or len(config) > 64
            or type(grants) is not int or not 0 <= grants <= 0xffffffff):
        raise ValueError("module or config length exceeds dispatcher ABI")
    if len(basename) >= 96:
        raise ValueError("module basename too long")
    raw = bytearray(COMMAND_BYTES)
    struct.pack_into("<16sIIQQQ", raw, 0, COMMAND_MAGIC, VERSION,
                     COMMAND_BYTES, nonce, seq, len(module))
    raw[48:80] = hashlib.sha256(module).digest()
    raw[80:80 + len(basename)] = basename
    struct.pack_into("<II", raw, 176, len(config), grants)
    raw[184:184 + len(config)] = config
    struct.pack_into("<I", raw, 252, zlib.crc32(raw[:252]))
    return bytes(raw)


def parse_command(raw: bytes) -> dict:
    _checked_crc(raw, COMMAND_BYTES, 252)
    magic, version, nbytes, nonce, seq, size = struct.unpack_from("<16sIIQQQ", raw)
    name_field = raw[80:176]
    name, _, tail = name_field.partition(b"\0")
    config_bytes, flags = struct.unpack_from("<II", raw, 176)
    if (magic != COMMAND_MAGIC or version != VERSION or nbytes != COMMAND_BYTES
            or not 1 <= nonce <= 0xffffffffffffffff or not 1 <= seq <= 0xffffffff
            or not 1 <= size <= MODULE_MAX_BYTES or not name or not _BASENAME.fullmatch(name)
            or name != module_basename(nonce, seq) or not tail or any(tail)
            or config_bytes > 64 or any(raw[184 + config_bytes:248])
            or raw[248:252] != b"\0" * 4):
        raise ValueError("invalid dispatcher command")
    return {"nonce": nonce, "seq": seq, "module_bytes": size,
            "module_sha256": raw[48:80].hex(), "basename": name.decode("ascii"),
            "config": raw[184:184 + config_bytes], "grants": flags,
            "sha256": hashlib.sha256(raw).hexdigest()}


def parse_result(raw: bytes, *, nonce: int, seq: int, module_sha256: str) -> dict:
    _checked_crc(raw, RESULT_BYTES, 124)
    magic, version, nbytes, found_nonce, found_seq, stage, status, module_rc, event_code, event_bytes = (
        struct.unpack_from("<16sIIQQIiiII", raw))
    if (magic != RESULT_MAGIC or version != VERSION or nbytes != RESULT_BYTES
            or found_nonce != nonce or found_seq != seq or event_bytes > 32
            or any(raw[60 + event_bytes:92]) or raw[92:124].hex() != module_sha256):
        raise ValueError("invalid or stale dispatcher result")
    return {"nonce": nonce, "seq": seq, "stage": stage, "status": status,
            "module_rc": module_rc, "event_code": event_code,
            "event_data_hex": raw[60:60 + event_bytes].hex(),
            "module_sha256": module_sha256,
            "sha256": hashlib.sha256(raw).hexdigest()}
