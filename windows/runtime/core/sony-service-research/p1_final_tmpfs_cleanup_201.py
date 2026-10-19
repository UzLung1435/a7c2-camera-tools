#!/usr/bin/env python3
"""Cleanup of one host-verified p1 capture's final temporary window.

Only exact Jiritsu SET_FILE_PATH/DELETE_FILE2 paths for the selected capture
are permitted. Rehashes the complete private image and all recorded chunks
before any camera deletion. The photo SD card and internal block nodes are
never opened by this module.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import service_probe as base
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
import p1_block_window_protocol_201 as wire
import p1_fixed_host_export_201 as host


LIVE_CLEANUP_REVIEWED = False
PATH_PREFIX = b"\x01\x10\x0f\x00\x00"
DELETE_DATA = b"\x01\x10\x12\x00\x00\xff\x00"


class CleanupSession(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        p = backend.profile
        capture = backend.capture_id
        index = backend.window_index
        start, count = wire.window_shape(p, index)
        self.manifest_path = preflight.PREFIX + wire.manifest_path(p, capture, index)
        self.chunk_paths = tuple(preflight.PREFIX + wire.chunk_path(
            p, capture, index, global_index)
            for global_index in range(start, start + count))
        self.selected_path = None
        self.allowed_paths = frozenset((self.manifest_path, *self.chunk_paths))
        self.allowed_path_bodies = frozenset(PATH_PREFIX + p for p in self.allowed_paths)

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            if len(raw) < version.HEADER.size:
                raise version.JiritsuProbeError("request_not_allowlisted")
            body = raw[version.HEADER.size:]
            if (body not in self.allowed_path_bodies | {preflight.READ_DATA, DELETE_DATA}
                    or (body == DELETE_DATA and
                        (not self.backend.camera_manifest_verified
                         or self.selected_path not in self.allowed_paths))):
                raise version.JiritsuProbeError("request_not_allowlisted")
        return version.JiritsuSession.write(self, data, ep)

    def _fixed_query(self, dev, body, label, expected_size):
        if body in self.allowed_path_bodies:
            self.selected_path = body[len(PATH_PREFIX):]
        result = super()._fixed_query(dev, body, label, expected_size)
        if body == DELETE_DATA:
            self.selected_path = None
        return result

    def _delete_exact(self, dev, label, path):
        if path not in self.allowed_paths:
            raise base.ProbeError("unlisted cleanup path")
        self._fixed_query(dev, PATH_PREFIX + path, "select_" + label, 4)
        self._fixed_query(dev, DELETE_DATA, "delete_" + label, 4)

    def product_info(self):
        if self.info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        dev = self.backend.senser_class(self)
        camera = self.backend.camera_class(dev)
        self.wire_phase = "product"
        try:
            product = camera.readHasp()
            self.finish(dev, product)
        finally:
            self.wire_phase = None
        if len(product) != 88:
            raise version.JiritsuProbeError("state_not_complete")
        self.product_verified = self.backend.product_verified = True
        self._read_fixed(dev, "camera_manifest", self.manifest_path)
        item = self.backend.files["camera_manifest"]
        if item[0] != "present":
            self.backend.camera_manifest_absent = True
            return 88
        parsed = wire.parse_manifest(self.backend.profile, item[1],
                                     self.backend.capture_id,
                                     self.backend.window_index)
        if parsed["manifest_sha256"] != self.backend.expected_manifest_sha256:
            raise base.ProbeError("camera and host completed manifest differ")
        self.backend.camera_manifest_verified = True
        start, count = wire.window_shape(self.backend.profile,
                                         self.backend.window_index)
        for local, path in enumerate(self.chunk_paths):
            self._read_fixed(dev, f"chunk_before_{local:02x}", path)
            file = self.backend.files[f"chunk_before_{local:02x}"]
            if file[0] == "not_found_or_unreadable":
                self.backend.already_absent_chunks += 1
                continue
            if file[0] != "present":
                raise base.ProbeError("chunk state not verified")
            record = wire.parse_chunk(self.backend.profile, file[1],
                                      start + local, parsed)
            expected = self.backend.expected_chunks[local]
            if (record["sha256"] != expected["sha256"]
                    or record["offset"] != expected["offset"]
                    or record["crc32"] != expected["camera_crc32"]):
                raise base.ProbeError("camera chunk differs from completed host image")
            self._delete_exact(dev, f"chunk_{local:02x}", path)
            self.backend.deleted_chunks += 1
        self._delete_exact(dev, "manifest", self.manifest_path)
        self._read_fixed(dev, "manifest_after", self.manifest_path)
        self.backend.cleanup_complete = (
            self.backend.files["manifest_after"][0] == "not_found_or_unreadable"
            and self.backend.deleted_chunks + self.backend.already_absent_chunks ==
                len(self.chunk_paths))
        return 88


class CleanupBackend(preflight.PreflightBackend):
    def __init__(self, *args, profile, capture_id, window_index,
                 expected_manifest_sha256, expected_chunks, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile = profile
        self.capture_id = capture_id
        self.window_index = window_index
        self.expected_manifest_sha256 = expected_manifest_sha256
        self.expected_chunks = expected_chunks
        self.camera_manifest_absent = False
        self.camera_manifest_verified = False
        self.deleted_chunks = 0
        self.already_absent_chunks = 0
        self.cleanup_complete = False

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = CleanupSession(self, info)
        self.sessions.append(session)
        return session.open()


def _quiet_logger():
    logger = version.safe_logger()
    def log(event, **fields):
        if event in ("probe_failed", "probe_summary", "normal_mode_verified"):
            logger(event, **fields)
    return log


def _host_proof(source, capture_id):
    if source != "cnflasha1" or len(capture_id) != 32 or any(
            c not in "0123456789abcdef" for c in capture_id):
        raise base.ProbeError("p1 capture identity invalid")
    owner = host._private_dir(0)
    profile = wire.CN1
    manifest = host.BACKUP_DIR / f"{source}-{capture_id}-manifest.json"
    info = manifest.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != owner.st_uid or info.st_nlink != 1
            or not 0 < info.st_size <= 8 * 1024 * 1024):
        raise base.ProbeError("private p1 manifest identity changed")
    fd = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, info.st_size + 1)
    finally:
        os.close(fd)
    if len(raw) != info.st_size:
        raise base.ProbeError("private p1 manifest read incomplete")
    receipt = json.loads(raw)
    if (receipt.get("format") != "codex-owner-block-image-v1"
            or receipt.get("camera") != "ILCE-7CM2"
            or receipt.get("firmware") != "2.01"
            or receipt.get("source") != source
            or receipt.get("capture_id") != capture_id
            or receipt.get("partition_bytes") != profile.bytes
            or receipt.get("elf_sha256") != host.ELF_SHA256
            or receipt.get("complete") is not True
            or len(receipt.get("windows", [])) != profile.windows):
        raise base.ProbeError("completed p1 receipt invalid")
    image = host.BACKUP_DIR / receipt.get("image_basename", "")
    info = image.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != owner.st_uid or info.st_nlink != 1
            or info.st_size != profile.bytes):
        raise base.ProbeError("private p1 image identity changed")
    whole = hashlib.sha256()
    fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        for window_index, window in enumerate(receipt["windows"]):
            start, count = wire.window_shape(profile, window_index)
            if (window.get("index") != window_index or
                    len(window.get("chunks", [])) != count):
                raise base.ProbeError("p1 window receipt incomplete")
            for local, chunk in enumerate(window["chunks"]):
                offset = (start + local) * wire.BLOCK
                data = os.pread(fd, wire.BLOCK, offset)
                if (len(data) != wire.BLOCK or chunk.get("offset") != offset
                        or hashlib.sha256(data).hexdigest() != chunk.get("sha256")):
                    raise base.ProbeError("p1 image chunk differs from receipt")
                whole.update(data)
    finally:
        os.close(fd)
    if whole.hexdigest() != receipt.get("image_sha256"):
        raise base.ProbeError("p1 whole image differs from receipt")
    digest = hashlib.sha256(raw).hexdigest()
    last = receipt["windows"][-1]
    if (last["index"] != profile.windows - 1
            or len(last["chunks"]) != wire.window_shape(profile, last["index"])[1]):
        raise base.ProbeError("completed final-window metadata mismatch")
    return owner, profile, last, digest


def cleanup(source, capture_id, *, no_camera=False):
    owner, profile, last, host_manifest_sha = _host_proof(source, capture_id)
    marker = host.BACKUP_DIR / f"p1-tmpfs-clean-{source}-{capture_id}.json"
    if marker.exists() or marker.is_symlink():
        info = marker.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != owner.st_uid or info.st_nlink != 1
                or not 0 < info.st_size <= 4096):
            raise base.ProbeError("existing p1 cleanup marker identity changed")
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, info.st_size + 1)
        finally:
            os.close(fd)
        if len(raw) != info.st_size:
            raise base.ProbeError("existing p1 cleanup marker read incomplete")
        old = json.loads(raw)
        if (old.get("source") == source and old.get("capture_id") == capture_id
                and old.get("host_manifest_sha256") == host_manifest_sha
                and old.get("camera_manifest_sha256") == last["manifest_sha256"]
                and old.get("complete") is True):
            return {"source": source, "result": "already_cleaned",
                    "window": last["index"], "chunks": len(last["chunks"])}
        raise base.ProbeError("existing cleanup marker inconsistent")
    if no_camera:
        return {"source": source, "result": "offline_plan", "camera_access": False,
                "window": last["index"], "chunks": len(last["chunks"])}
    host._prepare_host_volumes()
    core, util, auth, senser, camera, explicit = host._usb_backend()
    backend = CleanupBackend(
        core, util, auth, senser, camera, version.MSC_PID, version.PRODUCT,
        budget=host.WindowBudget(), usb_backend=explicit,
        logger=_quiet_logger(), profile=profile, capture_id=capture_id,
        window_index=last["index"],
        expected_manifest_sha256=last["manifest_sha256"],
        expected_chunks=last["chunks"])
    code, lifecycle = base.run_probe(backend)
    if code != 0 or not lifecycle["normal_mode_and_driver_verified"]:
        raise base.ProbeError("normal MSC not restored after cleanup")
    if backend.camera_manifest_absent:
        return {"source": source, "result": "camera_manifest_absent",
                "window": last["index"], "chunks": 0}
    if not backend.cleanup_complete:
        raise base.ProbeError("completed final window not fully deleted")
    receipt = {"format": "codex-p1-tmpfs-clean-v1", "source": source,
               "capture_id": capture_id, "host_manifest_sha256": host_manifest_sha,
               "camera_manifest_sha256": last["manifest_sha256"],
               "window_index": last["index"], "deleted_chunks": backend.deleted_chunks,
               "already_absent_chunks": backend.already_absent_chunks,
               "ordinary_msc_restored": True, "complete": True}
    host._write_manifest(marker, owner, receipt)
    return {"source": source, "result": "cleaned",
            "window": last["index"],
            "chunks": backend.deleted_chunks + backend.already_absent_chunks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if args.execute and not LIVE_CLEANUP_REVIEWED:
        parser.error("completed-window cleanup remains held for review")
    if args.execute and os.geteuid() != 0:
        parser.error("sudo -n root required")
    report = cleanup(args.source, args.capture_id, no_camera=not args.execute)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["result"] in ("offline_plan", "already_cleaned", "cleaned") else 2


if __name__ == "__main__":
    raise SystemExit(main())
