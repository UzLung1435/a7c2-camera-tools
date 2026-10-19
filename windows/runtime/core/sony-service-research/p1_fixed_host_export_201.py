#!/usr/bin/env python3
"""Fixed-node read-only p1 export using the reviewed Jiritsu window route.

One 8-MiB camera tmpfs window and one authenticated USB service session at a
time. The host keeps one sparse-in-progress image and a durable per-chunk hash
manifest; on success it publishes one 0600 image. No photo-card reads.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import types
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import service_probe as base
import jiritsu_version_probe as version
import cn10_window_producer_probe as producer
import cn10_same_session_probe as same
import p1_block_window_protocol_201 as protocol


ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIR = ROOT / "snapshots"
SOURCE_PATH = ROOT / "sony-firmware-research/volatile_p1_window_201.c"
SOURCE_SHA256 = "7ab0177c8c1d7e45a7b9d399e40e3ea37004acea08117d66938fb2a78dbdb742"
PROFILE = protocol.CN1
ELF_PATH = ROOT / "sony-firmware-research/libcodex_cn1_window_201.so"
ELF_SIZE = 9520
ELF_SHA256 = "2adbcbc2a2eca3fe262e0aac2db475a0cf524de8c3e8a67b6ead24aebda0af78"
LIVE_EXECUTION_REVIEWED = False
_configured = False
PROBE_REPORT = None


def set_probe_report(report):
    global PROBE_REPORT
    sys.path.insert(0, str(ROOT))
    import run_backup_snapshot_ro as identity
    identity.report_identity(report)
    PROBE_REPORT = report


def select_target(source):
    """Refuse all targets except the pinned p1 node and worker."""
    if _configured:
        raise base.ProbeError("target cannot change after transport binding")
    if (source != "cnflasha1" or PROFILE.source != source
            or hashlib.sha256(SOURCE_PATH.read_bytes()).hexdigest() != SOURCE_SHA256
            or ELF_PATH.stat().st_size != ELF_SIZE
            or hashlib.sha256(ELF_PATH.read_bytes()).hexdigest() != ELF_SHA256):
        raise base.ProbeError("p1 worker identity mismatch")


def configure_existing_transport():
    """Bind the tested cn10 session implementation to one pinned node protocol.

    This process-local adapter changes no on-disk cn10 source or saved receipt.
    """
    global _configured
    if _configured:
        return
    producer.ELF_PATH = ELF_PATH
    producer.ELF_SIZE = ELF_SIZE
    producer.ELF_SHA256 = ELF_SHA256
    tag = PROFILE.tag.lower().encode("ascii")
    producer.RAM_LIBRARY = b"/tmp_wbshd/libcodex_" + tag + b"_window_201.so"
    producer.RAM_PATH = producer.PREFIX + producer.RAM_LIBRARY
    producer.REQUEST_PATH = (
        producer.PREFIX + b"/tmp_wbshd/codex_" + tag + b"_request_201.bin")
    producer.ARM_TEXT = producer.RAM_LIBRARY + b"\n"
    producer.ARM_WRITE_DATA = producer.WRITE_PREFIX + producer.ARM_TEXT
    producer.RAM_PATH_DATA = producer.PATH_PREFIX + producer.RAM_PATH
    producer.REQUEST_PATH_DATA = producer.PATH_PREFIX + producer.REQUEST_PATH
    producer.REQUEST_MAGIC = PROFILE.magic("REQV1")
    producer.MANIFEST_MAGIC = PROFILE.magic("WINMAN1")
    producer.CHUNK_MAGIC = PROFILE.magic("CHUNKV1")
    producer.PARTITION_BYTES = PROFILE.bytes
    producer.TOTAL_CHUNKS = PROFILE.chunks
    producer.MIN_OWNED_PREFIX = len(b"/tmp_wbshd/libcodex_" + tag + b"_")
    producer.window_shape = lambda index: protocol.window_shape(PROFILE, index)
    producer.output_directory = lambda capture, index: protocol.output_dir(PROFILE, capture, index)
    producer.manifest_path = lambda capture, index: (
        producer.PREFIX + protocol.manifest_path(PROFILE, capture, index))
    producer.request_bytes = lambda capture, index: protocol.request_bytes(PROFILE, capture, index)
    producer.parse_manifest = lambda raw, capture, index: protocol.parse_manifest(
        PROFILE, raw, capture, index)
    same.schema = types.SimpleNamespace(
        BODY_SIZE=protocol.CHUNK.size + protocol.BLOCK,
        MAX_USB_FRAGMENT=4096,
        DATA_TIMEOUT_MS=5000,
        path_for_index=lambda index, capture, window: (
            producer.PREFIX + protocol.chunk_path(PROFILE, capture, window, index)),
        parse_chunk=lambda raw, index, manifest: protocol.parse_chunk(
            PROFILE, raw, index, manifest))
    _configured = True


class WindowBudget(same.Work10Budget):
    def __init__(self):
        base.Budget.__init__(self, total=600.0, reserve=60.0)
        self.work_calls = 0
        self.recovery_calls = 0
        self.long_trigger = False
        self.bulk_read = False
        self.max_work_calls = 4500
        self.max_response_bytes = 9 * 1024 * 1024


class WindowSession(same.Work10Session):
    def _read_fixed(self, dev, label, path):
        result = super()._read_fixed(dev, label, path)
        if label == "previous_manifest" and self.window_index > 0:
            item = self.backend.files.get(label)
            if (not item or item[0] != "present"
                    or hashlib.sha256(item[1]).hexdigest() !=
                        self.backend.expected_previous_manifest_sha256):
                raise base.ProbeError("previous owner window manifest changed")
        return result


class WindowBackend(producer.ProducerBackend):
    def __init__(self, *args, previous_manifest_sha256=None, **kwargs):
        super().__init__(*args, **kwargs)
        if self.window_index == 0:
            if previous_manifest_sha256 is not None:
                raise base.ProbeError("unexpected previous manifest")
        elif (not isinstance(previous_manifest_sha256, str)
              or len(previous_manifest_sha256) != 64
              or any(c not in "0123456789abcdef" for c in previous_manifest_sha256)):
            raise base.ProbeError("previous manifest SHA required")
        self.expected_previous_manifest_sha256 = previous_manifest_sha256
        self.validated = {}
        self.collection_verified = False
        self.failure_index = None
        self.failure_type = None
        self.failure_phase = None
        self.chunk_declared_bytes = None
        self.padding_returned_length = None

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = WindowSession(self, info)
        self.sessions.append(session)
        return session.open()


def _private_dir(needed):
    info = BACKUP_DIR.lstat()
    owner = int(os.environ.get("SUDO_UID", os.geteuid()))
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != owner):
        raise base.ProbeError("private backup directory identity/mode mismatch")
    free = os.statvfs(BACKUP_DIR)
    if free.f_bavail * free.f_frsize < 2 * 1024**3 + needed:
        raise base.ProbeError("private target below 2-GiB free-space reserve")
    return info


def _create_owned(path, owner, *, size=None):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchown(fd, owner.st_uid, owner.st_gid)
        os.fchmod(fd, 0o600)
        if size is not None:
            os.ftruncate(fd, size)
        os.fsync(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_manifest(path, owner, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temp = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = _create_owned(temp, owner)
    try:
        if os.write(fd, raw) != len(raw):
            raise base.ProbeError("short private manifest write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    dirfd = os.open(BACKUP_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def _pwrite_all(fd, offset, data):
    at = 0
    while at < len(data):
        n = os.pwrite(fd, data[at:], offset + at)
        if n <= 0:
            raise base.ProbeError("short private image write")
        at += n


def _store_window(fd, owner, receipt_path, receipt, backend):
    manifest = backend.manifest_fields
    start, count = protocol.window_shape(PROFILE, backend.window_index)
    rows = [backend.validated[i] for i in range(start, start + count)]
    protocol.verify_window(PROFILE, rows, manifest)
    free = os.statvfs(BACKUP_DIR)
    if free.f_bavail * free.f_frsize < 2 * 1024**3 + count * protocol.BLOCK:
        raise base.ProbeError("private target below 2-GiB window commit reserve")
    for row in rows:
        _pwrite_all(fd, row["offset"], row["data"])
    os.fsync(fd)
    hashes = []
    for row in rows:
        got = os.pread(fd, protocol.BLOCK, row["offset"])
        if len(got) != protocol.BLOCK or hashlib.sha256(got).hexdigest() != row["sha256"]:
            raise base.ProbeError("private image readback hash mismatch")
        hashes.append({"offset": row["offset"], "sha256": row["sha256"],
                       "camera_crc32": row["crc32"]})
    receipt["windows"].append({
        "index": backend.window_index,
        "manifest_sha256": manifest["manifest_sha256"],
        "window_crc32": manifest["window_crc32"],
        "selected_major": manifest["selected_major"],
        "selected_minor": manifest["selected_minor"],
        "selected_kernel_name": manifest["selected_kernel_name"],
        "chunks": hashes})
    _write_manifest(receipt_path, owner, receipt)


def _load_partial(part, receipt_path, owner, capture_id):
    for path, size in ((part, PROFILE.bytes), (receipt_path, None)):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != owner.st_uid or info.st_nlink != 1
                or (size is not None and info.st_size != size)
                or (size is None and not 0 < info.st_size <= 8 * 1024 * 1024)):
            raise base.ProbeError("partial owner image/manifest identity mismatch")
    receipt = json.loads(receipt_path.read_bytes())
    if (receipt.get("format") != "codex-owner-block-image-v1"
            or receipt.get("camera") != "ILCE-7CM2" or receipt.get("firmware") != "2.01"
            or receipt.get("source") != PROFILE.source
            or receipt.get("capture_id") != capture_id
            or receipt.get("major") != 252 or receipt.get("minor") != PROFILE.minor
            or receipt.get("partition_bytes") != PROFILE.bytes
            or receipt.get("elf_sha256") != ELF_SHA256
            or receipt.get("complete") is not False
            or not isinstance(receipt.get("windows"), list)
            or len(receipt["windows"]) >= PROFILE.windows):
        raise base.ProbeError("partial owner manifest source/completion mismatch")
    fd = os.open(part, os.O_RDWR | os.O_NOFOLLOW)
    try:
        for index, window in enumerate(receipt["windows"]):
            start, count = protocol.window_shape(PROFILE, index)
            if (window.get("index") != index
                    or window.get("selected_major") != 252
                    or window.get("selected_minor") != PROFILE.minor
                    or window.get("selected_kernel_name") != PROFILE.source
                    or not isinstance(window.get("manifest_sha256"), str)
                    or len(window["manifest_sha256"]) != 64
                    or type(window.get("window_crc32")) is not int
                    or not isinstance(window.get("chunks"), list)
                    or len(window["chunks"]) != count):
                raise base.ProbeError("partial owner window metadata mismatch")
            crc = 0
            for local, chunk in enumerate(window["chunks"]):
                offset = (start + local) * protocol.BLOCK
                if (chunk.get("offset") != offset
                        or not isinstance(chunk.get("sha256"), str)
                        or len(chunk["sha256"]) != 64
                        or type(chunk.get("camera_crc32")) is not int):
                    raise base.ProbeError("partial owner chunk metadata mismatch")
                data = os.pread(fd, protocol.BLOCK, offset)
                if (len(data) != protocol.BLOCK
                        or hashlib.sha256(data).hexdigest() != chunk["sha256"]
                        or zlib.crc32(data) != chunk["camera_crc32"]):
                    raise base.ProbeError("partial owner chunk bytes changed")
                crc = zlib.crc32(data, crc)
            if crc != window["window_crc32"]:
                raise base.ProbeError("partial owner window CRC mismatch")
    except BaseException:
        os.close(fd)
        raise
    return fd, receipt


def _events(output):
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            yield item


def _prepare_host_volumes():
    if PROBE_REPORT is None:
        raise base.ProbeError("new camera probe report is required")
    sys.path.insert(0, str(ROOT))
    import run_backup_snapshot_ro as identity
    camera, card, pmhome = identity.report_identity(PROBE_REPORT)
    identity.ensure_camera_volumes_unmounted(camera, card, pmhome)


def _usb_backend():
    sys.path.insert(0, str(ROOT))
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    chosen = ((PROBE_REPORT or {}).get("dependencies") or {}).get("libusb_library")
    if not chosen or not Path(chosen).is_file():
        chosen = next((candidate for candidate in
                       ("/opt/homebrew/lib/libusb-1.0.dylib",
                        "/usr/local/lib/libusb-1.0.dylib")
                       if Path(candidate).is_file()), None)
    if chosen is None:
        try:
            import libusb_package
            packaged = libusb_package.get_library_path()
            if packaged is not None and Path(packaged).is_file():
                chosen = str(packaged)
        except ImportError:
            pass
    if chosen is None:
        raise base.ProbeError("libusb-1.0.dylib unavailable")
    explicit = usb.backend.libusb1.get_backend(find_library=lambda _: str(chosen))
    if explicit is None:
        raise base.ProbeError("libusb backend unavailable")
    return usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice, SonySenserCamera, explicit


def run_one_window(capture_id, index, previous_sha, usb_parts):
    _prepare_host_volumes()
    core, util, auth, senser, camera, explicit = usb_parts
    backend = WindowBackend(
        core, util, auth, senser, camera, version.MSC_PID, version.PRODUCT,
        budget=WindowBudget(), usb_backend=explicit,
        logger=version.safe_logger(), capture_id=capture_id,
        window_index=index, previous_manifest_sha256=previous_sha)
    code, lifecycle = base.run_probe(backend)
    report = producer.summarize(backend, lifecycle["normal_mode_and_driver_verified"])
    start, count = protocol.window_shape(PROFILE, index)
    if (code != 0 or not report["proof_verified"]
            or not report["normal_mode_and_driver_verified"]
            or not backend.collection_verified
            or sorted(backend.validated) != list(range(start, start + count))):
        raise base.ProbeError("window or normal MSC recovery not verified")
    protocol.verify_window(PROFILE,
                           [backend.validated[i] for i in range(start, start + count)],
                           backend.manifest_fields)
    return backend


def run_capture(capture_id, *, resume=False, progress=None):
    configure_existing_transport()
    producer.fixed_elf()
    protocol.capture_bytes(capture_id)
    part = BACKUP_DIR / f"{PROFILE.source}-{capture_id}-{PROFILE.bytes}.part"
    receipt_path = BACKUP_DIR / f"{PROFILE.source}-{capture_id}-manifest.json"
    if resume:
        owner = _private_dir(8 * 1024 * 1024)
        fd, receipt = _load_partial(part, receipt_path, owner, capture_id)
    else:
        owner = _private_dir(PROFILE.bytes)
        if part.exists() or receipt_path.exists():
            raise base.ProbeError("capture ID already exists; never overwrite")
        receipt = {"format": "codex-owner-block-image-v1", "camera": "ILCE-7CM2",
                   "firmware": "2.01", "source": PROFILE.source,
                   "major": 252, "minor": PROFILE.minor,
                   "partition_bytes": PROFILE.bytes, "elf_sha256": ELF_SHA256,
                   "capture_id": capture_id, "atomic_snapshot": False,
                   "windows": [], "complete": False}
        fd = _create_owned(part, owner, size=PROFILE.bytes)
    try:
        if not resume:
            _write_manifest(receipt_path, owner, receipt)
        usb_parts = _usb_backend()
        for index in range(len(receipt["windows"]), PROFILE.windows):
            previous = (receipt["windows"][-1]["manifest_sha256"] if index else None)
            backend = run_one_window(capture_id, index, previous, usb_parts)
            _store_window(fd, owner, receipt_path, receipt, backend)
            if progress is not None:
                progress({"event": "owner_window_saved", "source": PROFILE.source,
                          "capture_id": capture_id, "completed": len(receipt["windows"]),
                          "total": PROFILE.windows})
        sha = hashlib.sha256()
        for offset in range(0, PROFILE.bytes, 1024 * 1024):
            data = os.pread(fd, min(1024 * 1024, PROFILE.bytes - offset), offset)
            if not data:
                raise base.ProbeError("short final image readback")
            sha.update(data)
        final = BACKUP_DIR / f"{PROFILE.source}-{capture_id}-{PROFILE.bytes}-{sha.hexdigest()}.img"
        os.link(part, final, follow_symlinks=False)
        os.unlink(part)
        receipt["complete"] = True
        receipt["image_sha256"] = sha.hexdigest()
        receipt["image_basename"] = final.name
        _write_manifest(receipt_path, owner, receipt)
        return receipt
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="cnflasha1")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--capture-id")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    select_target(args.source)
    configure_existing_transport()
    producer.fixed_elf()
    if not args.execute:
        print(json.dumps({"result": "offline_plan", "camera_access": False,
                          "source": PROFILE.source, "bytes": PROFILE.bytes,
                          "windows": PROFILE.windows, "elf_sha256": ELF_SHA256,
                          "live_reviewed": LIVE_EXECUTION_REVIEWED}))
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("fixed-node live export remains held for independent review")
    if os.geteuid() != 0:
        parser.error("sudo -n root required")
    if args.resume and not args.capture_id:
        parser.error("--resume requires the existing capture ID")
    capture_id = args.capture_id or secrets.token_hex(16)
    print(json.dumps({"event": "owner_capture_start", "source": PROFILE.source,
                      "capture_id": capture_id, "resuming": args.resume}), flush=True)
    result = run_capture(capture_id, resume=args.resume,
                         progress=lambda item: print(json.dumps(item), flush=True))
    print(json.dumps({"result": "observed", "source": PROFILE.source,
                      "capture_id": capture_id, "image_sha256": result["image_sha256"],
                      "windows": len(result["windows"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
