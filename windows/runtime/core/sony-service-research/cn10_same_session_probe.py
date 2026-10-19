#!/usr/bin/env python3
"""HELD fixed Work10 window producer and same-service chunk collector.

Window 0 reads 8 MiB; window 1 reads 4 MiB. The Work volume is mounted RW by
the camera, so each window is a bounded time-separated capture, not an atomic
filesystem snapshot. This host only journals complete chunks after MSC and
driver restoration. The camera-side ELF opens cn252:138 O_RDONLY.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import zlib

import service_probe as base
import jiritsu_version_probe as version
import cn10_window_producer_probe as producer
import cn10_window_chunk_schema as schema
# This bundle uses only Work10Session/Work10Budget as a transport base.
# The legacy Work10 journal CLI is deliberately disabled.


LIVE_EXECUTION_REVIEWED = False
BACKUP_DIR = schema.BACKUP_DIR
CAPTURE = re.compile(r"^[0-9a-f]{32}$")
SHA = re.compile(r"^[0-9a-f]{64}$")


class Work10Budget(producer.ProducerBudget):
    def __init__(self, window_index):
        total = 600.0 if window_index == 0 else 300.0
        base.Budget.__init__(self, total=total, reserve=60.0)
        self.work_calls = 0
        self.recovery_calls = 0
        self.long_trigger = False
        self.bulk_read = False
        self.max_work_calls = 4500 if window_index == 0 else 2200
        self.max_response_bytes = (9 if window_index == 0 else 5) * 1024 * 1024

    def timeout_ms(self, requested=1000):
        self.check()
        self.calls += 1
        if self.recovering:
            self.recovery_calls += 1
            if self.recovery_calls > 192:
                raise base.ProbeError("recovery USB transfer-count limit reached")
            cap = 1000
        else:
            self.work_calls += 1
            if self.work_calls > self.max_work_calls:
                raise base.ProbeError("Work10 USB transfer-count limit reached")
            cap = 30000 if self.long_trigger else 5000 if self.bulk_read else 1000
        chosen = cap if self.long_trigger and not self.recovering else (requested or cap)
        return max(1, min(cap, chosen, int(self.remaining() * 1000)))

    def received(self, size):
        if type(size) is not int or size < 0:
            raise base.ProbeError("invalid Work10 response size")
        self.rx_bytes += size
        if self.rx_bytes > self.max_response_bytes:
            raise base.ProbeError("Work10 response-byte limit reached")


class Work10Session(producer.ProducerSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        start, count = producer.window_shape(backend.window_index)
        self.indices = tuple(range(start, start + count))
        self.chunk_paths = {
            index: schema.path_for_index(index, self.capture_id, self.window_index)
            for index in self.indices}
        self.chunk_path_bodies = frozenset(
            producer.PATH_PREFIX + path for path in self.chunk_paths.values())
        self.path_bodies = self.path_bodies | self.chunk_path_bodies
        self.allowed_bodies = self.allowed_bodies | self.chunk_path_bodies
        self.service_dev = None
        self.current_chunk_index = None

    def _fixed_query(self, dev, body, label, expected_size):
        self.service_dev = dev
        return super()._fixed_query(dev, body, label, expected_size)

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            if (len(raw) >= version.HEADER.size
                    and raw[version.HEADER.size:] in self.chunk_path_bodies
                    and not self.backend.proof_verified):
                raise version.JiritsuProbeError("request_not_allowlisted")
        return super().write(data, ep)

    def _accept_stream_chunk(self, requested, raw):
        if self.current_chunk_index is not None and self.stream_header_expected:
            if requested != version.HEADER.size or len(raw) != version.HEADER.size:
                raise base.ProbeError("incomplete Work10 chunk response header")
            declared = version.HEADER.unpack(raw)[0]
            self.backend.chunk_declared_bytes = declared
            if declared != schema.BODY_SIZE + 4:
                raise base.ProbeError("Work10 chunk response length mismatch")
        return super()._accept_stream_chunk(requested, raw)

    def read(self, length, ep=0, timeout=None):
        if not (self.streaming and self.current_chunk_index is not None):
            return super().read(length, ep, timeout)
        if (self.wire_phase != "jiritsu" or not self.claimed or self.closed
                or not self.response_pending or self.info["pid"] != version.SERVICE_PID
                or ep != 0 or type(length) is not int or not 0 < length <= 32768):
            raise base.ProbeError("read outside Work10 chunk stream")
        request = min(length, schema.MAX_USB_FRAGMENT)
        try:
            raw = bytes(self.dev.read(
                self.ep_in[0], request,
                timeout=self.backend.budget.timeout_ms(schema.DATA_TIMEOUT_MS)))
        except BaseException as exc:
            self.backend.failure_index = self.current_chunk_index
            self.backend.failure_type = type(exc).__name__
            self.backend.failure_phase = (
                "padding" if getattr(self, "stream_padding_expected", False)
                else "response_header" if getattr(self, "stream_header_expected", False)
                else "usb_bulk")
            raise
        self.backend.budget.received(len(raw))
        if self.stream_padding_expected and length == 0x200:
            self.backend.padding_returned_length = len(raw)
        if (len(raw) > request or
                (not raw and not (self.stream_padding_expected and length == 0x200))):
            raise base.ProbeError("invalid Work10 chunk USB response size")
        self._accept_stream_chunk(length, raw)
        return raw

    def _read_fixed(self, dev, label, path):
        if label == "previous_manifest" and self.window_index == 1:
            result = super()._read_fixed(dev, label, path)
            item = self.backend.files.get(label)
            if (not item or item[0] != "present"
                    or hashlib.sha256(item[1]).hexdigest() !=
                        self.backend.expected_previous_manifest_sha256):
                raise base.ProbeError("previous Work10 window manifest changed")
            return result
        if not label.startswith("work10_chunk_"):
            return super()._read_fixed(dev, label, path)
        index = int(label.removeprefix("work10_chunk_"), 16)
        if index not in self.chunk_paths or path != self.chunk_paths[index]:
            raise base.ProbeError("unlisted Work10 chunk read")
        self.current_chunk_index = index
        self.backend.budget.bulk_read = True
        try:
            return super()._read_fixed(dev, label, path)
        finally:
            self.backend.budget.bulk_read = False
            self.current_chunk_index = None

    def product_info(self):
        length = super().product_info()
        if not self.backend.proof_verified:
            return length
        if (not self.backend.cleanup_absence_verified or not self._wire_clean()
                or self.service_dev is None):
            self.backend.failure_phase = "post_debug_wire_or_work"
            return length
        for index in self.indices:
            label = f"work10_chunk_{index:02x}"
            try:
                self._read_fixed(self.service_dev, label, self.chunk_paths[index])
                item = self.backend.files.get(label)
                if not item or item[0] != "present":
                    raise base.ProbeError("Work10 chunk missing or unreadable")
                record = schema.parse_chunk(
                    item[1], index, self.backend.manifest_fields)
            except BaseException:
                self.backend.failure_index = index
                if self.backend.failure_phase is None:
                    self.backend.failure_phase = "data_or_header"
                raise
            self.backend.validated[index] = record
            self.backend.log("fixed_chunk_validated", index=index,
                             raw_bytes=producer.CHUNK_BYTES,
                             sha256=record["sha256"], crc32=record["crc32"])
        self.backend.collection_verified = len(self.backend.validated) == len(self.indices)
        return length


class Work10Backend(producer.ProducerBackend):
    def __init__(self, *args, capture_id, window_index,
                 expected_previous_manifest_sha256=None, **kwargs):
        super().__init__(*args, capture_id=capture_id,
                         window_index=window_index, **kwargs)
        if window_index == 1:
            if (not isinstance(expected_previous_manifest_sha256, str)
                    or not SHA.fullmatch(expected_previous_manifest_sha256)):
                raise base.ProbeError("previous Work10 manifest SHA required")
        elif expected_previous_manifest_sha256 is not None:
            raise base.ProbeError("unexpected previous Work10 manifest SHA")
        self.expected_previous_manifest_sha256 = expected_previous_manifest_sha256
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
        session = Work10Session(self, info)
        self.sessions.append(session)
        return session.open()


def private_window_crc(capture_id, window_index, manifest_sha256):
    raise base.ProbeError("legacy Work10 journal disabled in p1 bundle")
    start, count = producer.window_shape(window_index)
    if (not isinstance(capture_id, str) or not CAPTURE.fullmatch(capture_id)
            or not isinstance(manifest_sha256, str) or not SHA.fullmatch(manifest_sha256)):
        raise base.ProbeError("invalid private Work10 window identity")
    entries = {}
    for path in BACKUP_DIR.glob(f"cap{capture_id}-nflasha10-*.json"):
        item = journal.verify_chunk(path)
        if item.get("window_index") != window_index:
            continue
        if (item.get("capture_id") != capture_id
                or item.get("partition") != 10
                or item.get("partition_bytes") != producer.PARTITION_BYTES
                or item.get("raw_bytes") != producer.CHUNK_BYTES
                or item.get("selected_kernel_name") != "cnflasha10"
                or item.get("selected_major") != 252
                or item.get("selected_minor") != 138
                or item.get("window_manifest_sha256") != manifest_sha256
                or type(item.get("offset")) is not int
                or item["offset"] % producer.CHUNK_BYTES):
            raise base.ProbeError("private Work10 chunk provenance mismatch")
        index = item["offset"] // producer.CHUNK_BYTES
        if index in entries:
            raise base.ProbeError("duplicate private Work10 offset")
        entries[index] = item
    if set(entries) != set(range(start, start + count)):
        return None
    dirfd, owner = journal._open_private_dir(BACKUP_DIR)
    crc = 0
    try:
        for index in range(start, start + count):
            item = entries[index]
            compressed = journal._read_private_archive(dirfd, item["archive"], owner)
            raw = journal._decompress(compressed)
            if (len(raw) != producer.CHUNK_BYTES
                    or hashlib.sha256(raw).hexdigest() != item["raw_sha256"]
                    or zlib.crc32(raw) != item["camera_crc32"]):
                raise base.ProbeError("private Work10 chunk changed")
            crc = zlib.crc32(raw, crc)
    finally:
        os.close(dirfd)
    return crc


def main(argv=None):
    raise base.ProbeError("legacy Work10 command disabled in p1 bundle")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--capture-id")
    parser.add_argument("--window-index", type=int)
    parser.add_argument("--previous-manifest-sha256")
    parser.add_argument("--previous-window-crc32", type=int)
    parser.add_argument("--prior-inventory-verified", action="store_true")
    parser.add_argument("--prior-window-verified", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--photo-card-absent", action="store_true")
    parser.add_argument("--msc-pid", type=lambda value: int(value, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    args = parser.parse_args(argv)
    producer.fixed_elf()
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  action="fixed Work10 window same-service read",
                  fixed_elf_sha256=producer.ELF_SHA256,
                  live_reviewed=LIVE_EXECUTION_REVIEWED)
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("Work10 same-service read remains held")
    if (not args.prior_inventory_verified or not args.msc_volumes_unmounted
            or not args.photo_card_absent or args.msc_pid != version.MSC_PID
            or not isinstance(args.capture_id, str)
            or not CAPTURE.fullmatch(args.capture_id)
            or args.capture_id == "0" * 32
            or args.window_index not in (0, 1)
            or (args.window_index == 1 and not args.prior_window_verified)):
        parser.error("exact1.02 Work10 card-absent inventory/window preflight required")
    if args.window_index == 1:
        if (not isinstance(args.previous_manifest_sha256, str)
                or not SHA.fullmatch(args.previous_manifest_sha256)
                or type(args.previous_window_crc32) is not int
                or not 0 <= args.previous_window_crc32 <= 0xffffffff
                or private_window_crc(args.capture_id, 0,
                    args.previous_manifest_sha256) != args.previous_window_crc32):
            parser.error("previous Work10 private window incomplete")
    elif (args.previous_manifest_sha256 is not None
          or args.previous_window_crc32 is not None):
        parser.error("unexpected Work10 previous manifest")
    dirfd, _owner = journal._open_private_dir(BACKUP_DIR)
    try:
        _start, count = producer.window_shape(args.window_index)
        journal._reserve(dirfd, extra=2 * count * producer.CHUNK_BYTES + 1024 * 1024)
    finally:
        os.close(dirfd)
    if args.pmca_path:
        sys.path.insert(0, str(args.pmca_path))
    import usb.core
    import usb.util
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    explicit_backend = None
    if args.libusb:
        import usb.backend.libusb1
        explicit_backend = usb.backend.libusb1.get_backend(
            find_library=lambda _: str(args.libusb))
        if explicit_backend is None:
            parser.error("configured libusb unavailable")
    backend = Work10Backend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=Work10Budget(args.window_index), usb_backend=explicit_backend,
        logger=version.safe_logger(), capture_id=args.capture_id,
        window_index=args.window_index,
        expected_previous_manifest_sha256=args.previous_manifest_sha256)
    code, lifecycle = base.run_probe(backend)
    report = producer.summarize(backend,
                                lifecycle["normal_mode_and_driver_verified"])
    report.update(capture_id=args.capture_id,
                  requested_count=producer.window_shape(args.window_index)[1],
                  validated_count=len(backend.validated),
                  saved_count=0, saved_indices=[],
                  collection_verified=backend.collection_verified,
                  window_crc_observed=None, window_crc_verified=False,
                  usb_work_calls=backend.budget.work_calls,
                  response_bytes=backend.budget.rx_bytes,
                  failure_index=backend.failure_index,
                  failure_type=backend.failure_type,
                  failure_phase=backend.failure_phase,
                  chunk_declared_bytes=backend.chunk_declared_bytes,
                  padding_returned_length=backend.padding_returned_length)
    if (report["proof_verified"] and report["cleanup_absence_verified"]
            and report["manifest_verified"]
            and report["normal_mode_and_driver_verified"]):
        for index, record in sorted(backend.validated.items()):
            try:
                _archive, sidecar = journal.store_chunk(
                    BACKUP_DIR, partition=10, offset=record["offset"],
                    partition_bytes=producer.PARTITION_BYTES,
                    data=record["data"], camera_crc32=record["crc32"],
                    capture_id=args.capture_id,
                    selected_kernel_name="cnflasha10",
                    selected_major=252, selected_minor=138,
                    window_index=args.window_index,
                    window_manifest_sha256=report["manifest_sha256"])
                checked = journal.verify_chunk(sidecar)
                if (checked.get("raw_sha256") != record["sha256"]
                        or checked.get("offset") != index * producer.CHUNK_BYTES):
                    raise base.ProbeError("saved Work10 chunk mismatch")
                report["saved_indices"].append(index)
            except BaseException as exc:
                report["journal_failure_kind"] = type(exc).__name__
                break
        report["saved_count"] = len(report["saved_indices"])
        if report["saved_count"] == report["requested_count"]:
            try:
                crc = private_window_crc(args.capture_id, args.window_index,
                                         report["manifest_sha256"])
                report["window_crc_observed"] = crc
                report["window_crc_verified"] = crc == report["window_crc32"]
            except BaseException as exc:
                report["window_failure_kind"] = type(exc).__name__
    base.emit("cn10_same_session_summary", **report)
    return 0 if (code == 0 and report["proof_verified"]
                 and report["collection_verified"]
                 and report["normal_mode_and_driver_verified"]
                 and report["saved_count"] == report["requested_count"]
                 and report["window_crc_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
