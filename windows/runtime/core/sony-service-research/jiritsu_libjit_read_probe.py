#!/usr/bin/env python3
"""HELD read-only probe for the fixed Jiritsu libJit.so file on ILCE-7CM2 1.02.

This file is deliberately not executable against hardware yet. The offline
analysis and independent review must establish the full high-capacity response
and cleanup contract before LIVE_EXECUTION_REVIEWED may be changed.
"""

import argparse
import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

import service_probe as base
from jiritsu_version_probe import safe_logger


LIVE_EXECUTION_REVIEWED = False
MSC_PID = 0x0E8A
SERVICE_PID = 0x0336
PRODUCT = "ILCE-7CM2"
HEADER = struct.Struct("<IHHBBBB")
PRODUCT_DATA = b"\0\0\x1f\0\0"
GET_FILE_DATA = b"\x01\x10\x08\x00\x00\x02\x00"
PRODUCT_REQUEST = HEADER.pack(len(PRODUCT_DATA), 0x10, 1, 0, 0, 0, 0) + PRODUCT_DATA
GET_FILE_REQUEST = HEADER.pack(len(GET_FILE_DATA), 0x40, 2, 0, 0, 0, 0) + GET_FILE_DATA
PARTITION_BYTES = 26_214_400
BODY_LIMIT = PARTITION_BYTES + 4
WIRE_LIMIT = BODY_LIMIT + 1_048_576


class ReadBudget(base.Budget):
    def __init__(self):
        super().__init__(total=210.0, reserve=45.0)
        self.work_calls = 0
        self.recovery_calls = 0

    def timeout_ms(self, requested=1000):
        self.check()
        self.calls += 1
        if self.recovering:
            self.recovery_calls += 1
            if self.recovery_calls > 192:
                raise base.ProbeError("recovery USB transfer-count limit reached")
        else:
            self.work_calls += 1
            if self.work_calls > 2600:
                raise base.ProbeError("work USB transfer-count limit reached")
        return max(1, min(requested or 1000, 1000,
                          int(self.remaining() * 1000)))

    def received(self, size):
        self.rx_bytes += size
        if self.rx_bytes > WIRE_LIMIT:
            raise base.ProbeError("response-byte limit reached")


class BoundedSink:
    def __init__(self, path):
        self.path = path
        self.stream = path.open("xb")
        self.size = 0

    def write(self, data):
        if self.size + len(data) > BODY_LIMIT:
            raise base.ProbeError("file response exceeds hidden partition")
        written = self.stream.write(data)
        if written != len(data):
            raise base.ProbeError("short host output write")
        self.size += len(data)
        return written

    def close(self):
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()


class ReadSession(base.ManagedSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.product_verified = False
        self.file_request_sent = False

    def write(self, data, ep=0):
        if self.wire_phase == "auth":
            return super().write(data, ep)
        if (not self.claimed or self.closed or self.info["pid"] != SERVICE_PID
                or ep != 0):
            raise base.ProbeError("unverified service write")
        allowed = ((self.wire_phase == "product" and bytes(data) == PRODUCT_REQUEST
                    and not self.product_request_sent)
                   or (self.wire_phase == "file" and bytes(data) == GET_FILE_REQUEST
                       and self.product_verified and not self.file_request_sent))
        if not allowed:
            raise base.ProbeError("request not allowlisted")
        written = self.dev.write(self.ep_out[0], data,
                                 timeout=self.backend.budget.timeout_ms())
        if written != len(data):
            raise base.ProbeError("short USB write")
        if self.wire_phase == "product":
            self.product_request_sent = True
        else:
            self.file_request_sent = True

    def read(self, length, ep=0, timeout=None):
        if self.wire_phase == "auth":
            return super().read(length, ep, timeout)
        if (not self.claimed or self.closed or self.info["pid"] != SERVICE_PID
                or self.wire_phase not in ("product", "file") or ep != 0
                or type(length) is not int or not 0 < length <= 32768):
            raise base.ProbeError("read outside approved protocol phase")
        raw = bytes(self.dev.read(self.ep_in[0], length,
                                  timeout=self.backend.budget.timeout_ms(timeout)))
        self.backend.budget.received(len(raw))
        if not raw:
            raise base.ProbeError("empty USB response")
        return raw

    def product_info(self):
        dev = self.backend.senser_class(self)
        self.wire_phase = "product"
        try:
            product = self.backend.camera_class(dev).readHasp()
        finally:
            self.wire_phase = None
        if len(product) != 88:
            raise base.ProbeError("unexpected product-info size")
        self.product_verified = self.backend.product_verified = True
        self.backend.log("product_info_received", bytes=len(product))
        del product
        target = self.backend.output_dir
        target.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="libjit-read-", suffix=".part", dir=target)
        os.close(fd)
        temp = Path(temp_name)
        temp.unlink()
        self.backend.temp_path = temp
        sink = BoundedSink(temp)
        try:
            self.wire_phase = "file"
            try:
                outer_status, _ = dev.sendSenserPacket(0x40, GET_FILE_DATA, sink)
            finally:
                self.wire_phase = None
        except BaseException:
            try:
                sink.close()
            except OSError:
                pass
            raise
        sink.close()
        self.backend.outer_status = outer_status
        self.backend.body_length = sink.size
        self.backend.query_observed = True
        self.backend.log("libjit_read_response", outer_status=outer_status,
                         body_length=sink.size)
        return 88


class ReadBackend(base.UsbBackend):
    def __init__(self, *args, output_dir, **kwargs):
        super().__init__(*args, **kwargs)
        if self.expected_pid != MSC_PID or self.expected_product != PRODUCT:
            raise base.ProbeError("wrong target")
        self.output_dir = output_dir
        self.temp_path = None
        self.product_verified = False
        self.query_observed = False
        self.outer_status = None
        self.body_length = None

    def check_target(self, info, initial=None, service=False):
        super().check_target(info, initial, service)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != SERVICE_PID:
            raise base.ProbeError("unexpected service PID")

    def open(self, info):
        self.require_known_pid(info)
        session = ReadSession(self, info)
        self.sessions.append(session)
        return session.open()


def inspect_readback(path, outer_status, restored):
    result = {"outer_status": outer_status, "restored": restored}
    if path is None or not path.is_file():
        result["file_state"] = "no_response_file"
        return result
    with path.open("rb") as stream:
        prefix = stream.read(24)
    size = path.stat().st_size
    result["body_length"] = size
    if (outer_status == 0 and restored and size == 4
            and prefix == struct.pack("<I", 0x10000006)):
        result["file_state"] = "absent"
    elif (outer_status == 0 and restored and 28 <= size <= BODY_LIMIT
          and prefix[:4] == b"\x00\x00\x00\x00"
          and prefix[4:8] == b"\x7fELF" and prefix[8] == 2
          and prefix[9] == 1 and prefix[22:24] == struct.pack("<H", 183)):
        result["file_state"] = "aarch64_elf_read"
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            stream.read(4)
            for block in iter(lambda: stream.read(1 << 20), b""):
                digest.update(block)
        result["libjit_sha256"] = digest.hexdigest()
        result["libjit_bytes"] = size - 4
    else:
        result["file_state"] = "unverified_response"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--prior-service-probe-verified", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--photo-card-absent", action="store_true")
    parser.add_argument("--msc-pid", type=lambda value: int(value, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  target={"model": PRODUCT, "msc_pid": "0e8a"},
                  request="JIRITSU_GET_FILE selector0 index2 mode0",
                  live_reviewed=LIVE_EXECUTION_REVIEWED)
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("live high-capacity read remains held for review")
    if (not args.prior_service_probe_verified or not args.msc_volumes_unmounted
            or not args.photo_card_absent or args.msc_pid != MSC_PID
            or args.output_dir is None):
        parser.error("camera-only MSC and card-absent preflight required")
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
            parser.error("configured libusb backend unavailable")
    backend = ReadBackend(usb.core, usb.util, SonySenserAuthDevice,
                          SonySenserDevice, SonySenserCamera, MSC_PID, PRODUCT,
                          budget=ReadBudget(), usb_backend=explicit_backend,
                          output_dir=args.output_dir, logger=safe_logger())
    code, summary = base.run_probe(backend)
    finding = inspect_readback(backend.temp_path, backend.outer_status,
                               summary["normal_mode_and_driver_verified"])
    finding.update(product_verified=backend.product_verified,
                   query_observed=backend.query_observed,
                   normal_mode_and_driver_verified=summary["normal_mode_and_driver_verified"])
    if finding["file_state"] == "aarch64_elf_read":
        final = args.output_dir / "ILCE-7CM2-1.02-installed-libJit.so"
        if final.exists():
            raise base.ProbeError("verified output path already exists")
        with backend.temp_path.open("rb") as source, final.open("xb") as dest:
            source.read(4)
            for block in iter(lambda: source.read(1 << 20), b""):
                dest.write(block)
            dest.flush()
            os.fsync(dest.fileno())
        finding["saved_copy"] = str(final)
    if backend.temp_path and backend.temp_path.exists():
        backend.temp_path.unlink()
    base.emit("libjit_read_summary", **finding)
    return 0 if code == 0 and finding["file_state"] in ("absent", "aarch64_elf_read") else 1


if __name__ == "__main__":
    raise SystemExit(main())
