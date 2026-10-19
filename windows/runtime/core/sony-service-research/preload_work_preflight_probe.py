#!/usr/bin/env python3
"""Fixed read-only Work mount/preload preflight on ILCE-7CM2 1.02.

Reads only /tmp/hosts, /etc/hosts, /tmp/ld.so.preload, and
/etc/ld.so.preload through the already reviewed Jiritsu GET_FILE2 path.
Every GET_FILE2 selector is 0/index FF. The hidden diagnostic VFAT is
RW-mounted by Sony's handler, but no file-write/delete opcode is sent.
"""

import argparse
import hashlib
import io
import struct
import sys
from pathlib import Path

import service_probe as base
import jiritsu_version_probe as version
import jiritsu_ram_stage_probe as stage
from jiritsu_libjit_read_probe import ReadBudget


LIVE_EXECUTION_REVIEWED = True
PREFIX = b"/tmp/jiritsu/../.."
PATHS = (
    ("tmp_hosts", PREFIX + b"/tmp/hosts"),
    ("etc_hosts", PREFIX + b"/etc/hosts"),
    ("tmp_preload", PREFIX + b"/tmp/ld.so.preload"),
    ("etc_preload", PREFIX + b"/etc/ld.so.preload"),
)
READ_DATA = stage.READ_DATA
ABSENT_WORD = struct.pack("<I", 0x10000006)
WORK_BYTES = 12_582_912


class LimitedBytesIO(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > WORK_BYTES + 4:
            raise base.ProbeError("Work file response exceeds partition")
        return super().write(data)


class PreflightSession(stage.StageSession):
    streaming = False

    def _accept_stream_chunk(self, requested, raw):
        if self.stream_header_expected:
            if requested != version.HEADER.size or len(raw) != version.HEADER.size:
                raise base.ProbeError("incomplete Work response header")
            size, function, sequence, _, _, _, status = version.HEADER.unpack(raw)
            if (function not in (0x40, 0x4040) or sequence != self.query_sequence
                    or status != 0 or not 0 < size <= WORK_BYTES + 4):
                raise base.ProbeError("invalid Work response header")
            if self.stream_declared is None:
                self.stream_declared = size
            elif size != self.stream_declared - self.stream_body_received:
                raise base.ProbeError("inconsistent Work response length")
            self.stream_frame_remaining = min(size, 0x100000)
            self.stream_header_expected = False
            return
        if self.stream_padding_expected:
            # Sony's service endpoint may satisfy the mandatory padding read
            # with a USB zero-length packet, or with 512 explicit zero bytes.
            # Neither representation belongs to the file body.
            if (requested != 0x200 or len(raw) not in (0, 0x200)
                    or (len(raw) == 0x200 and raw != b"\0" * 0x200)):
                raise base.ProbeError("invalid Work USB padding")
            self.stream_padding_expected = False
            if self.stream_frame_remaining == 0:
                self.stream_header_expected = True
            return
        if not 0 < requested <= min(self.stream_frame_remaining, 0x8000):
            raise base.ProbeError("Work body read exceeds response length")
        if self.stream_chunk_remaining == 0:
            self.stream_chunk_remaining = requested
            self.stream_chunk_size = requested
        elif requested != self.stream_chunk_remaining:
            raise base.ProbeError("unexpected Work body chunk length")
        if len(raw) > self.stream_chunk_remaining:
            raise base.ProbeError("oversized Work body chunk")
        self.stream_chunk_remaining -= len(raw)
        self.stream_frame_remaining -= len(raw)
        self.stream_body_received += len(raw)
        if self.stream_chunk_remaining == 0:
            self.stream_padding_expected = self.stream_chunk_size % 0x200 == 0
            if self.stream_frame_remaining == 0 and not self.stream_padding_expected:
                self.stream_header_expected = True

    def read(self, length, ep=0, timeout=None):
        if not self.streaming:
            return super().read(length, ep, timeout)
        if (self.wire_phase != "jiritsu" or not self.claimed or self.closed
                or not self.response_pending or self.info["pid"] != version.SERVICE_PID or ep != 0
                or type(length) is not int or not 0 < length <= 32768):
            raise base.ProbeError("read outside fixed Work stream")
        raw = bytes(self.dev.read(self.ep_in[0], length,
                                  timeout=self.backend.budget.timeout_ms(timeout)))
        self.backend.budget.received(len(raw))
        if not raw and not (self.stream_padding_expected and length == 0x200):
            raise base.ProbeError("empty Work read response")
        self._accept_stream_chunk(length, raw)
        return raw

    def _read_fixed(self, dev, label, path):
        path_data = b"\x01\x10\x0f\x00\x00" + path
        self._fixed_query(dev, path_data, "set_" + label, 4)
        self.query_sequence = dev._sequence
        self.query_request = version.HEADER.pack(
            len(READ_DATA), 0x40, self.query_sequence, 0, 0, 0, 0) + READ_DATA
        self.wire_phase = "jiritsu"
        self.streaming = True
        self.stream_header_expected = True
        self.stream_declared = None
        self.stream_frame_remaining = 0
        self.stream_body_received = 0
        self.stream_chunk_remaining = 0
        self.stream_chunk_size = 0
        self.stream_padding_expected = False
        sink = LimitedBytesIO()
        try:
            status, _ = dev.sendSenserPacket(0x40, READ_DATA, sink)
        finally:
            self.streaming = False
            self.wire_phase = None
        body = sink.getvalue()
        if (not self.response_pending or not self.stream_header_expected
                or self.stream_padding_expected or self.stream_chunk_remaining
                or self.stream_body_received != self.stream_declared
                or len(body) != self.stream_declared):
            raise version.JiritsuProbeError("state_not_complete")
        self.response_pending = False
        self.header_pending = False
        if dev._sequence != self.expected_sequence or status != 0:
            raise version.JiritsuProbeError("state_not_complete")
        if body == ABSENT_WORD:
            state, data = "not_found_or_unreadable", None
        elif 4 <= len(body) <= WORK_BYTES + 4 and body[:4] == b"\0" * 4:
            state, data = "present", body[4:]
        else:
            raise version.JiritsuProbeError("state_not_complete")
        self.backend.files[label] = (state, data)
        self.backend.log("preload_preflight_read", name=label, state=state,
                         body_length=len(body), outer_status=status)

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
        del product
        self.product_verified = self.backend.product_verified = True
        self.backend.log("product_info_received", bytes=88)
        for label, path in PATHS:
            self._read_fixed(dev, label, path)
        self.backend.query_observed = True
        return 88


class PreflightBackend(stage.StageBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.files = {}

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = PreflightSession(self, info)
        self.sessions.append(session)
        return session.open()


def summarize(backend, restored):
    files = backend.files
    tmp_hosts = files.get("tmp_hosts")
    etc_hosts = files.get("etc_hosts")
    alias_confirmed = bool(tmp_hosts and etc_hosts and tmp_hosts[0] == "present"
                           and etc_hosts[0] == "present"
                           and len(tmp_hosts[1]) > 0
                           and tmp_hosts[1] == etc_hosts[1])
    result = {"product_verified": backend.product_verified,
              "query_observed": backend.query_observed,
              "normal_mode_and_driver_verified": restored,
              "hosts_alias_supported": alias_confirmed}
    for label, _ in PATHS:
        state, data = files.get(label, ("not_observed", None))
        result[label + "_state"] = state
        if state == "present":
            result[label + "_size"] = len(data)
            result[label + "_sha256"] = hashlib.sha256(data).hexdigest()
    result["preload_baseline_eligible"] = (
        alias_confirmed and files.get("tmp_preload", (None,))[0] == "not_found_or_unreadable"
        and files.get("etc_preload", (None,))[0] == "not_found_or_unreadable")
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
    args = parser.parse_args(argv)
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  request="four fixed Work files, read only",
                  live_reviewed=LIVE_EXECUTION_REVIEWED)
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("Work/preload preflight remains held for review")
    if (not args.prior_service_probe_verified or not args.msc_volumes_unmounted
            or not args.photo_card_absent or args.msc_pid != version.MSC_PID):
        parser.error("card-absent exact A7C II MSC preflight required")
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
    backend = PreflightBackend(usb.core, usb.util, SonySenserAuthDevice,
                               SonySenserDevice, SonySenserCamera,
                               version.MSC_PID, version.PRODUCT,
                               budget=ReadBudget(),
                               usb_backend=explicit_backend,
                               logger=version.safe_logger())
    code, summary = base.run_probe(backend)
    result = summarize(backend, summary["normal_mode_and_driver_verified"])
    base.emit("preload_work_summary", **result)
    return 0 if (code == 0 and result["query_observed"]
                 and result["normal_mode_and_driver_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
