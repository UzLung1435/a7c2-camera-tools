#!/usr/bin/env python3
"""Fixed-target, opt-in JIRITSU_GET_VERSION capability observation.

The only command added to the previously verified service-product lifecycle is
AdjustControl(0x1001, 0x000d) with the exact four-byte payload 01 10 0d 00.
There is no user-supplied command, file path, address, terminal operation,
firmware update, or camera setting write. Start/authentication and Stop still
transmit protocol bytes and are not passive operations.

The 2.01 firmware's handler reads /tmp/jiritsu/ver.txt, but the attached body is
1.02. Version-specific behavior and diagnostic-log side effects are unknown.
The probe observes only the outer status and payload length, plus a recognized
four-byte error category. It never prints, hashes, or saves HASP or version data.

Without --execute it imports no USB package and never enumerates hardware.
Execution requires a prior successful service-product/restoration observation
and camera-only MSC volume unmount. The shared service_probe lifecycle imposes
45 seconds total with 17 seconds reserved for recovery. Each command response
payload is limited to 512 bytes before the PMCA implementation reads it.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

import service_probe as base


MSC_PID = 0x0E8A
SERVICE_PID = 0x0336
PRODUCT = "ILCE-7CM2"
HEADER = struct.Struct("<IHHBBBB")
MAX_PAYLOAD = 512
PRODUCT_REQUEST = HEADER.pack(5, 0x10, 1, 0, 0, 0, 0) + b"\0\0\x1f\0\0"
VERSION_REQUEST = HEADER.pack(4, 0x40, 2, 0, 0, 0, 0) + b"\x01\x10\x0d\x00"

# These exact little-endian result words are shown in the *2.01* version
# handler. They classify an observed four-byte body; they make no assertion
# that 1.02 uses the same internal implementation.
KNOWN_FOUR_BYTE_ERRORS = {
    0x10000006: "file_absent",
    0x10000008: "open_failed",
    0x1000000A: "read_failed",
    0x1000000F: "response_too_large",
    0x1000001A: "parse_failed",
}
ERROR_CODES = frozenset((
    "wrong_probe_target", "unverified_service_pid", "wrong_protocol_phase",
    "request_not_allowlisted", "response_pending", "short_usb_write",
    "read_endpoint_or_length", "empty_response", "oversized_response",
    "short_response_header", "sequence_mismatch", "payload_over_limit",
    "payload_length_mismatch", "product_status_rejected", "state_not_complete",
    "usb_transport_error", "inherited_probe_constraint", "interrupted",
    "dependency_error",
))


class JiritsuProbeError(base.ProbeError):
    def __init__(self, code):
        if code not in ERROR_CODES:
            raise ValueError("unknown diagnostic code")
        self.error_code = code
        super().__init__(code)


def failure_code(exc):
    code = getattr(exc, "error_code", None)
    if code in ERROR_CODES:
        return code
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        return "interrupted"
    if isinstance(exc, base.ProbeError):
        return "inherited_probe_constraint"
    if isinstance(exc, OSError) or getattr(exc, "backend_error_code", None) is not None:
        return "usb_transport_error"
    return "dependency_error"


def safe_logger(sink=base.emit):
    """Filter inherited logs; in particular discard hashes and exception text."""
    numeric = frozenset(("bytes", "body_length", "outer_status", "seconds_left",
                         "elapsed_seconds", "usb_transfer_calls", "response_bytes",
                         "product_bytes", "errno", "backend_error_code"))
    boolean = frozenset(("gone", "originally_active", "active", "initially_active",
                         "product_info_ok", "product_verified", "query_observed",
                         "mode_change_attempted", "normal_mode_and_driver_verified",
                         "sequence_validated"))

    def log(event, **fields):
        result = {}
        for key, value in fields.items():
            if key in numeric and (value is None or type(value) in (int, float)):
                result[key] = value
            elif key in boolean and (value is None or type(value) is bool):
                result[key] = value
            elif key == "identity" and isinstance(value, dict):
                result[key] = {k: value[k] for k in ("vid", "pid", "bus", "ports", "address")
                               if k in value}
            elif key == "known_four_byte_error" and value in KNOWN_FOUR_BYTE_ERRORS.values():
                result[key] = value
            elif key == "error_code" and (value is None or value in ERROR_CODES):
                result[key] = value
            elif key == "type" and isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", value):
                result[key] = value
            elif key in ("failure", "cleanup_errors"):
                result[key + "_present"] = bool(value)
        if "message" in fields and "error_code" not in result:
            message = fields["message"]
            result["error_code"] = (message if message in ERROR_CODES else
                                    "usb_transport_error" if fields.get("errno") is not None or
                                    fields.get("backend_error_code") is not None else
                                    "inherited_probe_constraint" if fields.get("type") == "ProbeError" else
                                    "dependency_error")
        sink(event, **result)
    return log


class JiritsuSession(base.ManagedSession):
    query_request = VERSION_REQUEST
    query_sequence = 2

    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.expected_sequence = 1
        self.response_pending = False
        self.header_pending = False
        self.declared_size = None
        self.command_status = None
        self.command_bytes = 0
        self.product_verified = False

    def write(self, data, ep=0):
        if self.wire_phase == "auth":
            return super().write(data, ep)
        if (self.info["pid"] != SERVICE_PID or self.wire_phase not in ("product", "jiritsu")
                or not self.claimed or self.closed):
            raise JiritsuProbeError("wrong_protocol_phase")
        required = PRODUCT_REQUEST if self.wire_phase == "product" else self.query_request
        if (ep != 0 or bytes(data) != required or
                self.expected_sequence != (1 if self.wire_phase == "product"
                                            else self.query_sequence) or
                (self.wire_phase == "jiritsu" and not self.product_verified)):
            raise JiritsuProbeError("request_not_allowlisted")
        if self.response_pending:
            raise JiritsuProbeError("response_pending")
        sent = self.dev.write(self.ep_out[0], required,
                              timeout=self.backend.budget.timeout_ms())
        if sent != len(required):
            raise JiritsuProbeError("short_usb_write")
        self.response_pending = self.header_pending = True
        self.declared_size = self.command_status = None
        self.command_bytes = 0
        self.expected_sequence += 1

    def read(self, length, ep=0, timeout=None):
        if self.wire_phase == "auth":
            return super().read(length, ep, timeout)
        if (self.wire_phase not in ("product", "jiritsu") or not self.response_pending
                or self.info["pid"] != SERVICE_PID or not self.claimed or self.closed):
            raise JiritsuProbeError("wrong_protocol_phase")
        if (ep != 0 or type(length) is not int or not 0 < length <= MAX_PAYLOAD
                or self.command_bytes + length > HEADER.size + MAX_PAYLOAD):
            raise JiritsuProbeError("read_endpoint_or_length")
        if self.header_pending and length != HEADER.size:
            raise JiritsuProbeError("read_endpoint_or_length")
        if not self.header_pending and length > (self.declared_size or 0) - self.command_bytes + HEADER.size:
            raise JiritsuProbeError("read_endpoint_or_length")
        raw = bytes(self.dev.read(self.ep_in[0], length,
                                  timeout=self.backend.budget.timeout_ms(timeout)))
        self.backend.budget.received(len(raw))
        self.command_bytes += len(raw)
        if not raw:
            raise JiritsuProbeError("empty_response")
        if len(raw) > length:
            raise JiritsuProbeError("oversized_response")
        if self.header_pending:
            if len(raw) != HEADER.size:
                raise JiritsuProbeError("short_response_header")
            size, _function, sequence, _version, _micon, _offset, status = HEADER.unpack(raw)
            if sequence != self.expected_sequence - 1:
                raise JiritsuProbeError("sequence_mismatch")
            if size > MAX_PAYLOAD:
                raise JiritsuProbeError("payload_over_limit")
            if self.wire_phase == "product" and status != 1:
                raise JiritsuProbeError("product_status_rejected")
            self.declared_size = size
            self.command_status = status
            self.header_pending = False
        return raw

    def finish(self, dev, data):
        if (not self.response_pending or self.header_pending or self.declared_size is None
                or dev._sequence != self.expected_sequence
                or len(data) != self.declared_size
                or self.command_bytes != HEADER.size + self.declared_size):
            raise JiritsuProbeError("payload_length_mismatch")
        self.response_pending = False
        return self.command_status

    def product_info(self):
        if self.info["pid"] != SERVICE_PID:
            raise JiritsuProbeError("unverified_service_pid")
        dev = self.backend.senser_class(self)
        camera = self.backend.camera_class(dev)
        self.wire_phase = "product"
        try:
            product = camera.readHasp()
            self.finish(dev, product)
            product_bytes = len(product)
            del product
            self.product_verified = self.backend.product_verified = True
            self.backend.log("product_info_received", bytes=product_bytes)
            self.wire_phase = "jiritsu"
            self.backend.budget.check()
            status, body = dev.sendSenserPacket(0x40, self.query_request[HEADER.size:])
            observed_status = self.finish(dev, body)
            if status != observed_status:
                raise JiritsuProbeError("state_not_complete")
            self.backend.outer_status = status
            self.backend.body_length = len(body)
            if len(body) == 4:
                code = struct.unpack("<I", body)[0]
                self.backend.known_four_byte_error = KNOWN_FOUR_BYTE_ERRORS.get(code)
            self.backend.query_observed = True
            self.backend.log("jiritsu_version_response", outer_status=status,
                             body_length=len(body), sequence_validated=True,
                             known_four_byte_error=self.backend.known_four_byte_error)
            del body
            return product_bytes
        finally:
            self.wire_phase = None


class JiritsuBackend(base.UsbBackend):
    def __init__(self, *args, logger=base.emit, **kwargs):
        super().__init__(*args, logger=safe_logger(logger), **kwargs)
        if self.expected_pid != MSC_PID or self.expected_product != PRODUCT:
            raise JiritsuProbeError("wrong_probe_target")
        self.product_verified = False
        self.query_observed = False
        self.outer_status = None
        self.body_length = None
        self.known_four_byte_error = None

    def check_target(self, info, initial=None, service=False):
        super().check_target(info, initial, service)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != SERVICE_PID:
            raise JiritsuProbeError("unverified_service_pid")

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != SERVICE_PID:
            raise JiritsuProbeError("unverified_service_pid")
        session = JiritsuSession(self, info)
        self.sessions.append(session)
        return session.open()


def run_probe(backend):
    code, original = base.run_probe(backend)
    error = failure_code_from_fields(original.get("failure"))
    summary = {key: original[key] for key in (
        "normal_mode_and_driver_verified", "mode_change_attempted",
        "elapsed_seconds", "usb_transfer_calls", "response_bytes")}
    summary.update(product_verified=backend.product_verified,
                   query_observed=backend.query_observed,
                   outer_status=backend.outer_status,
                   body_length=backend.body_length,
                   known_four_byte_error=backend.known_four_byte_error,
                   error_code=error, cleanup_errors_present=bool(original.get("cleanup_errors")))
    backend.log("jiritsu_summary", **summary)
    if code == 0 and not backend.query_observed:
        code = 2
    return code, summary


def failure_code_from_fields(fields):
    if not fields:
        return None
    code = fields.get("message")
    if code in ERROR_CODES:
        return code
    if fields.get("errno") is not None or fields.get("backend_error_code") is not None:
        return "usb_transport_error"
    if fields.get("type") == "ProbeError":
        return "inherited_probe_constraint"
    if fields.get("type") in ("KeyboardInterrupt", "SystemExit"):
        return "interrupted"
    return "dependency_error"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--prior-service-probe-verified", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--msc-pid", type=lambda value: int(value, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  target={"product": PRODUCT, "msc_pid": "0e8a", "service_pid": "0336"},
                  command="JIRITSU_GET_VERSION",
                  limits={"response_payload_bytes": MAX_PAYLOAD, "total_seconds": 45,
                          "recovery_reserved_seconds": 17})
        return 0
    if not args.prior_service_probe_verified or not args.msc_volumes_unmounted:
        parser.error("verified prior service/restoration and unmounted camera volumes required")
    if args.msc_pid != MSC_PID:
        parser.error("fixed target requires observed MSC PID 0e8a")
    if args.pmca_path:
        sys.path.insert(0, str(args.pmca_path))
    import usb.core
    import usb.util
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    explicit_backend = None
    if args.libusb:
        import usb.backend.libusb1
        explicit_backend = usb.backend.libusb1.get_backend(find_library=lambda _: str(args.libusb))
        if explicit_backend is None:
            raise JiritsuProbeError("dependency_error")
    backend = JiritsuBackend(usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
                             SonySenserCamera, MSC_PID, PRODUCT, usb_backend=explicit_backend)
    return run_probe(backend)[0]


if __name__ == "__main__":
    sys.exit(main())
