#!/usr/bin/env python3
"""HELD fixed 19-byte RAM-staging round trip on A7C II 1.02.

The path contains dot segments and resolves to /tmp_wbshd on the reviewed
Linux mount layout. The command still RW-mounts internal diagnostic VFAT.
It does not upload or execute a shared library or change camera settings.
"""

import argparse
import struct
import sys
from pathlib import Path

import service_probe as base
import jiritsu_version_probe as version


LIVE_EXECUTION_REVIEWED = False
RAM_PATH = b"/tmp/jiritsu/../../tmp_wbshd/codex_probe_102.bin"
MARKER = b"CODEX-A7C2-RAM-102\n"
PATH_DATA = b"\x01\x10\x0f\x00\x00" + RAM_PATH
WRITE_DATA = b"\x01\x10\x10\x00\x00\xff\x00" + MARKER
READ_DATA = b"\x01\x10\x11\x00\x00\xff\x00"
assert (len(RAM_PATH), len(MARKER), len(PATH_DATA), len(WRITE_DATA),
        len(READ_DATA)) == (48, 19, 53, 26, 7)


class StageBudget(base.Budget):
    def __init__(self):
        super().__init__(total=120.0, reserve=35.0)
        self.work_calls = 0
        self.recovery_calls = 0

    def timeout_ms(self, requested=1000):
        self.check()
        self.calls += 1
        if self.recovering:
            self.recovery_calls += 1
            if self.recovery_calls > 192:
                raise base.ProbeError("recovery transfer limit")
        else:
            self.work_calls += 1
            if self.work_calls > 512:
                raise base.ProbeError("work transfer limit")
        return max(1, min(requested or 1000, 1000,
                          int(self.remaining() * 1000)))

    def received(self, size):
        self.rx_bytes += size
        if self.rx_bytes > 8192:
            raise base.ProbeError("response-byte limit")


class StageSession(version.JiritsuSession):
    def _fixed_query(self, dev, body, label, expected_size):
        self.query_sequence = dev._sequence
        self.query_request = version.HEADER.pack(
            len(body), 0x40, self.query_sequence, 0, 0, 0, 0) + body
        self.wire_phase = "jiritsu"
        try:
            status, response = dev.sendSenserPacket(0x40, body)
            observed = self.finish(dev, response)
        finally:
            self.wire_phase = None
        if (status != observed or status != 0 or len(response) != expected_size
                or response[:4] != b"\0\0\0\0"):
            raise version.JiritsuProbeError("state_not_complete")
        self.backend.log("ram_stage_step", step=label, body_length=len(response),
                         outer_status=status)
        return response

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
        self._fixed_query(dev, PATH_DATA, "set_ram_path", 4)
        self._fixed_query(dev, WRITE_DATA, "write_ram_marker", 4)
        self.backend.write_observed = True
        self._fixed_query(dev, PATH_DATA, "reset_ram_path", 4)
        response = self._fixed_query(dev, READ_DATA, "read_ram_marker", 4 + len(MARKER))
        self.backend.readback_match = response[4:] == MARKER
        self.backend.query_observed = True
        if not self.backend.readback_match:
            raise version.JiritsuProbeError("state_not_complete")
        return 88


class StageBackend(version.JiritsuBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.write_observed = False
        self.readback_match = False

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = StageSession(self, info)
        self.sessions.append(session)
        return session.open()


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
        base.emit("offline_plan", hardware_access=False, command="fixed RAM marker round trip",
                  marker_bytes=len(MARKER), live_reviewed=LIVE_EXECUTION_REVIEWED)
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("RAM staging remains held for independent review")
    if (not args.prior_service_probe_verified or not args.msc_volumes_unmounted
            or not args.photo_card_absent or args.msc_pid != version.MSC_PID):
        parser.error("fixed card-absent A7C II MSC preflight required")
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
    backend = StageBackend(usb.core, usb.util, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera, version.MSC_PID,
                           version.PRODUCT, budget=StageBudget(),
                           usb_backend=explicit_backend,
                           logger=version.safe_logger())
    code, summary = base.run_probe(backend)
    base.emit("ram_stage_summary", product_verified=backend.product_verified,
              write_observed=backend.write_observed,
              readback_match=backend.readback_match,
              normal_mode_and_driver_verified=summary["normal_mode_and_driver_verified"])
    return 0 if (code == 0 and backend.product_verified and backend.write_observed
                 and backend.readback_match and summary["normal_mode_and_driver_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
