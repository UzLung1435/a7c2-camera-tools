#!/usr/bin/env python3
"""Read only the existing hot-loader READY record and Work safety baseline.

The Sony service Start/auth/Stop lifecycle temporarily switches USB mode.
Within Jiritsu, this probe permits only GET_FILE2 path selectors and reads;
it sends no file write, delete, debug, setting, shutter, or capture command.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

import service_probe as base
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
from jiritsu_libjit_read_probe import ReadBudget
import im_hot_module_protocol_102 as wire

READY = preflight.PREFIX + wire.READY_PATH
PATHS = dict(preflight.PATHS)
PATHS["ready"] = READY
SELECTORS = frozenset(b"\x01\x10\x0f\x00\x00" + value
                      for value in PATHS.values())
ALLOWED = SELECTORS | {preflight.READ_DATA}


class ReadySession(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.selected = False
        self.active_label = None

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            body = raw[version.HEADER.size:]
            if (body not in ALLOWED or
                    (body == preflight.READ_DATA and not self.selected) or
                    (body in SELECTORS and self.active_label is None)):
                raise base.ProbeError("request outside read-only READY allowlist")
        return super().write(data, ep)

    def _fixed_query(self, dev, body, label, expected_size):
        if body in SELECTORS:
            self.selected = False
        result = super()._fixed_query(dev, body, label, expected_size)
        if body in SELECTORS:
            self.selected = True
        return result

    def _accept_stream_chunk(self, requested, raw):
        if self.stream_header_expected and self.active_label is not None:
            if requested != version.HEADER.size or len(raw) != version.HEADER.size:
                raise base.ProbeError("incomplete fixed read response header")
            declared = version.HEADER.unpack(raw)[0]
            cap = (wire.READY_BYTES + 4 if self.active_label == "ready" else
                   4096 if "hosts" in self.active_label else 512)
            if declared > cap:
                raise base.ProbeError("fixed read response exceeds cap")
        return super()._accept_stream_chunk(requested, raw)

    def _read_one(self, dev, label):
        self.active_label = label
        self.selected = False
        try:
            self._read_fixed(dev, label, PATHS[label])
        finally:
            self.active_label = None
            self.selected = False

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
        self.backend.log("product_info_received", bytes=88)
        for label, _ in preflight.PATHS:
            self._read_one(dev, label)
        files = self.backend.files
        hosts = (files["tmp_hosts"][0] == files["etc_hosts"][0] == "present"
                 and files["tmp_hosts"][1] == files["etc_hosts"][1]
                 and bool(files["tmp_hosts"][1]))
        preloads = all(files[x][0] == "not_found_or_unreadable"
                       for x in ("tmp_preload", "etc_preload"))
        self.backend.work_clean = bool(hosts and preloads)
        if not self.backend.work_clean:
            self.backend.stop_reason = "Work baseline changed"
            return 88
        self._read_one(dev, "ready")
        state, raw = files["ready"]
        self.backend.ready_state = state
        if state == "present":
            self.backend.ready_sha256 = hashlib.sha256(raw).hexdigest()
            parsed = wire.parse_ready(raw)
            if parsed["checks"] != 0xff:
                raise base.ProbeError("READY checks incomplete")
            self.backend.ready = parsed
        self.backend.query_observed = True
        return 88


class ReadyBackend(preflight.PreflightBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.work_clean = False
        self.ready_state = None
        self.ready_sha256 = None
        self.ready = None
        self.stop_reason = None

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unexpected service PID")
        session = ReadySession(self, info)
        self.sessions.append(session)
        return session.open()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--card-and-pmhome-verified", action="store_true")
    parser.add_argument("--msc-pid", type=lambda s: int(s, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  purpose="read existing dispatcher READY and Work baseline")
        return 0
    if (not args.msc_volumes_unmounted or not args.card_and_pmhome_verified
            or args.msc_pid != version.MSC_PID or args.pmca_path is None
            or args.libusb is None):
        parser.error("exact MSC identity and unmounted camera volumes required")
    sys.path.insert(0, str(args.pmca_path))
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    usb_backend = usb.backend.libusb1.get_backend(
        find_library=lambda _: str(args.libusb))
    if usb_backend is None:
        parser.error("configured libusb backend unavailable")
    backend = ReadyBackend(usb.core, usb.util, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera,
                           version.MSC_PID, version.PRODUCT,
                           budget=ReadBudget(), usb_backend=usb_backend,
                           logger=version.safe_logger())
    code, lifecycle = base.run_probe(backend)
    summary = {
        "event": "im_hot_ready_observe_summary_102",
        "product_verified": backend.product_verified,
        "Work_clean": backend.work_clean,
        "query_observed": backend.query_observed,
        "ready_state": backend.ready_state,
        "ready_sha256": backend.ready_sha256,
        "ready": backend.ready,
        "normal_mode_and_driver_verified": lifecycle["normal_mode_and_driver_verified"],
        "stop_reason": backend.stop_reason,
    }
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if (code == 0 and backend.product_verified
                 and backend.work_clean and backend.query_observed
                 and lifecycle["normal_mode_and_driver_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
