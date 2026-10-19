"""Bounded read-only 2.01 FL2/FL3 model snapshot over Sony service USB."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
import zlib

import service_probe as base
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
from jiritsu_libjit_read_probe import ReadBudget

ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / "sony-firmware-research/libcodex_fl23_state_ro201.so"
ELF_SIZE = 20800
ELF_SHA256 = "585c268a853e03be6a6c893bddd80eae86634908d1844c4095e5c6fc5ce1e62d"
PREFIX = preflight.PREFIX
RAM = PREFIX + b"/tmp_wbshd/libcodex_fl23_state_ro201.so"
MARKER = PREFIX + b"/tmp_wbshd/codex_fl23_state_ro201.bin"
TMP = PREFIX + b"/tmp/ld.so.preload"
ETC = PREFIX + b"/etc/ld.so.preload"
ARM = b"/tmp_wbshd/libcodex_fl23_state_ro201.so\n"
SELECT = b"\x01\x10\x0f\x00\x00"
WRITE = b"\x01\x10\x10\x00\x00\xff\x00"
READ = preflight.READ_DATA
DELETE = b"\x01\x10\x12\x00\x00\xff\x00"
DEBUG = b"\x01\x10\x05\x00\x00"
RESULT = struct.Struct("<16sQ5I4H4BI")
MAGIC = b"A7C2FL23RO201\0\0\0"
assert RESULT.size == 60 and len(MAGIC) == 16


def pinned_elf():
    raw = ELF.read_bytes()
    if (len(raw) != ELF_SIZE or hashlib.sha256(raw).hexdigest() != ELF_SHA256
            or raw[:7] != b"\x7fELF\x02\x01\x01" or raw[18:20] != b"\xb7\0"):
        raise base.ProbeError("FL23 read-only ELF identity mismatch")
    return raw


def parse_marker(raw):
    if not isinstance(raw, bytes) or len(raw) != RESULT.size:
        raise base.ProbeError("FL23 marker length mismatch")
    values = RESULT.unpack(raw)
    magic, app_base, version_no, stage, checks, pid, error = values[:7]
    support = values[7:11]
    flags = values[11:15]
    crc = values[15]
    copy = bytearray(raw)
    copy[-4:] = b"\0" * 4
    if magic != MAGIC or version_no != 1 or zlib.crc32(copy) != crc:
        raise base.ProbeError("FL23 marker identity/CRC mismatch")
    return {"stage": stage, "checks": checks, "im_pid": pid,
            "app_base": hex(app_base), "error": error,
            "support": list(support), "flags": list(flags),
            "complete": stage == 9 and checks == 0xff and pid > 1 and app_base != 0}


class Session(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.elf = pinned_elf()
        self.paths = {SELECT + p for p in (RAM, MARKER, TMP, ETC)}
        self.allowed = self.paths | {READ, DELETE, DEBUG,
                                     WRITE + self.elf, WRITE + ARM}

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            body = bytes(data)[version.HEADER.size:]
            if body not in self.allowed:
                raise base.ProbeError("FL23 request outside fixed allowlist")
        return super().write(data, ep)

    def _query(self, dev, body, label):
        return self._fixed_query(dev, body, label, 4)

    def _read(self, dev, label, path):
        self._read_fixed(dev, label, path)
        return self.backend.files[label]

    def _cleanup(self, dev):
        b = self.backend
        try:
            tmp = self._read(dev, "tmp_after", TMP)
            etc = self._read(dev, "etc_after", ETC)
            if tmp[0] == etc[0] == "not_found_or_unreadable":
                b.cleanup = "verified_absent"
                return
            if tmp != ("present", ARM) or etc != ("present", ARM):
                b.cleanup = "unexpected_content_not_deleted"
                return
            self._query(dev, SELECT + TMP, "select_cleanup")
            self._query(dev, DELETE, "delete_preload")
            tmp = self._read(dev, "tmp_final", TMP)
            etc = self._read(dev, "etc_final", ETC)
            b.cleanup = ("verified_absent" if
                         tmp[0] == etc[0] == "not_found_or_unreadable"
                         else "delete_unverified")
        except BaseException:
            b.cleanup = "cleanup_wire_failed"

    def _cleanup_stage(self, dev):
        b = self.backend
        if (b.cleanup != "verified_absent" or not b.baseline_verified or
                not b.payload_verified or b.marker is None or
                not b.marker["complete"] or b.marker_raw is None):
            b.stage_cleanup = "skipped_unverified"
            return
        try:
            ram = self._read(dev, "ram_cleanup_before", RAM)
            marker = self._read(dev, "marker_cleanup_before", MARKER)
            if ram != ("present", self.elf) or marker != ("present", b.marker_raw):
                b.stage_cleanup = "stage_identity_changed"
                return
            for label, path in (("marker", MARKER), ("ram", RAM)):
                self._query(dev, SELECT + path, "select_cleanup_" + label)
                self._query(dev, DELETE, "delete_cleanup_" + label)
                if self._read(dev, label + "_cleanup_after", path)[0] != \
                        "not_found_or_unreadable":
                    b.stage_cleanup = "stage_delete_unverified"
                    return
            b.stage_cleanup = "verified_absent"
        except BaseException:
            b.stage_cleanup = "stage_cleanup_wire_failed"

    def product_info(self):
        if self.info["pid"] != version.SERVICE_PID:
            raise base.ProbeError("wrong service PID")
        b = self.backend
        dev = b.senser_class(self)
        camera = b.camera_class(dev)
        self.wire_phase = "product"
        try:
            product = camera.readHasp()
            self.finish(dev, product)
        finally:
            self.wire_phase = None
        if len(product) != 88:
            raise base.ProbeError("camera identity incomplete")
        self.product_verified = b.product_verified = True
        for label, path in (("ram_before", RAM), ("marker_before", MARKER),
                            ("tmp_before", TMP), ("etc_before", ETC)):
            if self._read(dev, label, path)[0] != "not_found_or_unreadable":
                b.stop_reason = "staging_path_not_absent"
                return 88
        b.baseline_verified = True
        self._query(dev, SELECT + RAM, "select_payload")
        self._query(dev, WRITE + self.elf, "stage_payload")
        if self._read(dev, "payload_readback", RAM) != ("present", self.elf):
            b.stop_reason = "payload_mismatch"
            return 88
        b.payload_verified = True
        for label, path in (("tmp_recheck", TMP), ("etc_recheck", ETC)):
            if self._read(dev, label, path)[0] != "not_found_or_unreadable":
                b.stop_reason = "preload_appeared"
                return 88
        self._query(dev, SELECT + TMP, "select_preload")
        try:
            self._query(dev, WRITE + ARM, "arm_preload")
            if self._read(dev, "etc_armed", ETC) != ("present", ARM):
                b.stop_reason = "preload_mismatch"
                return 88
            b.arm_verified = True
            self._query(dev, DEBUG, "trigger_fixed_child")
            b.trigger_ack = True
            for _ in range(5):
                state, data = self._read(dev, "marker_after", MARKER)
                if state == "present":
                    b.marker = parse_marker(data)
                    b.marker_raw = data
                    break
                time.sleep(.2)
            if b.marker is None:
                b.stop_reason = "marker_absent"
        finally:
            self._cleanup(dev)
            self._cleanup_stage(dev)
        b.query_observed = True
        return 88


class Backend(preflight.PreflightBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseline_verified = False
        self.payload_verified = False
        self.arm_verified = False
        self.trigger_ack = False
        self.marker = None
        self.marker_raw = None
        self.cleanup = "not_started"
        self.stage_cleanup = "not_started"
        self.stop_reason = None

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise base.ProbeError("wrong service PID")
        session = Session(self, info)
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
        print(json.dumps({"camera_access": False, "elf_sha256": ELF_SHA256}))
        return 0
    if (not args.msc_volumes_unmounted or not args.card_and_pmhome_verified
            or args.msc_pid != version.MSC_PID or args.pmca_path is None
            or args.libusb is None):
        parser.error("exact A7C II and unmounted-volume preconditions required")
    pinned_elf()
    sys.path.insert(0, str(args.pmca_path))
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    usb_backend = usb.backend.libusb1.get_backend(
        find_library=lambda _: str(args.libusb))
    if usb_backend is None:
        parser.error("configured libusb backend unavailable")
    backend = Backend(usb.core, usb.util, SonySenserAuthDevice,
                      SonySenserDevice, SonySenserCamera,
                      version.MSC_PID, version.PRODUCT,
                      budget=ReadBudget(), usb_backend=usb_backend,
                      logger=version.safe_logger())
    code, lifecycle = base.run_probe(backend)
    success = (code == 0 and backend.product_verified and
               backend.baseline_verified and backend.payload_verified and
               backend.arm_verified and backend.trigger_ack and
               backend.marker is not None and backend.marker["complete"] and
               backend.cleanup == "verified_absent" and
               backend.stage_cleanup == "verified_absent" and
               lifecycle["normal_mode_and_driver_verified"])
    report = {"event": "fl23_state_ro_201_summary",
              "product_verified": backend.product_verified,
              "baseline_verified": backend.baseline_verified,
              "payload_verified": backend.payload_verified,
              "arm_verified": backend.arm_verified,
              "trigger_ack": backend.trigger_ack,
              "marker": backend.marker,
               "preload_cleanup": backend.cleanup,
               "stage_cleanup": backend.stage_cleanup,
              "stop_reason": backend.stop_reason,
              "normal_mode_and_driver_verified": lifecycle["normal_mode_and_driver_verified"],
              "read_only_probe_verified": success}
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
