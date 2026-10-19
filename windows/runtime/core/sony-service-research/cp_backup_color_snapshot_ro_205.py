#!/usr/bin/env python3
"""Read only the camera's existing two BK4 backup files through GET_FILE2.

No Jiritsu write/delete/debug opcode, CP memory write, or updater operation is
permitted. Full backup bytes stay in process memory; stdout gives hashes and
the one color property's metadata, not user settings.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import service_probe as service
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
from jiritsu_libjit_read_probe import ReadBudget
import im_hot_ready_observe_102 as ready

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sony-firmware-research"))
from audit_fx2_native_fl23_color_block_204 import read_property, sha

PREFIX = preflight.PREFIX
PATHS = {
    "backup_bin": PREFIX + b"/setting/Backup.bin",
    "backup_bak": PREFIX + b"/setting/Backup.bak",
}
SELECTORS = frozenset(b"\x01\x10\x0f\x00\x00" + path for path in PATHS.values())
ALLOWED = SELECTORS | {preflight.READ_DATA}
MAX_BACKUP_BYTES = 3_000_000
OUTPUT_DIR = ROOT / "snapshots"


class Session(ready.ReadySession):
    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            body = bytes(data)[version.HEADER.size:]
            if (body not in ALLOWED or
                    (body == preflight.READ_DATA and not self.selected) or
                    (body in SELECTORS and self.active_label is None)):
                raise service.ProbeError("outside fixed read-only backup allowlist")
        return super(ready.ReadySession, self).write(data, ep)

    def _fixed_query(self, dev, body, label, expected_size):
        if body in SELECTORS:
            self.selected = False
        result = super(ready.ReadySession, self)._fixed_query(
            dev, body, label, expected_size)
        if body in SELECTORS:
            self.selected = True
        return result

    def _accept_stream_chunk(self, requested, raw):
        if self.stream_header_expected and self.active_label is not None:
            if requested != version.HEADER.size or len(raw) != version.HEADER.size:
                raise service.ProbeError("incomplete backup response header")
            declared = version.HEADER.unpack(raw)[0]
            if declared > MAX_BACKUP_BYTES + 4:
                raise service.ProbeError("backup response exceeds cap")
        return super(ready.ReadySession, self)._accept_stream_chunk(requested, raw)

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
        for label in PATHS:
            self._read_one(dev, label)
            state, data = self.backend.files[label]
            if state != "present" or not 0 < len(data) <= MAX_BACKUP_BYTES:
                raise service.ProbeError("backup file absent or invalid size")
            block, meta = read_property(data)
            if len(block) != 8192 or meta["property_attribute"] != "0x8":
                raise service.ProbeError("color property structure mismatch")
            digest = hashlib.sha256(data).hexdigest()
            if not OUTPUT_DIR.is_dir():
                raise service.ProbeError("private snapshot directory absent")
            filename = f"a7c2-readonly-{label}-{digest}.bin"
            destination = OUTPUT_DIR / filename
            if destination.exists():
                if (destination.is_symlink() or not destination.is_file() or
                        destination.stat().st_size != len(data) or
                        hashlib.sha256(destination.read_bytes()).hexdigest() != digest):
                    raise service.ProbeError("existing private backup mismatch")
            else:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT |
                             os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as stream:
                    if hasattr(os, "fchmod"):
                        os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            self.backend.results[label] = {
                "file_size": len(data),
                "file_sha256": digest,
                "private_snapshot": filename,
                "bk4_record_checksum_verified": meta["record_checksum_verified"],
                "property_id": meta["property_id"],
                "property_attr": meta["property_attribute"],
                "property_file_offset": meta["property_data_offset"],
                "property_length": len(block),
                "property_sha256": sha(block),
                "id_0x36_to_0x39_map": list(block[0x1236:0x123A]),
                "rows_22_to_25_zero": [not any(block[0x1250+i*64:0x1250+(i+1)*64])
                                       for i in range(22, 26)],
            }
        self.backend.query_observed = True
        return 88


class Backend(preflight.PreflightBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.results = {}

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in service.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unexpected service PID")
        session = Session(self, info)
        self.sessions.append(session)
        return session.open()


def main(argv=None):
    global OUTPUT_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--card-and-pmhome-verified", action="store_true")
    parser.add_argument("--msc-pid", type=lambda s: int(s, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    parser.add_argument("--out-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"camera_access": False, "paths": list(PATHS)}))
        return 0
    if (not args.msc_volumes_unmounted or not args.card_and_pmhome_verified
            or args.msc_pid != version.MSC_PID or args.pmca_path is None
            or args.libusb is None):
        parser.error("verified camera identity and unmounted camera volumes required")
    requested_output = args.out_dir.expanduser()
    if requested_output.is_symlink():
        parser.error("snapshot directory must not be a symlink")
    OUTPUT_DIR = requested_output.resolve()
    OUTPUT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if OUTPUT_DIR.stat().st_mode & 0o077:
        parser.error("snapshot directory must be private (mode 0700)")
    sys.path.insert(0, str(args.pmca_path))
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    usb_backend = usb.backend.libusb1.get_backend(
        find_library=lambda _: str(args.libusb))
    if usb_backend is None:
        parser.error("configured libusb unavailable")
    backend = Backend(usb.core, usb.util, SonySenserAuthDevice,
                      SonySenserDevice, SonySenserCamera,
                      version.MSC_PID, version.PRODUCT,
                      budget=ReadBudget(), usb_backend=usb_backend,
                      logger=version.safe_logger())
    code, lifecycle = service.run_probe(backend)
    summary = {"event": "cp_backup_color_snapshot_ro_205",
               "product_verified": backend.product_verified,
               "query_observed": backend.query_observed,
               "results": backend.results,
               "normal_mode_and_driver_verified":
                   lifecycle["normal_mode_and_driver_verified"]}
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if (code == 0 and backend.product_verified
                 and backend.query_observed and
                 lifecycle["normal_mode_and_driver_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
