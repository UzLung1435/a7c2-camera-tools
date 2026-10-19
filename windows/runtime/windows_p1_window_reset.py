#!/usr/bin/env python3
"""Remove the two owned cnflasha1 window staging files from camera Work storage.

A p1 window capture stages one worker ELF and one 64-byte window request into
the camera Work volume and reuses both for windows 1 and 2. Neither the final
cleanup nor the capture itself removes them, and window 0 is allowed to start
only when both paths read back "absent". A second capture on a camera that is
still holding the previous capture's staging therefore aborts at the window-0
baseline gate with

    baseline_file_present_or_unreadable

before a single write command is sent. This tool deletes exactly those two
paths, and only after the bytes prove they belong to this worker:

* the worker ELF must hash to the pinned cn1_window_201 SHA-256,
* the request must be 64 bytes starting with the CXDCN1REQV1 wire magic,
* both preload paths must read back absent (otherwise a capture, not a
  leftover, owns the volume and nothing is touched).

Every path is re-read afterwards and must report not found.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))

import service_probe as service
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
import p1_block_window_protocol_201 as wire
from jiritsu_libjit_read_probe import ReadBudget
import windows_libusb
import windows_usb_adapter as adapter
from windows_service_probe import require_winusb, verify_normal_in_new_process


PATH_PREFIX = b"\x01\x10\x0f\x00\x00"
DELETE_DATA = b"\x01\x10\x12\x00\x00\xff\x00"
PROFILE = wire.CN1
TAG = PROFILE.tag.lower().encode("ascii")
RAM_PATH = preflight.PREFIX + b"/tmp_wbshd/libcodex_" + TAG + b"_window_201.so"
REQUEST_PATH = (preflight.PREFIX + b"/tmp_wbshd/codex_" + TAG +
                b"_request_201.bin")
REQUEST_SIZE = wire.REQUEST.size
REQUEST_MAGIC = PROFILE.magic("REQV1")
ELF_PATH = ROOT / "core" / "sony-firmware-research" / "libcodex_cn1_window_201.so"
ELF_SIZE = 9520
ELF_SHA256 = "2adbcbc2a2eca3fe262e0aac2db475a0cf524de8c3e8a67b6ead24aebda0af78"


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def worker_elf():
    raw = ELF_PATH.read_bytes()
    require(len(raw) == ELF_SIZE and
            hashlib.sha256(raw).hexdigest() == ELF_SHA256,
            "host cnflasha1 window worker identity differs")
    return raw


def request_fields(data):
    """Wire fields of a staged window request, or {} when it is not one."""
    if not isinstance(data, bytes) or len(data) != REQUEST_SIZE:
        return {}
    fields = wire.REQUEST.unpack(data)
    return {"capture_id": fields[1].hex(), "partition": fields[3],
            "window_index": fields[4], "start": fields[5], "count": fields[6]}


class ResetSession(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.selected_path = None
        self.allowed_paths = frozenset(backend.paths.values())
        self.allowed_path_bodies = frozenset(PATH_PREFIX + path
                                             for path in self.allowed_paths)

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            require(len(raw) >= version.HEADER.size,
                    "reset request header is incomplete")
            body = raw[version.HEADER.size:]
            require(body in self.allowed_path_bodies | {preflight.READ_DATA,
                                                        DELETE_DATA},
                    "reset request is not allowlisted")
            if body == DELETE_DATA:
                require(self.backend.content_verified and
                        self.selected_path in self.backend.present_paths,
                        "reset delete was not authorized by exact readback")
        return version.JiritsuSession.write(self, data, ep)

    def _fixed_query(self, dev, body, label, expected_size):
        if body in self.allowed_path_bodies:
            self.selected_path = body[len(PATH_PREFIX):]
        result = super()._fixed_query(dev, body, label, expected_size)
        if body == DELETE_DATA:
            self.selected_path = None
        return result

    def _delete_exact(self, dev, label, path):
        require(path in self.allowed_paths, "unlisted reset path")
        self._fixed_query(dev, PATH_PREFIX + path, "select_" + label, 4)
        self._fixed_query(dev, DELETE_DATA, "delete_" + label, 4)

    def product_info(self):
        require(self.info["pid"] == version.SERVICE_PID,
                "unverified service mode")
        dev = self.backend.senser_class(self)
        camera = self.backend.camera_class(dev)
        self.wire_phase = "product"
        try:
            product = camera.readHasp()
            self.finish(dev, product)
        finally:
            self.wire_phase = None
        require(len(product) == 88, "ProductInfo differs")
        self.product_verified = self.backend.product_verified = True

        for label, path in self.backend.paths.items():
            self._read_fixed(dev, label + "_before", path)
        files = self.backend.files
        for label in ("tmp_preload", "etc_preload"):
            require(files[label + "_before"][0] == "not_found_or_unreadable",
                    label + " is present; a capture may be in flight, "
                    "so no staging file was deleted")

        ram_state, ram = files["ram_before"]
        if ram_state == "present":
            require(isinstance(ram, bytes) and len(ram) == ELF_SIZE and
                    hashlib.sha256(ram).hexdigest() == ELF_SHA256,
                    "camera Work ELF differs from this pinned window worker")
            self.backend.present_paths.add(self.backend.paths["ram"])
        else:
            require(ram_state == "not_found_or_unreadable",
                    "camera Work ELF state not verified")

        request_state, request = files["request_before"]
        if request_state == "present":
            fields = request_fields(request)
            require(isinstance(request, bytes) and len(request) == REQUEST_SIZE
                    and request[:len(REQUEST_MAGIC)] == REQUEST_MAGIC
                    and fields.get("partition") == PROFILE.partition,
                    "camera Work request is not this capture's wire format")
            self.backend.request_fields = fields
            self.backend.present_paths.add(self.backend.paths["request"])
        else:
            require(request_state == "not_found_or_unreadable",
                    "camera Work request state not verified")
        self.backend.content_verified = True

        for label in ("ram", "request"):
            path = self.backend.paths[label]
            if path in self.backend.present_paths:
                self._delete_exact(dev, label, path)
                self.backend.deleted.append(label)
            self._read_fixed(dev, label + "_after", path)
            require(files[label + "_after"][0] == "not_found_or_unreadable",
                    label + " still present after exact deletion")
        self.backend.reset_complete = True
        return 88


class ResetBackend(preflight.PreflightBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.paths = {
            "ram": RAM_PATH,
            "request": REQUEST_PATH,
            "tmp_preload": preflight.PATHS[2][1],
            "etc_preload": preflight.PATHS[3][1],
        }
        self.product_verified = False
        self.content_verified = False
        self.reset_complete = False
        self.present_paths = set()
        self.deleted = []
        self.states = {}
        self.request_fields = {}

    def open(self, info):
        self.require_known_pid(info)
        require(info["pid"] not in service.SERVICE_PIDS or
                info["pid"] == version.SERVICE_PID,
                "unverified service PID")
        session = ResetSession(self, info)
        self.sessions.append(session)
        return session.open()


def describe(files, label):
    item = files.get(label) or ("unknown", None)
    data = item[1]
    return {"state": item[0],
            "bytes": len(data) if isinstance(data, bytes) else None,
            "sha256": hashlib.sha256(data).hexdigest()
            if isinstance(data, bytes) else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    worker_elf()
    if not args.execute:
        service.emit("offline_plan", camera_access=False, profile=PROFILE.tag,
                     paths=["/tmp_wbshd/libcodex_" + PROFILE.tag.lower() +
                            "_window_201.so",
                            "/tmp_wbshd/codex_" + PROFILE.tag.lower() +
                            "_request_201.bin"])
        return 0
    require_winusb(args.serial)
    if not args.child:
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--execute", "--child"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=360)
        print(child.stdout, end="", flush=True)
        if child.stderr:
            print(child.stderr, file=sys.stderr, end="", flush=True)
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events
                       if item.get("event") == "target_verified"), None)
        receipt = next((item for item in reversed(events)
                        if item.get("event") == "windows_p1_window_reset"), None)
        require(target is not None and receipt is not None,
                "reset child returned no complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(receipt["product_verified"] and receipt["reset_complete"],
                "camera window staging was not reset")
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera

    backend = ResetBackend(usb.core, usb.util, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera,
                           version.MSC_PID, version.PRODUCT,
                           budget=ReadBudget(),
                           usb_backend=windows_libusb.get_backend(),
                           logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    receipt = {"event": "windows_p1_window_reset", "serial": args.serial,
               "product_verified": backend.product_verified,
               "content_verified": backend.content_verified,
               "reset_complete": backend.reset_complete,
               "deleted": backend.deleted,
               "ram_before": describe(backend.files, "ram_before"),
               "request_before": describe(backend.files, "request_before"),
               "stale_request": backend.request_fields,
               "child_normal_verified":
                   lifecycle["normal_mode_and_driver_verified"],
               "child_code": code}
    print(json.dumps(receipt), flush=True)
    return 0 if receipt["product_verified"] and receipt["reset_complete"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
