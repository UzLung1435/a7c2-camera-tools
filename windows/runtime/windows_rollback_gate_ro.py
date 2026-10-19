#!/usr/bin/env python3
"""Read current dat4 and libupdaterufp.so before an A7C II rollback."""

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
from jiritsu_libjit_read_probe import ReadBudget
from windows_service_probe import (require_winusb,
                                   verify_normal_in_new_process, windows_devices)
import windows_libusb

PATHS = {"dat4": preflight.PREFIX + b"/setting/updater/dat4",
         "libupdaterufp": preflight.PREFIX + b"/usr/lib/libupdaterufp.so"}
OFFICIAL_LIB_SHA = "2bf92c7b4e77b714b0370e37d747daade19edf59f243de3d0b928acc651418d3"
SELECTORS = frozenset(b"\x01\x10\x0f\x00\x00" + path for path in PATHS.values())


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


class Session(preflight.PreflightSession):
    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            body = bytes(data)[version.HEADER.size:]
            if body not in SELECTORS | {preflight.READ_DATA}:
                raise service.ProbeError("outside two fixed read-only paths")
        return super().write(data, ep)

    def product_info(self):
        require(self.info["pid"] == version.SERVICE_PID,
                "wrong Sony service PID")
        dev = self.backend.senser_class(self)
        camera = self.backend.camera_class(dev)
        self.wire_phase = "product"
        try:
            product = camera.readHasp()
            self.finish(dev, product)
        finally:
            self.wire_phase = None
        require(len(product) == 88, "camera product identity incomplete")
        self.product_verified = self.backend.product_verified = True
        for label, path in PATHS.items():
            self._read_fixed(dev, label, path)
        self.backend.query_observed = True
        return 88


class Backend(preflight.PreflightBackend):
    def open(self, info):
        self.require_known_pid(info)
        session = Session(self, info)
        self.sessions.append(session)
        return session.open()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-dat4-hex", choices=("0602", "0102", "0002"),
                        default="0602")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    out = args.out.resolve()
    require(out.is_relative_to(ROOT.resolve()),
            "report must stay inside Windows research workspace")
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     paths=["/setting/updater/dat4", "/usr/lib/libupdaterufp.so"])
        return 0
    require_winusb(args.serial)
    if not args.child:
        require(not out.exists(), "rollback gate report already exists")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--out", str(out),
                                "--expected-dat4-hex", args.expected_dat4_hex,
                                "--execute", "--child"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=300)
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
                        if item.get("event") == "rollback_gate_read_only"), None)
        require(target is not None and receipt is not None,
                "rollback gate child returned no complete receipt")
        if not receipt["product_verified"] or not receipt["query_observed"]:
            service.emit("service_read_incomplete_host_inventory",
                         serial=args.serial, inventory=windows_devices(),
                         camera_storage_write_attempted=False)
            raise service.ProbeError(
                "service read did not reach ProductInfo; inspect 0336 driver and current USB mode")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        require(receipt["product_verified"] and receipt["query_observed"] and
                receipt["dat4_hex"] == args.expected_dat4_hex,
                "installed dat4 differs from expected version")
        receipt["normal_mode_and_driver_verified_after_child_exit"] = True
        out.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        service.emit("rollback_gate_host_verified", report=str(out),
                     dat4_hex=receipt["dat4_hex"],
                     updater_library_matches_official_201=
                     receipt["updater_library_matches_official_201"])
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import windows_usb_adapter as adapter

    backend = Backend(usb.core, usb.util, SonySenserAuthDevice,
                      SonySenserDevice, SonySenserCamera,
                      version.MSC_PID, version.PRODUCT,
                      budget=ReadBudget(),
                      usb_backend=windows_libusb.get_backend(),
                      logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    dat4_state, dat4 = backend.files.get("dat4", (None, None))
    lib_state, lib = backend.files.get("libupdaterufp", (None, None))
    receipt = {"event": "rollback_gate_read_only", "serial": args.serial,
               "product_verified": backend.product_verified,
               "query_observed": backend.query_observed,
               "dat4_hex": dat4.hex() if dat4_state == "present" else None,
               "updater_library_state": lib_state,
               "updater_library_size": len(lib) if lib_state == "present" else None,
               "updater_library_sha256": hashlib.sha256(lib).hexdigest()
               if lib_state == "present" else None,
               "updater_library_matches_official_201":
               lib_state == "present" and len(lib) == 22776 and
               hashlib.sha256(lib).hexdigest() == OFFICIAL_LIB_SHA,
               "updater_instruction_1888_hex": lib[0x1888:0x188c].hex()
               if lib_state == "present" and len(lib) >= 0x188c else None,
               "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
               "child_code": code}
    print(json.dumps(receipt), flush=True)
    return 0 if backend.product_verified and backend.query_observed else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
