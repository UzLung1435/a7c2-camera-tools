#!/usr/bin/env python3
"""Remove only two verified p1 inspection artifacts from camera Work storage."""

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
import p1_gate_generic_200 as gate
import windows_libusb
import windows_usb_adapter as adapter
from windows_service_probe import require_winusb, verify_normal_in_new_process
from windows_p1_200 import verified_manifest


PATH_PREFIX = b"\x01\x10\x0f\x00\x00"
DELETE_DATA = b"\x01\x10\x12\x00\x00\xff\x00"


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


class CleanupSession(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.selected_path = None
        self.allowed_paths = backend.paths
        self.allowed_path_bodies = frozenset(PATH_PREFIX + path for path in
                                              self.allowed_paths.values())

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            require(len(raw) >= version.HEADER.size,
                    "cleanup request header is incomplete")
            body = raw[version.HEADER.size:]
            require(body in self.allowed_path_bodies | {preflight.READ_DATA,
                                                        DELETE_DATA},
                    "cleanup request is not allowlisted")
            if body == DELETE_DATA:
                require(self.backend.content_verified and
                        self.selected_path in self.allowed_paths.values() and
                        self.selected_path in self.backend.present_paths,
                        "cleanup delete was not authorized by exact readback")
        return version.JiritsuSession.write(self, data, ep)

    def _fixed_query(self, dev, body, label, expected_size):
        if body in self.allowed_path_bodies:
            self.selected_path = body[len(PATH_PREFIX):]
        result = super()._fixed_query(dev, body, label, expected_size)
        if body == DELETE_DATA:
            self.selected_path = None
        return result

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

        for label, path in self.allowed_paths.items():
            self._read_fixed(dev, label + "_before", path)
        files = self.backend.files
        if self.backend.inspect_only:
            self.backend.states = {
                label: {"state": files[label + "_before"][0],
                        "bytes": len(files[label + "_before"][1])
                        if isinstance(files[label + "_before"][1], bytes) else None,
                        "sha256": hashlib.sha256(files[label + "_before"][1]).hexdigest()
                        if isinstance(files[label + "_before"][1], bytes) else None}
                for label in self.allowed_paths
            }
            state, raw = files["status_before"]
            if state == "present" and len(raw) == gate.STATUS.size:
                unpacked = gate.STATUS.unpack(raw)
                self.backend.status_fields = {
                    "magic_hex": unpacked[0].hex(), "version": unpacked[1],
                    "phase": unpacked[2], "camera_status": unpacked[3],
                    "rollback": unpacked[4], "major": unpacked[5],
                    "minor": unpacked[6], "capacity": unpacked[7],
                    "patch_at": unpacked[8], "patch_bytes": unpacked[9],
                    "source_crc": unpacked[10], "target_crc": unpacked[11],
                    "reserved": unpacked[12], "checksum_at": unpacked[13],
                    "nonce": unpacked[14]}
                try:
                    self.backend.parsed_status = gate.parse_status(raw,
                                                                     self.backend.config)
                except ValueError as exc:
                    self.backend.status_error = str(exc)
            self.backend.inspection_complete = True
            return 88
        for label in ("tmp_preload", "etc_preload"):
            require(files[label + "_before"][0] == "not_found_or_unreadable",
                    label + " remains present or unreadable")

        ram_state, ram = files["ram_before"]
        status_state, status = files["status_before"]
        require(ram_state in ("present", "not_found_or_unreadable") and
                status_state in ("present", "not_found_or_unreadable") and
                (ram_state == "present" or status_state == "present"),
                "no exact owned artifact found")
        if ram_state == "present":
            require(ram == self.backend.expected_elf,
                    "camera Work ELF differs from this host worker")
            self.backend.present_paths.add(self.allowed_paths["ram"])
        if status_state == "present":
            marker = gate.parse_status(status, self.backend.config)
            require(marker["phase"] == 6 and marker["camera_status"] == 0 and
                    marker["p1_crc_before"] == self.backend.config["source_crc"],
                    "camera Work status differs from verified read-only p1 step")
            self.backend.present_paths.add(self.allowed_paths["status"])
        self.backend.content_verified = True

        for label in ("status", "ram"):
            path = self.allowed_paths[label]
            if path in self.backend.present_paths:
                self._fixed_query(dev, PATH_PREFIX + path, "select_" + label, 4)
                self._fixed_query(dev, DELETE_DATA, "delete_" + label, 4)
                self.backend.deleted.append(label)
            self._read_fixed(dev, label + "_after", path)
            require(files[label + "_after"][0] == "not_found_or_unreadable",
                    label + " still present after exact deletion")
        self.backend.cleanup_complete = True
        return 88


class CleanupBackend(preflight.PreflightBackend):
    def __init__(self, *args, config, expected_elf, inspect_only, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.expected_elf = expected_elf
        self.inspect_only = inspect_only
        self.paths = {
            "ram": gate.PREFIX + b"/tmp_wbshd/" + config["filename"].encode(),
            "status": gate.PREFIX + b"/tmp_wbshd/" + config["status"].encode(),
            "tmp_preload": preflight.PATHS[2][1],
            "etc_preload": preflight.PATHS[3][1],
        }
        self.product_verified = False
        self.content_verified = False
        self.cleanup_complete = False
        self.present_paths = set()
        self.deleted = []
        self.states = {}
        self.status_fields = None
        self.parsed_status = None
        self.status_error = None
        self.inspection_complete = False

    def open(self, info):
        self.require_known_pid(info)
        require(info["pid"] not in service.SERVICE_PIDS or
                info["pid"] == version.SERVICE_PID,
                "unverified service PID")
        session = CleanupSession(self, info)
        self.sessions.append(session)
        return session.open()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stage", choices=("dual", "triple"), default="dual")
    parser.add_argument("--mode", choices=("verify_orig", "apply", "verify_patch",
                                            "restore"), default="verify_orig")
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "camera serial format differs")
    manifest_path = args.manifest.resolve()
    require(manifest_path.is_relative_to(ROOT.resolve()),
            "manifest outside Windows workspace")
    manifest = verified_manifest(manifest_path, args.serial)
    config = gate.config_for(args.stage, args.mode, manifest, manifest_path)
    elf = config["elf_path"].read_bytes()
    require(len(elf) == config["size"] and
            hashlib.sha256(elf).hexdigest() == config["sha256"],
            "host p1 inspection worker differs")
    if not args.execute:
        print(json.dumps({"camera_access": False,
                          "inspect_only": args.inspect_only,
                          "paths": ["/tmp_wbshd/" + config["filename"],
                                    "/tmp_wbshd/" + config["status"]]}))
        return 0
    require_winusb(args.serial)
    if not args.child:
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--manifest",
                                str(manifest_path), "--stage", args.stage,
                                "--mode", args.mode,
                                *(("--inspect-only",) if args.inspect_only else ()),
                                "--execute", "--child"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=300)
        print(child.stdout, end="", flush=True)
        if child.stderr:
            print(child.stderr, file=sys.stderr, end="", flush=True)
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events if
                       item.get("event") == "target_verified"), None)
        result = next((item for item in reversed(events) if
                       item.get("event") == "p1_owned_cleanup"), None)
        require(target is not None and result is not None,
                "cleanup child did not return a complete receipt")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        deleted = set(result["deleted"])
        require(result["verified"] is True and
                (args.inspect_only or
                 (bool(deleted) and deleted <= {"ram", "status"})),
                "exact file inspection/cleanup or recovery did not verify")
        return 0

    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera

    backend = CleanupBackend(usb.core, usb.util, SonySenserAuthDevice,
                             SonySenserDevice, SonySenserCamera,
                             version.MSC_PID, version.PRODUCT,
                             config=config, expected_elf=elf,
                             inspect_only=args.inspect_only,
                             budget=ReadBudget(),
                             usb_backend=windows_libusb.get_backend(),
                             logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    verified = (backend.product_verified and
                (backend.inspection_complete if args.inspect_only else
                 backend.content_verified and backend.cleanup_complete))
    service.emit("p1_owned_cleanup", serial=args.serial,
                 verified=verified, deleted=backend.deleted,
                 inspect_only=args.inspect_only, states=backend.states,
                 status_fields=backend.status_fields,
                 parsed_status=backend.parsed_status,
                 status_error=backend.status_error,
                 child_normal_verified=lifecycle["normal_mode_and_driver_verified"],
                 child_code=code)
    return 0 if verified else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
