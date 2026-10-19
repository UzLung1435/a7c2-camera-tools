#!/usr/bin/env python3
"""HELD one-shot read-only 4-MiB nflasha13 tmpfs producer.

The pinned ELF opens literal /dev/nflasha13 O_RDONLY and writes 64 fixed
64-KiB chunks into tmpfs, then a small manifest. This host probe stages the
ELF, triggers the exact child once, validates the manifest, cleans Work and
restores MSC. A separate read-only collector fetches chunks in short sessions.
No live hardware access is possible until independently reviewed gates change.
"""

import argparse
import hashlib
from pathlib import Path
import struct
import sys
import time

import service_probe as base
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
from jiritsu_libjit_read_probe import ReadBudget


LIVE_EXECUTION_REVIEWED = False
ELF_PATH = (Path(__file__).resolve().parents[1] / "sony-firmware-research"
            / "libcodex_raw13_full_102.so")
ELF_SIZE = 7328
ELF_SHA256 = "c9012b1a63a8bf009db9f8dabe37a6edf2b9cbd4456132050c63bef29b144879"

PREFIX = preflight.PREFIX
RAM_PATH = PREFIX + b"/tmp_wbshd/libcodex_raw13_full_102.so"
MANIFEST_PATH = PREFIX + b"/tmp_wbshd/codex_raw13_full_102/manifest.bin"
TMP_PRELOAD_PATH = preflight.PATHS[2][1]
ETC_PRELOAD_PATH = preflight.PATHS[3][1]
ARM_TEXT = b"/tmp_wbshd/libcodex_raw13_full_102.so\n"
DEBUG_DATA = b"\x01\x10\x05\x00\x00"
DELETE_DATA = b"\x01\x10\x12\x00\x00\xff\x00"
READ_DATA = preflight.READ_DATA
WRITE_PREFIX = b"\x01\x10\x10\x00\x00\xff\x00"
ARM_WRITE_DATA = WRITE_PREFIX + ARM_TEXT
PATH_PREFIX = b"\x01\x10\x0f\x00\x00"
TMP_PATH_DATA = PATH_PREFIX + TMP_PRELOAD_PATH
RAM_PATH_DATA = PATH_PREFIX + RAM_PATH
PATH_BODIES = frozenset(PATH_PREFIX + path for path in
                        (RAM_PATH, MANIFEST_PATH, TMP_PRELOAD_PATH,
                         ETC_PRELOAD_PATH))
MANIFEST = struct.Struct("<16sIIQIIIIII16siIQQ")
MAGIC = b"CXDRAW13FULLM1\0\0"
MANIFEST_MAGIC = MAGIC
NONCE = 0xa7c210200013ffff
CHUNK_BYTES = 65536
PARTITION_BYTES = 4194304
MIN_OWNED_PREFIX = len(b"/tmp_wbshd/libcodex_raw13_full_")
assert len(MAGIC) == 16 and MANIFEST.size == 96
assert ARM_TEXT == RAM_PATH.split(b"../../", 1)[1].replace(
    b"tmp_wbshd/", b"/tmp_wbshd/", 1) + b"\n"


def fixed_elf():
    raw = ELF_PATH.read_bytes()
    if len(raw) != ELF_SIZE or hashlib.sha256(raw).hexdigest() != ELF_SHA256:
        raise base.ProbeError("fixed raw13 ELF size/hash mismatch")
    if raw[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 183:
        raise base.ProbeError("fixed raw13 ELF format mismatch")
    return raw


def parse_manifest(raw):
    if not isinstance(raw, bytes) or len(raw) != MANIFEST.size:
        raise base.ProbeError("raw13 full manifest length mismatch")
    fields = MANIFEST.unpack(raw)
    (magic, version_, partition, partition_bytes, chunk_bytes, chunk_count,
     produced_count, full_crc32, selected_major, selected_minor,
     selected_name_raw, status, reserved, nonce, reserved2) = fields
    selected_name = selected_name_raw.split(b"\0", 1)[0]
    if (magic != MAGIC or version_ != 1 or partition != 13
            or partition_bytes != PARTITION_BYTES or chunk_bytes != CHUNK_BYTES
            or chunk_count != 64 or produced_count != 64
            or nonce != NONCE or status != 0 or reserved or reserved2
            or selected_major == 0
            or selected_name not in (b"pnflasha13", b"cnflasha13")
            or selected_name_raw != selected_name.ljust(16, b"\0")
            ):
        raise base.ProbeError("raw13 full manifest fields/status mismatch")
    return {"partition_bytes": partition_bytes, "chunk_bytes": chunk_bytes,
            "chunk_count": chunk_count, "full_crc32": full_crc32,
            "selected_kernel_name": selected_name.decode("ascii"),
            "selected_major": selected_major, "selected_minor": selected_minor,
            "manifest_sha256": hashlib.sha256(raw).hexdigest()}


def _absent(files, *labels):
    return all(files.get(label, (None,))[0] == "not_found_or_unreadable"
               for label in labels)


def _present_exact(files, label, value):
    return files.get(label) == ("present", value)


class ProducerBudget(ReadBudget):
    def __init__(self):
        super().__init__()
        self.long_trigger = False

    def timeout_ms(self, requested=1000):
        if not self.long_trigger or self.recovering:
            return super().timeout_ms(requested)
        self.check()
        self.calls += 1
        self.work_calls += 1
        if self.work_calls > 2600:
            raise base.ProbeError("work USB transfer-count limit reached")
        return max(1, min(15000, int(self.remaining() * 1000)))


class ProducerSession(preflight.PreflightSession):
    def __init__(self, backend, info):
        super().__init__(backend, info)
        self.selected_path = None
        self.ram_write_attempted = False
        self.arm_write_attempted = False
        self.trigger_attempted = False
        self.delete_attempted = False
        self.ram_write_data = WRITE_PREFIX + fixed_elf()
        self.arm_write_data = ARM_WRITE_DATA
        self.allowed_bodies = (PATH_BODIES | {READ_DATA, self.ram_write_data,
                                             self.arm_write_data, DEBUG_DATA,
                                             DELETE_DATA})

    def _fixed_query(self, dev, body, label, expected_size):
        if body in PATH_BODIES:
            self.selected_path = None
        result = super()._fixed_query(dev, body, label, expected_size)
        if body in PATH_BODIES:
            self.selected_path = body
        elif body in (self.ram_write_data, self.arm_write_data, DELETE_DATA):
            self.selected_path = None
        return result

    def _read_fixed(self, dev, label, path):
        try:
            return super()._read_fixed(dev, label, path)
        finally:
            self.selected_path = None

    def write(self, data, ep=0):
        if self.wire_phase == "jiritsu":
            raw = bytes(data)
            if len(raw) < version.HEADER.size:
                raise version.JiritsuProbeError("request_not_allowlisted")
            body = raw[version.HEADER.size:]
            if body not in self.allowed_bodies:
                raise version.JiritsuProbeError("request_not_allowlisted")
            if body == self.ram_write_data:
                if (self.selected_path != RAM_PATH_DATA or not self.backend.baseline_verified
                        or self.ram_write_attempted):
                    raise version.JiritsuProbeError("request_not_allowlisted")
                self.ram_write_attempted = True
            elif body == self.arm_write_data:
                if (self.selected_path != TMP_PATH_DATA or not self.backend.ram_verified
                        or not self.backend.output_absent_recheck
                        or not self.backend.preload_absent_recheck
                        or not self.backend.arm_authorized
                        or self.arm_write_attempted):
                    raise version.JiritsuProbeError("request_not_allowlisted")
                self.arm_write_attempted = True
            elif body == DEBUG_DATA:
                if (not self.backend.arm_verified or not self.backend.trigger_authorized
                        or self.trigger_attempted):
                    raise version.JiritsuProbeError("request_not_allowlisted")
                self.trigger_attempted = True
            elif body == DELETE_DATA:
                if (not self.backend.cleanup_started or not self.backend.arm_write_sent
                        or self.selected_path != TMP_PATH_DATA or self.delete_attempted):
                    raise version.JiritsuProbeError("request_not_allowlisted")
                self.delete_attempted = True
        result = super().write(data, ep)
        if self.wire_phase == "jiritsu":
            if body == self.ram_write_data:
                self.backend.ram_write_sent = True
            elif body == self.arm_write_data:
                self.backend.arm_write_sent = True
            elif body == DEBUG_DATA:
                self.backend.trigger_sent = True
        return result

    def _wire_clean(self):
        return (self.claimed and not self.closed
                and self.info["pid"] == version.SERVICE_PID
                and not self.response_pending and not self.header_pending)

    def _cleanup(self, dev):
        if not self.backend.arm_request_maybe_sent:
            return
        if not self._wire_clean():
            self.backend.cleanup_state = "wire_state_unknown"
            return
        try:
            self._read_fixed(dev, "cleanup_tmp_before", TMP_PRELOAD_PATH)
            self._read_fixed(dev, "cleanup_etc_before", ETC_PRELOAD_PATH)
        except BaseException:
            self.backend.cleanup_state = "readback_unverified"
            return
        files = self.backend.files
        if _absent(files, "cleanup_tmp_before", "cleanup_etc_before"):
            self.backend.cleanup_absence_verified = True
            self.backend.cleanup_state = "verified_absent"
            return
        tmp, etc = files["cleanup_tmp_before"], files["cleanup_etc_before"]
        owned = (self.backend.arm_write_sent and tmp[0] == etc[0] == "present"
                 and tmp[1] == etc[1] and ARM_TEXT.startswith(tmp[1])
                 and (not tmp[1] or len(tmp[1]) >= MIN_OWNED_PREFIX))
        if not owned:
            self.backend.cleanup_state = "unexpected_content_not_deleted"
            return
        self.backend.cleanup_started = True
        try:
            self._fixed_query(dev, TMP_PATH_DATA, "set_cleanup_preload", 4)
            self._fixed_query(dev, DELETE_DATA, "delete_owned_preload", 4)
            self.backend.delete_ack = True
        except BaseException:
            self.backend.cleanup_state = "delete_unverified"
        if not self._wire_clean():
            self.backend.cleanup_state = "wire_state_unknown"
            return
        try:
            self._read_fixed(dev, "cleanup_tmp_after", TMP_PRELOAD_PATH)
            self._read_fixed(dev, "cleanup_etc_after", ETC_PRELOAD_PATH)
            self.backend.cleanup_absence_verified = _absent(
                files, "cleanup_tmp_after", "cleanup_etc_after")
            self.backend.cleanup_state = ("verified_absent" if self.backend.cleanup_absence_verified
                                          else "file_still_present_or_unreadable")
        except BaseException:
            self.backend.cleanup_state = "final_readback_unverified"

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

        self._read_fixed(dev, "ram_before", RAM_PATH)
        self._read_fixed(dev, "manifest_before", MANIFEST_PATH)
        self._read_fixed(dev, "tmp_preload_before", TMP_PRELOAD_PATH)
        self._read_fixed(dev, "etc_preload_before", ETC_PRELOAD_PATH)
        self.backend.baseline_verified = _absent(
            self.backend.files, "ram_before", "manifest_before",
            "tmp_preload_before", "etc_preload_before")
        if not self.backend.baseline_verified:
            self.backend.stop_reason = "baseline_file_present_or_unreadable"
            return 88

        self._fixed_query(dev, RAM_PATH_DATA, "select_ram_elf", 4)
        self.backend.ram_write_request_maybe_sent = True
        self._fixed_query(dev, self.ram_write_data, "stage_ram_elf", 4)
        self.backend.ram_write_ack = True
        self._read_fixed(dev, "ram_after", RAM_PATH)
        self.backend.ram_verified = _present_exact(
            self.backend.files, "ram_after", fixed_elf())
        if not self.backend.ram_verified:
            self.backend.stop_reason = "ram_elf_readback_mismatch"
            return 88

        self._read_fixed(dev, "manifest_recheck", MANIFEST_PATH)
        self._read_fixed(dev, "tmp_preload_recheck", TMP_PRELOAD_PATH)
        self._read_fixed(dev, "etc_preload_recheck", ETC_PRELOAD_PATH)
        self.backend.output_absent_recheck = _absent(self.backend.files, "manifest_recheck")
        self.backend.preload_absent_recheck = _absent(
            self.backend.files, "tmp_preload_recheck", "etc_preload_recheck")
        if not (self.backend.output_absent_recheck and self.backend.preload_absent_recheck):
            self.backend.stop_reason = "output_or_preload_appeared"
            return 88

        self._fixed_query(dev, TMP_PATH_DATA, "select_preload", 4)
        try:
            self.backend.arm_request_maybe_sent = True
            self.backend.arm_authorized = True
            self._fixed_query(dev, self.arm_write_data, "arm_full_producer", 4)
            self.backend.arm_write_ack = True
            self._read_fixed(dev, "etc_armed", ETC_PRELOAD_PATH)
            self.backend.arm_verified = _present_exact(
                self.backend.files, "etc_armed", ARM_TEXT)
            if not self.backend.arm_verified:
                self.backend.stop_reason = "arm_readback_mismatch"
                return 88
            self.backend.trigger_request_maybe_sent = True
            self.backend.trigger_authorized = True
            self.backend.budget.long_trigger = True
            try:
                self._fixed_query(dev, DEBUG_DATA, "trigger_full_snapshot", 4)
            finally:
                self.backend.budget.long_trigger = False
            self.backend.trigger_ack = True
            manifest_deadline = time.monotonic() + 10.0
            attempt = 0
            while attempt < 40 and (attempt == 0 or time.monotonic() < manifest_deadline):
                label = f"manifest_result_{attempt}"
                self._read_fixed(dev, label, MANIFEST_PATH)
                state, raw = self.backend.files[label]
                if state == "present":
                    try:
                        self.backend.manifest_fields = parse_manifest(raw)
                        self.backend.manifest_verified = True
                    except base.ProbeError:
                        self.backend.stop_reason = "manifest_invalid"
                    break
                attempt += 1
                remaining = manifest_deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.backend.budget.check()
                time.sleep(min(0.25, remaining))
            if not self.backend.manifest_verified and self.backend.stop_reason is None:
                self.backend.stop_reason = "manifest_pending_or_missing"
            self._read_fixed(dev, "tmp_after_trigger", TMP_PRELOAD_PATH)
            self._read_fixed(dev, "etc_after_trigger", ETC_PRELOAD_PATH)
            self.backend.constructor_unlink_verified = _absent(
                self.backend.files, "tmp_after_trigger", "etc_after_trigger")
        finally:
            self.backend.arm_authorized = False
            self.backend.trigger_authorized = False
            self._cleanup(dev)
        self.backend.proof_verified = (self.backend.trigger_ack and
            self.backend.manifest_verified and self.backend.constructor_unlink_verified
            and self.backend.cleanup_absence_verified)
        return 88


class ProducerBackend(preflight.PreflightBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.baseline_verified = False
        self.ram_write_request_maybe_sent = False
        self.ram_write_sent = False
        self.ram_write_ack = False
        self.ram_verified = False
        self.output_absent_recheck = False
        self.preload_absent_recheck = False
        self.arm_request_maybe_sent = False
        self.arm_authorized = False
        self.arm_write_sent = False
        self.arm_write_ack = False
        self.arm_verified = False
        self.trigger_request_maybe_sent = False
        self.trigger_authorized = False
        self.trigger_sent = False
        self.trigger_ack = False
        self.manifest_fields = None
        self.manifest_verified = False
        self.constructor_unlink_verified = False
        self.cleanup_started = False
        self.delete_ack = False
        self.cleanup_absence_verified = False
        self.cleanup_state = "not_needed"
        self.proof_verified = False
        self.stop_reason = None

    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = ProducerSession(self, info)
        self.sessions.append(session)
        return session.open()


def summarize(backend, restored):
    return {"product_verified": backend.product_verified,
            "baseline_verified": backend.baseline_verified,
            "ram_write_request_maybe_sent": backend.ram_write_request_maybe_sent,
            "ram_verified": backend.ram_verified,
            "arm_request_maybe_sent": backend.arm_request_maybe_sent,
            "arm_write_sent": backend.arm_write_sent,
            "arm_verified": backend.arm_verified,
            "trigger_request_maybe_sent": backend.trigger_request_maybe_sent,
            "trigger_ack": backend.trigger_ack,
            "manifest_verified": backend.manifest_verified,
            "constructor_unlink_verified": backend.constructor_unlink_verified,
            "cleanup_absence_verified": backend.cleanup_absence_verified,
            "cleanup_state": backend.cleanup_state,
            "proof_verified": backend.proof_verified,
            "stop_reason": backend.stop_reason,
            "normal_mode_and_driver_verified": restored,
            "elf_sha256": ELF_SHA256,
            **(backend.manifest_fields or {})}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--prior-inventory-verified", action="store_true")
    parser.add_argument("--prior-service-probe-verified", action="store_true")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--photo-card-absent", action="store_true")
    parser.add_argument("--msc-pid", type=lambda value: int(value, 16))
    parser.add_argument("--pmca-path", type=Path)
    parser.add_argument("--libusb", type=Path)
    args = parser.parse_args(argv)
    fixed_elf()
    if not args.execute:
        base.emit("offline_plan", hardware_access=False,
                  action="fixed one-shot 4-MiB nflasha13 tmpfs producer",
                  fixed_elf_sha256=ELF_SHA256,
                  live_reviewed=LIVE_EXECUTION_REVIEWED)
        return 0
    if not LIVE_EXECUTION_REVIEWED:
        parser.error("raw13 full producer is held; no camera access")
    if (not args.prior_inventory_verified or not args.prior_service_probe_verified
            or not args.msc_volumes_unmounted or not args.photo_card_absent
            or args.msc_pid != version.MSC_PID):
        parser.error("exact1.02 card-absent inventory/MSC preflight required")
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
    backend = ProducerBackend(usb.core, usb.util, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera,
                           version.MSC_PID, version.PRODUCT,
                           budget=ProducerBudget(), usb_backend=explicit_backend,
                           logger=version.safe_logger())
    code, lifecycle = base.run_probe(backend)
    result = summarize(backend, lifecycle["normal_mode_and_driver_verified"])
    base.emit("raw13_full_producer_summary", **result)
    return 0 if (code == 0 and result["product_verified"]
                 and result["proof_verified"] and result["manifest_verified"]
                 and result["cleanup_absence_verified"]
                 and result["normal_mode_and_driver_verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
