#!/usr/bin/env python3
"""Minimal, bounded PMCA service-product-info probe; never run on import.

HOST PREPARATION (performed separately by the operator):
* Verify the single connected Sony body is the intended ILCE-7CM2, firmware 1.02.
* Connect in MSC mode, record its actual PID, and safely unmount EVERY volume on
  that camera's storage device. Do not eject/unplug the USB device itself.
* Close applications using the camera. Administrator access may be required.
* Do not pass --msc-volumes-unmounted until disk/volume ownership was verified.
  This script deliberately does not unmount disks or install/alter host drivers.

Only protocol operations: StartSenser, authentication, ProductInfo/ReadHasp,
StopSenser. No terminal, file, memory, backup-setting or firmware operations.
Authentication and mode changes send protocol bytes; this is not a passive read.
ReadHasp output is reduced to byte count and SHA-256; no payload bytes are logged.

Execution is opt-in: without --execute this prints a plan and does not even
import USB libraries. All normal/recovery transfers have short timeouts. The
45-second total is a cooperative deadline: an OS driver call which itself
ignores cancellation cannot safely be force-killed while an interface is held.

PMCA dependency modules may be preloaded into sys.modules by a trusted launcher.
No pmca.commands, original UsbBackend, or automatic-reset driver is used here.
"""

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path


VID = 0x054C
SERVICE_PIDS = frozenset((0x02A9, 0x0336))
KNOWN_MTP_PID = 0x0E8B
START = (1, 0x37FF, 0xD7AA)
STOP = (1, 0xC800, 0x2855)
MSC_CLASS = 8
SERVICE_CLASS = 255
UNKNOWN_OBSERVATION_SECONDS = 10.0


class ProbeError(Exception):
    pass


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, ensure_ascii=False), flush=True)


def error_text(exc):
    return {"type": type(exc).__name__, "message": str(exc),
            "errno": getattr(exc, "errno", None),
            "backend_error_code": getattr(exc, "backend_error_code", None)}


def is_gone(exc):
    # -4 is NO_DEVICE, -5 is NOT_FOUND (often returned by old interface handles
    # after re-enumeration). Neither is proof of restored state: fresh normal
    # PID/port/native-driver verification is still mandatory.
    return (getattr(exc, "backend_error_code", None) in (-4, -5) or
            getattr(exc, "errno", None) in (2, 19))


class Budget:
    def __init__(self, total=45.0, reserve=17.0):
        self.started = time.monotonic()
        self.end = self.started + total
        self.work_end = self.end - reserve
        self.recovering = False
        self.calls = 0
        self.rx_bytes = 0

    def remaining(self):
        end = self.end if self.recovering else self.work_end
        return end - time.monotonic()

    def check(self):
        if self.remaining() <= 0:
            raise ProbeError("recovery deadline reached" if self.recovering
                             else "work deadline reached; recovery reserved")

    def timeout_ms(self, requested=1000):
        self.check()
        self.calls += 1
        limit = 192 if self.recovering else 96
        if self.calls > limit:
            raise ProbeError("USB transfer-count limit reached")
        return max(1, min(requested or 1000, 1000,
                          int(self.remaining() * 1000)))

    def received(self, size):
        self.rx_bytes += size
        if self.rx_bytes > 262144:
            raise ProbeError("response-byte limit reached")


class ManagedSession:
    """Owns only interface 0. Reattach only this session's live captured device.

    Also implements the tiny driver API used by SonySenserAuthDevice and
    SonySenserDevice. reset() is intentionally a checked NO-OP: never the
    original PMCA reset/detach implementation.
    """
    def __init__(self, backend, info):
        self.backend, self.info = backend, info
        self.dev = info["device"]
        self.detached = False
        self.claimed = False
        self.closed = False
        self.was_active = None
        self.cleanup_errors = []
        self.ep_in, self.ep_out = [], []
        self.wire_phase = None
        self.product_request_sent = False

    def open(self):
        b = self.backend
        # Also guards subclasses which construct a session directly. Unknown
        # modes must never reach a driver query, claim, detach, or transport.
        b.require_known_pid(self.info)
        try:
            b.budget.check()
            self.was_active = self.dev.is_kernel_driver_active(0)
            if self.was_active:
                self.dev.detach_kernel_driver(0)
                self.detached = True
                b.log("interface_detached", identity=b.identity(self.info))
            b.budget.check()
            b.usb_util.claim_interface(self.dev, 0)
            self.claimed = True
            for ep in self.info["interface"]:
                if ep.bmAttributes & 3 == 2:
                    dest = self.ep_in if ep.bEndpointAddress & 0x80 else self.ep_out
                    dest.append(ep.bEndpointAddress)
            if not self.ep_in or not self.ep_out:
                raise ProbeError("interface 0 lacks bulk IN/OUT endpoints")
            b.log("interface_claimed", identity=b.identity(self.info),
                  originally_active=self.was_active)
            return self
        except BaseException:
            self.close()
            raise

    def reset(self):
        if not self.claimed or self.closed:
            raise ProbeError("driver reset called without owned interface")
        self.backend.budget.check()

    def getId(self):
        return VID, self.info["pid"]

    def read(self, length, ep=0, timeout=None):
        if ep != 0:
            raise ProbeError("terminal/secondary endpoint reads forbidden")
        if not 0 < length <= 32768:
            raise ProbeError("unexpected read length")
        if self.wire_phase not in ("auth", "product"):
            raise ProbeError("read outside approved protocol phase")
        data = self.dev.read(self.ep_in[0], length,
                             timeout=self.backend.budget.timeout_ms(timeout))
        raw = bytes(data)
        self.backend.budget.received(len(raw))
        if not raw:
            raise ProbeError("empty USB response; refusing an unbounded loop")
        return raw

    def write(self, data, ep=0):
        if ep != 0 or not 0 < len(data) <= 1024:
            raise ProbeError("unexpected write endpoint or length")
        data = bytes(data)
        if self.wire_phase == "auth":
            if (len(data) != 516 or data[:2] not in (b"\xff\xfe", b"\xff\xfc", b"\xff\xfa")
                    or data[2:4] != b"\0\0"):
                raise ProbeError("unapproved authentication frame")
        elif self.wire_phase == "product":
            allowed = struct.pack("<IHHBBBBHHB", 5, 0x10, 1, 0, 0, 0, 0, 0, 0x1F, 0)
            if self.product_request_sent or data != allowed:
                raise ProbeError("only one exact read-only product request is permitted")
            self.product_request_sent = True
        else:
            raise ProbeError("bulk write outside approved protocol phase")
        n = self.dev.write(self.ep_out[0], data,
                           timeout=self.backend.budget.timeout_ms())
        if n != len(data):
            raise ProbeError("short USB write")

    def vendorRequestOut(self, request, value, index, data=b""):
        if data or (request, value, index) not in (START, STOP):
            raise ProbeError("unapproved vendor request")
        return self.dev.ctrl_transfer(0x43, request, value, index, b"",
                                      timeout=self.backend.budget.timeout_ms())

    def start(self):
        self.backend.log("start_requested", identity=self.backend.identity(self.info))
        try:
            self.vendorRequestOut(*START)
        except Exception as exc:
            # The reference PMCA start() tolerates a failed control-status
            # phase before authenticating. This device returned a PIPE stall.
            # Tolerate ONLY that known status, never a disconnect/access error;
            # the next step must still validate every authentication response.
            if (getattr(exc, "backend_error_code", None) != -9
                    or getattr(exc, "errno", None) not in (None, 32)):
                raise
            self.backend.log("start_status_stall_authentication_required",
                             identity=self.backend.identity(self.info))

    def authenticate(self):
        self.backend.budget.check()
        self.wire_phase = "auth"
        try:
            self.backend.auth_class(self).authenticate()
        finally:
            self.wire_phase = None
        self.backend.log("authentication_complete",
                         identity=self.backend.identity(self.info))

    def product_info(self):
        # Deliberately call exactly one read-only product-info command.
        dev = self.backend.senser_class(self)
        self.wire_phase = "product"
        try:
            data = self.backend.camera_class(dev).readHasp()
        finally:
            self.wire_phase = None
        self.backend.log("product_info_received", bytes=len(data),
                         sha256=hashlib.sha256(data).hexdigest())
        return len(data)

    def stop(self):
        self.backend.log("stop_requested", identity=self.backend.identity(self.info))
        self.vendorRequestOut(*STOP)
        self.backend.log("stop_request_returned",
                         identity=self.backend.identity(self.info))

    def close(self, disconnected=False):
        if self.closed:
            return
        b = self.backend
        # Do not skip resource release/reattach just because a deadline passed.
        if self.claimed:
            try:
                b.usb_util.release_interface(self.dev, 0)
                b.log("interface_released", identity=b.identity(self.info))
            except Exception as exc:
                b.log("release_failed", gone=is_gone(exc), **error_text(exc))
                if not is_gone(exc):
                    self.cleanup_errors.append(error_text(exc))
            self.claimed = False
        if self.detached and disconnected:
            # Re-enumeration created a different USB object. Releasing our old
            # handle is still necessary; attaching an old/new incarnation can
            # race the mode switch or violate libusb's capture accounting.
            b.log("reattach_skipped_disconnected", identity=b.identity(self.info))
            self.detached = False
        elif self.detached:
            try:
                self.dev.attach_kernel_driver(0)
                b.log("interface_reattached", identity=b.identity(self.info))
            except Exception as exc:
                b.log("reattach_failed", gone=is_gone(exc), **error_text(exc))
                if not is_gone(exc):
                    self.cleanup_errors.append(error_text(exc))
            self.detached = False
        try:
            b.usb_util.dispose_resources(self.dev)
        except Exception as exc:
            b.log("dispose_failed", gone=is_gone(exc), **error_text(exc))
            if not is_gone(exc):
                self.cleanup_errors.append(error_text(exc))
        self.closed = True


class UsbBackend:
    def __init__(self, core, util, auth_class, senser_class, camera_class,
                 expected_pid, expected_product, budget=None, usb_backend=None,
                 logger=emit):
        self.usb_core, self.usb_util = core, util
        self.auth_class, self.senser_class, self.camera_class = (
            auth_class, senser_class, camera_class)
        self.expected_pid, self.expected_product = expected_pid, expected_product
        self.budget = budget or Budget()
        self.usb_backend = usb_backend
        self.log = logger
        self.sessions = []
        self.native_bind_wait = 1.5

    @staticmethod
    def identity(info):
        return {"vid": "054c", "pid": f"{info['pid']:04x}",
                "bus": info["bus"], "ports": info["ports"],
                "address": info["address"]}

    @staticmethod
    def instance_key(info):
        return (info["bus"], info["ports"], info["address"], info["pid"])

    def require_known_pid(self, info):
        if info is None or (info["pid"] not in SERVICE_PIDS
                            and info["pid"] != self.expected_pid):
            raise ProbeError("unknown USB PID may only be passively observed")

    @staticmethod
    def cached_device_descriptor(dev):
        # Read only the descriptor values already stored in the enumerated
        # PyUSB object. No GET_DESCRIPTOR / GET_CONFIGURATION, string lookup,
        # active-configuration lookup, or endpoint discovery is done here.
        names = ("bcdUSB", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol",
                 "bMaxPacketSize0", "idVendor", "idProduct", "bcdDevice",
                 "bNumConfigurations")
        cached = vars(dev)
        return {name: cached[name] for name in names
                if isinstance(cached.get(name), int) and 0 <= cached[name] <= 65535}

    def enumerate(self):
        self.budget.check()
        devices = list(self.usb_core.find(find_all=True, idVendor=VID,
                                         backend=self.usb_backend))
        if len(devices) > 1:
            raise ProbeError("multiple Sony USB devices; refusing to select one")
        if not devices:
            return None
        dev = devices[0]
        dev.default_timeout = min(1000, max(1, int(self.budget.remaining() * 1000)))
        ports = tuple(dev.port_numbers or ())
        if dev.bus is None or not ports:
            raise ProbeError("physical USB port identity unavailable")
        info = {"device": dev, "pid": dev.idProduct, "bus": dev.bus,
                "ports": ports, "address": dev.address,
                "interface": None, "class": None}
        if dev.idProduct not in SERVICE_PIDS and dev.idProduct != self.expected_pid:
            # Unknown modes are returned without opening configuration handles.
            # Missing endpoint information is intentional: querying for it can
            # send standard control requests, even without vendor commands.
            info["cached_descriptor"] = self.cached_device_descriptor(dev)
            return info
        # Known modes only; no set_configuration or set_altsetting.
        interface = dev.get_active_configuration()[(0, 0)]
        info.update(interface=interface, **{"class": interface.bInterfaceClass})
        return info

    def check_target(self, info, initial=None, service=False):
        if info is None:
            raise ProbeError("Sony camera not enumerated")
        pid = info["pid"]
        if pid not in SERVICE_PIDS and pid != self.expected_pid:
            raise ProbeError(f"unexpected Sony PID {pid:04x}; refusing")
        if initial and (info["bus"], info["ports"]) != (initial["bus"], initial["ports"]):
            raise ProbeError("USB physical port changed; identity not verified")
        expected_class = SERVICE_CLASS if pid in SERVICE_PIDS else MSC_CLASS
        if info["class"] != expected_class:
            raise ProbeError("unexpected USB interface class; MSC start required")
        if service and pid not in SERVICE_PIDS:
            raise ProbeError("service device required")
        if initial is None:
            if pid in SERVICE_PIDS:
                raise ProbeError("initial device already in service mode; refusing new probe")
            product = self.usb_util.get_string(info["device"], info["device"].iProduct)
            if product != self.expected_product:
                raise ProbeError("USB product string does not match intended camera")
            self.log("target_verified", product=product, identity=self.identity(info))

    def open(self, info):
        self.require_known_pid(info)
        session = ManagedSession(self, info)
        self.sessions.append(session)
        return session.open()

    def wait_service(self, initial, seconds=8.0):
        end = min(time.monotonic() + seconds, self.budget.work_end)
        while time.monotonic() < end:
            info = self.enumerate()
            if info:
                self.check_target(info, initial)
                if info["pid"] in SERVICE_PIDS:
                    self.log("service_enumerated", identity=self.identity(info))
                    return info
            time.sleep(0.15)
        raise ProbeError("service re-enumeration deadline reached")

    def verify_normal_driver(self, info, initial_active):
        dev = info["device"]
        try:
            end = min(time.monotonic() + self.native_bind_wait, self.budget.end)
            while True:
                self.budget.check()
                active = dev.is_kernel_driver_active(0)
                if not initial_active or active:
                    break
                if time.monotonic() >= end:
                    raise ProbeError("normal PID returned but native driver did not bind naturally")
                time.sleep(min(0.1, max(0, end - time.monotonic())))
            # Never attach here: this fresh enumeration handle was not detached
            # by us, so it has no paired libusb capture to release.
            self.log("normal_driver_verified", active=active,
                     initially_active=initial_active)
        finally:
            self.usb_util.dispose_resources(dev)

    def recover(self, initial, initial_active, current):
        self.budget.recovering = True
        self.log("recovery_started", seconds_left=round(self.budget.remaining(), 2))
        attempts = {}
        opened_service_keys = set()
        unknown_deadline = None
        observed_unknown_keys = set()

        def wait_unknown():
            # One absolute window for this entire recovery, including gaps and
            # different unknown PIDs/addresses. Never extend the total budget.
            nonlocal unknown_deadline
            if unknown_deadline is None:
                unknown_deadline = min(time.monotonic() + UNKNOWN_OBSERVATION_SECONDS,
                                       self.budget.end)
            remaining = min(unknown_deadline, self.budget.end) - time.monotonic()
            if remaining <= 0:
                self.log("normal_mode_not_verified", reason="unknown-mode observation deadline")
                return False
            time.sleep(min(0.15, remaining))
            return True

        def request_stop(session):
            key = self.instance_key(session.info)
            count = attempts.get(key, (0, 0))[0]
            if count >= 2 or sum(value[0] for value in attempts.values()) >= 4:
                return
            attempts[key] = (count + 1, time.monotonic())
            try:
                session.stop()
            except Exception as exc:
                self.log("stop_failed", gone=is_gone(exc), **error_text(exc))

        try:
            # Enumerate BEFORE deciding whether any previous handle is still
            # the same known instance. A failed auth may have re-enumerated to
            # an unknown mode, which must receive no Stop or other commands.
            while self.budget.remaining() > 0.2:
                info = self.enumerate()
                if current and not current.closed and (
                        info is None or self.instance_key(info) != self.instance_key(current.info)):
                    current.close(disconnected=True)
                    current = None
                if info is None:
                    if unknown_deadline is not None:
                        if not wait_unknown():
                            return False
                    else:
                        time.sleep(min(0.15, max(0, self.budget.remaining())))
                    continue
                if (info["bus"], info["ports"]) != (initial["bus"], initial["ports"]):
                    raise ProbeError("USB physical port changed; identity not verified")
                if info["pid"] not in SERVICE_PIDS and info["pid"] != self.expected_pid:
                    key = self.instance_key(info)
                    if key not in observed_unknown_keys:
                        observed_unknown_keys.add(key)
                        self.log("unknown_mode_observed", identity=self.identity(info),
                                 cached_descriptor=info.get("cached_descriptor", {}))
                    if not wait_unknown():
                        return False
                    continue
                self.check_target(info, initial)
                if info["pid"] == self.expected_pid:
                    if current and not current.closed:
                        key = self.instance_key(info)
                        if key not in attempts:
                            # The original known MSC instance may have accepted
                            # part of Start/auth without changing descriptors.
                            # Stop only after its identity was freshly checked,
                            # and re-enumerate once more before verifying normal.
                            request_stop(current)
                            time.sleep(min(0.15, max(0, self.budget.remaining())))
                            continue
                        # A failed Start may have left the same MSC instance
                        # captured. Only this exact instance has a valid pair.
                        current.close()
                        current = None
                    self.verify_normal_driver(info, initial_active)
                    self.log("normal_mode_verified", identity=self.identity(info))
                    return True
                key = self.instance_key(info)
                if current is None or current.closed:
                    if key not in opened_service_keys and len(opened_service_keys) >= 2:
                        raise ProbeError("recovery service-device attempt limit reached")
                    opened_service_keys.add(key)
                    current = self.open(info)
                    request_stop(current)
                else:
                    count, last = attempts.get(key, (0, 0))
                    if count == 0 or (count < 2 and time.monotonic() - last >= 0.75):
                        request_stop(current)
                time.sleep(0.15)
            self.log("normal_mode_not_verified", reason="recovery deadline")
            return False
        except Exception as exc:
            self.log("recovery_verification_failed", **error_text(exc))
            # An unknown/multiple device must never be operated on.
            return False
        finally:
            if current and not current.closed:
                # No transition was confirmed: best-effort release and the
                # matching reattach on our own captured handle only.
                current.close()


def run_probe(backend):
    """Injectable orchestration. Returns (exit_code, structured summary)."""
    initial = current = None
    initial_active = None
    changed = False
    restored = False
    product_bytes = None
    failure = None
    try:
        initial = backend.enumerate()
        backend.check_target(initial)
        current = backend.open(initial)
        initial_active = current.was_active
        changed = True  # Even a failed start may have changed the device mode.
        current.start()
        current.authenticate()
        service = backend.wait_service(initial)
        current.close(disconnected=True)
        current = None
        current = backend.open(service)
        current.start()
        current.authenticate()
        product_bytes = current.product_info()
    except BaseException as exc:
        failure = error_text(exc)
        backend.log("probe_failed", **failure)
    finally:
        if changed:
            try:
                restored = backend.recover(initial, initial_active, current)
            except BaseException as exc:
                backend.log("recovery_aborted", **error_text(exc))
        # Covers failures during open/claim as well as interrupted recovery.
        for session in backend.sessions:
            session.close()
    cleanup_errors = [e for s in backend.sessions for e in s.cleanup_errors]
    summary = {"product_info_ok": product_bytes is not None,
               "product_bytes": product_bytes,
               "mode_change_attempted": changed,
               "normal_mode_and_driver_verified": restored,
               "failure": failure, "cleanup_errors": cleanup_errors,
               "elapsed_seconds": round(time.monotonic() - backend.budget.started, 3),
               "usb_transfer_calls": backend.budget.calls,
               "response_bytes": backend.budget.rx_bytes}
    backend.log("probe_summary", **summary)
    code = (0 if product_bytes is not None and restored and not cleanup_errors
            else 3 if changed and not restored else 2)
    return code, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--msc-pid", "--expected-msc-pid", dest="expected_msc_pid",
                        type=lambda s: int(s, 16))
    parser.add_argument("--expected-product", default="ILCE-7CM2")
    parser.add_argument("--msc-volumes-unmounted", action="store_true")
    parser.add_argument("--pmca-path", type=Path, default=None,
                        help="Optional source path; omit when dependencies are preloaded")
    parser.add_argument("--libusb", type=Path, help="Optional absolute libusb shared-library path")
    args = parser.parse_args(argv)
    if not args.execute:
        emit("offline_plan", requires=["verified actual MSC PID", "single ILCE-7CM2",
                                       "camera storage volumes safely unmounted"],
             steps=["capture MSC interface", "start/auth", "re-enumerate service",
                    "start/auth", "read product info", "finally stop/release/reattach",
                    "fresh enumeration verifies original MSC PID/native-driver state"],
             limits={"total_seconds": 45, "recovery_reserved_seconds": 17,
                     "transfer_timeout_ms": 1000,
                     "unknown_observation_seconds": UNKNOWN_OBSERVATION_SECONDS}, hardware_access=False)
        return 0
    if (args.expected_msc_pid is None or not 0 <= args.expected_msc_pid <= 0xFFFF or
            args.expected_msc_pid in SERVICE_PIDS or args.expected_msc_pid == KNOWN_MTP_PID):
        parser.error("provide the actually observed MSC PID; MTP/service PIDs are rejected")
    if not args.msc_volumes_unmounted:
        parser.error("operator must first verify and safely unmount the camera's MSC volumes")
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
            raise ProbeError("explicit libusb library could not be loaded")
    backend = UsbBackend(usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
                         SonySenserCamera, args.expected_msc_pid, args.expected_product,
                         usb_backend=explicit_backend)
    return run_probe(backend)[0]


if __name__ == "__main__":
    sys.exit(main())
