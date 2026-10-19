"""Windows WinUSB bindings for the existing bounded Sony service sessions."""

import types
import time

from windows_service_probe import WindowsSession, require_winusb
import service_probe as base


_native_enumerate = base.UsbBackend.enumerate


def install(backend, serial):
    require_winusb(serial)
    # Only this child process is modified. Its parent verifies normal mode
    # after every libusb handle has been closed by process exit.
    base.ManagedSession.open = WindowsSession.open
    backend.windows_serial = serial
    backend.windows_transitioning = False
    backend.windows_initial_address = None
    native_check = backend.check_target
    native_wait = backend.wait_service

    def check(self, info, initial=None, service=False):
        native_check(info, initial, service)
        if initial is None:
            self.windows_initial_address = info["address"]

    def wait(self, initial, seconds=8.0):
        self.windows_transitioning = True
        try:
            return native_wait(initial, max(seconds, 15.0))
        finally:
            self.windows_transitioning = False

    def enumerate(self):
        if self.budget.recovering:
            devices = list(self.usb_core.find(find_all=True, idVendor=base.VID,
                                              backend=self.usb_backend))
            if len(devices) > 1:
                raise base.ProbeError("multiple Sony USB devices")
            if devices and devices[0].idProduct == self.expected_pid:
                dev = devices[0]
                ports = tuple(dev.port_numbers or ())
                if dev.bus is None or not ports:
                    raise base.ProbeError("normal USB port identity unavailable")
                return {"device": dev, "pid": dev.idProduct, "bus": dev.bus,
                        "ports": ports, "address": dev.address,
                        "interface": None, "class": base.MSC_CLASS}
        try:
            return _native_enumerate(self)
        except Exception as exc:
            binding = ((getattr(exc, "backend_error_code", None) == -3 or
                        isinstance(exc, NotImplementedError)) and
                       (self.windows_transitioning or self.budget.recovering))
            if not base.is_gone(exc) and not binding:
                raise
            return None

    def verify_normal_driver(self, info, initial_active):
        deadline = min(time.monotonic() + 20, self.budget.end)
        last_error = "normal WinUSB binding not yet visible"
        while time.monotonic() < deadline:
            if info is not None and info["pid"] == self.expected_pid:
                if info["address"] != self.windows_initial_address:
                    try:
                        require_winusb(self.windows_serial)
                    except base.ProbeError as exc:
                        last_error = str(exc)
                    else:
                        self.log("normal_winusb_verified",
                                 serial=self.windows_serial,
                                 address=info["address"])
                        return
            time.sleep(0.2)
            info = self.enumerate()
        raise base.ProbeError("normal WinUSB postflight timed out: " + last_error)

    backend.check_target = types.MethodType(check, backend)
    backend.wait_service = types.MethodType(wait, backend)
    backend.enumerate = types.MethodType(enumerate, backend)
    backend.verify_normal_driver = types.MethodType(verify_normal_driver, backend)
    return backend
