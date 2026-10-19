"""Windows WinUSB bindings for the existing bounded Sony service sessions.

The Windows-specific recovery behaviour lives in windows_service_probe and is
bound into whichever backend a step uses. It used to be duplicated here, and
the copy kept the obsolete "the USB address must change" restore test alive in
every child process while the module's own copy had already been fixed: the
p1 capture child therefore reported "normal WinUSB postflight timed out" on a
camera that had restored correctly. One implementation, one place.
"""

import types

import service_probe as base
from windows_service_probe import (WindowsSession, recovery_enumerate,
                                   require_winusb, windows_verify_normal,
                                   windows_wait_service)


def install(backend, serial):
    require_winusb(serial)
    # Only this child process is modified. Its parent verifies normal mode
    # after every libusb handle has been closed by process exit.
    base.ManagedSession.open = WindowsSession.open
    backend.windows_serial = serial
    backend.windows_transitioning = False
    backend.windows_initial_address = None
    native_check = backend.check_target

    def check(self, info, initial=None, service=False):
        # Keeps the backend's own target rules (service PID, product string)
        # and only records the starting address for diagnostics.
        native_check(info, initial, service)
        if initial is None:
            self.windows_initial_address = info["address"]

    backend.check_target = types.MethodType(check, backend)
    backend.wait_service = types.MethodType(windows_wait_service, backend)
    backend.enumerate = types.MethodType(recovery_enumerate, backend)
    backend.verify_normal_driver = types.MethodType(windows_verify_normal,
                                                    backend)
    return backend
