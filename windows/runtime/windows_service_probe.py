#!/usr/bin/env python3
"""Bounded A7C II service ProductInfo probe using WinUSB on Windows.

This reads only ProductInfo. It requires a separately installed WinUSB driver
for both 054c:0e8a and 054c:0336, and never changes a driver or card file.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as original
import windows_libusb


def windows_devices():
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$d=@(Get-CimInstance Win32_PnPEntity | Where-Object {
    $_.PNPDeviceID -match '^USB\\VID_054C&PID_(0E8A|0336|096F)\\'
} | ForEach-Object {
    [pscustomobject]@{id=$_.PNPDeviceID; service=$_.Service; status=$_.Status}
})
$disks=@(Get-CimInstance Win32_DiskDrive | Where-Object {
    $_.PNPDeviceID -match '^USBSTOR\\DISK&VEN_SONY&PROD_DSC&'
} | ForEach-Object { $_.PNPDeviceID })
[pscustomobject]@{devices=$d; disks=$disks} | ConvertTo-Json -Depth 4 -Compress
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                             "-Command", script], capture_output=True, timeout=30)
    if result.returncode:
        raise original.ProbeError("Windows device inventory failed")
    return json.loads(result.stdout.decode("utf-8"))


def require_winusb(serial):
    inventory = windows_devices()
    expected = "USB\\VID_054C&PID_0E8A\\" + serial.upper()
    active = [item for item in inventory["devices"]
              if item["id"].upper() == expected]
    if (len(active) != 1 or active[0]["status"] != "OK" or
            str(active[0]["service"]).lower() != "winusb"):
        raise original.ProbeError("target 0e8a must be present and bound to WinUSB")
    if any(serial.upper() in disk.upper() for disk in inventory["disks"]):
        raise original.ProbeError("camera storage disks remain present")
    return inventory


class WindowsSession(original.ManagedSession):
    def open(self):
        backend = self.backend
        backend.require_known_pid(self.info)
        try:
            backend.budget.check()
            # Windows libusb cannot detach a kernel driver. The exact WinUSB
            # binding is checked by PnP before the first camera transfer.
            self.was_active = False
            backend.usb_util.claim_interface(self.dev, 0)
            self.claimed = True
            for ep in self.info["interface"]:
                if ep.bmAttributes & 3 == 2:
                    (self.ep_in if ep.bEndpointAddress & 0x80 else
                     self.ep_out).append(ep.bEndpointAddress)
            if not self.ep_in or not self.ep_out:
                raise original.ProbeError("interface 0 lacks bulk IN/OUT endpoints")
            backend.log("winusb_interface_claimed", identity=backend.identity(self.info))
            return self
        except BaseException:
            self.close()
            raise


class WindowsBackend(original.UsbBackend):
    def __init__(self, *args, serial, **kwargs):
        super().__init__(*args, **kwargs)
        self.serial = serial
        self.transitioning = False
        self.initial_address = None

    def check_target(self, info, initial=None, service=False):
        super().check_target(info, initial, service)
        if initial is None:
            self.initial_address = info["address"]

    def wait_service(self, initial, seconds=8.0):
        self.transitioning = True
        try:
            return super().wait_service(initial, seconds)
        finally:
            self.transitioning = False

    def open(self, info):
        self.require_known_pid(info)
        session = WindowsSession(self, info)
        self.sessions.append(session)
        return session.open()

    def enumerate(self):
        if self.budget.recovering:
            devices = list(self.usb_core.find(find_all=True, idVendor=original.VID,
                                              backend=self.usb_backend))
            if len(devices) > 1:
                raise original.ProbeError("multiple Sony USB devices during recovery")
            if devices and devices[0].idProduct == self.expected_pid:
                dev = devices[0]
                ports = tuple(dev.port_numbers or ())
                if dev.bus is None or not ports:
                    raise original.ProbeError("normal USB port identity unavailable")
                # Descriptor reads through the old libusb process can return
                # ACCESS after a Windows WinUSB rebind. The fresh PID/address,
                # port and PnP binding are checked here; a new process checks
                # the active interface descriptor before success is reported.
                return {"device": dev, "pid": dev.idProduct, "bus": dev.bus,
                        "ports": ports, "address": dev.address,
                        "interface": None, "class": original.MSC_CLASS}
        try:
            return super().enumerate()
        except Exception as exc:
            # Windows can invalidate a descriptor handle between libusb's
            # device list and configuration query during a PID change.
            binding = ((getattr(exc, "backend_error_code", None) == -3 or
                        isinstance(exc, NotImplementedError)) and
                       (self.transitioning or self.budget.recovering))
            if not original.is_gone(exc) and not binding:
                raise
            self.log("reenumeration_in_progress", error_type=type(exc).__name__,
                     driver_binding=binding)
            return None

    def verify_normal_driver(self, info, initial_active):
        deadline = min(time.monotonic() + 20, self.budget.end)
        last_error = "normal WinUSB binding not yet visible"
        while time.monotonic() < deadline:
            if info is not None and info["address"] != self.initial_address:
                try:
                    require_winusb(self.serial)
                except original.ProbeError as exc:
                    last_error = str(exc)
                else:
                    self.log("normal_winusb_verified", serial=self.serial,
                             address=info["address"])
                    return
            time.sleep(0.15)
            info = self.enumerate()
            if info is None:
                continue
        raise original.ProbeError("fresh normal WinUSB instance not verified: " +
                                  last_error)


def verify_normal_in_new_process(serial, old_address):
    deadline = time.monotonic() + 20
    while True:
        try:
            require_winusb(serial)
            break
        except original.ProbeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    code = ("import sys,time,usb.core\n"
            "old=int(sys.argv[1])\n"
            "sys.path.insert(0,sys.argv[2])\n"
            "import windows_libusb\n"
            "backend=windows_libusb.get_backend()\n"
            "for _ in range(80):\n"
            " d=list(usb.core.find(find_all=True,idVendor=0x054c,backend=backend))\n"
            " if len(d)==1 and d[0].idProduct==0x0e8a and d[0].address!=old:\n"
            "  try:\n"
            "   if d[0].get_active_configuration()[(0,0)].bInterfaceClass==8:\n"
            "    sys.exit(0)\n"
            "  except Exception: pass\n"
            " time.sleep(0.2)\n"
            "sys.exit(3)\n")
    result = subprocess.run([sys.executable, "-c", code, str(old_address), str(ROOT)],
                            timeout=22, capture_output=True)
    if result.returncode:
        raise original.ProbeError("new process could not verify restored MSC interface")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Windows required")
    if not re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial):
        parser.error("12 hex digit camera USB serial required")
    if not args.execute:
        print(json.dumps({"camera_access": False, "serial": args.serial,
                          "normal_driver": windows_devices()}), flush=True)
        return 0
    require_winusb(args.serial)
    if not args.child:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                 "--serial", args.serial, "--execute", "--child"],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=70)
        print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="", flush=True)
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events if item.get("event") == "target_verified"), None)
        summary = next((item for item in reversed(events)
                        if item.get("event") == "probe_summary"), None)
        if target is None or summary is None:
            raise original.ProbeError("child probe did not return a complete receipt")
        if (not summary.get("product_info_ok") or summary.get("failure") or
                summary.get("cleanup_errors")):
            raise original.ProbeError("service ProductInfo or cleanup did not verify")
        verify_normal_in_new_process(args.serial, target["identity"]["address"])
        original.emit("postflight_normal_interface_verified", serial=args.serial)
        return 0
    import usb.core
    import usb.util
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    backend = WindowsBackend(usb.core, usb.util, SonySenserAuthDevice,
                             SonySenserDevice, SonySenserCamera,
                             0x0e8a, "ILCE-7CM2", serial=args.serial,
                             usb_backend=windows_libusb.get_backend())
    return original.run_probe(backend)[0]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            original.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
