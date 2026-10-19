#!/usr/bin/env python3
"""Read-only diagnosis of the post-recovery MSC verification on Windows.

This never claims interface 0, never sends a vendor request, and never
changes a driver. It only reports what the two verification paths in
windows_service_probe.py can actually see, so a failure of

    new process could not verify restored MSC interface

can be attributed to one concrete condition.

Usage:
    python windows_verify_diag.py --serial D11D0075B240 --old-address 5
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))

import windows_libusb

PID_NORMAL = 0x0E8A
PID_SERVICE = 0x0336
PID_INTERMEDIATE = 0x096F


def pnp_devices(serial):
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$rows=@()
foreach($d in @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like 'USB\VID_054C*' })){
    $arr=$null
    try { $arr=(Get-PnpDeviceProperty -InstanceId $d.InstanceId `
            -KeyName 'DEVPKEY_Device_LastArrivalDate' -ErrorAction Stop).Data } catch {}
    $rows += [pscustomobject]@{
        id=$d.InstanceId; status=[string]$d.Status; service=[string]$d.Service
        class=[string]$d.Class; name=[string]$d.FriendlyName
        arrival=$(if($arr){$arr.ToString('o')}else{$null})}
}
[pscustomobject]@{devices=$rows} | ConvertTo-Json -Depth 4 -Compress
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                             "-Command", script], capture_output=True, timeout=60)
    if result.returncode:
        return {"error": result.stderr.decode("utf-8", "replace")[-400:]}
    raw = result.stdout.decode("utf-8", "replace").strip()
    if not raw:
        return {"devices": []}
    data = json.loads(raw)
    devices = data.get("devices") or []
    if isinstance(devices, dict):
        devices = [devices]
    return {"devices": devices}


def libusb_view():
    backend = windows_libusb.get_backend()
    import usb.core
    found = []
    for dev in usb.core.find(find_all=True, idVendor=0x054C, backend=backend):
        entry = {"pid": f"{dev.idProduct:04x}", "bus": dev.bus,
                 "address": dev.address, "ports": list(dev.port_numbers or ()),
                 "interface_class": None, "error": None}
        try:
            entry["interface_class"] = dev.get_active_configuration()[(0, 0)].bInterfaceClass
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        found.append(entry)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--old-address", type=int, required=True,
                        help="USB address captured before the mode switch")
    args = parser.parse_args()

    pnp = pnp_devices(args.serial.upper())
    devices = libusb_view()

    normal = [d for d in devices if d["pid"] == "0e8a"]
    checks = {
        "libusb_sees_exactly_one_sony": len(devices) == 1,
        "libusb_pid_is_0e8a": bool(normal),
        "libusb_address_differs_from_old":
            bool(normal) and normal[0]["address"] != args.old_address,
        "libusb_interface_class_is_8":
            bool(normal) and normal[0]["interface_class"] == 8,
    }

    pnp_normal = [d for d in pnp.get("devices", [])
                  if "PID_0E8A" in str(d.get("id", "")).upper()
                  and args.serial.upper() in str(d.get("id", "")).upper()]
    report = {
        "serial": args.serial.upper(),
        "old_address": args.old_address,
        "pnp_normal_nodes": pnp_normal,
        "pnp_all_sony": pnp.get("devices", []),
        "libusb_devices": devices,
        "checks_used_by_verify_normal_in_new_process": checks,
        "verdict": ("all conditions pass" if all(checks.values())
                    else "child process would exit 3: " +
                    ", ".join(k for k, v in checks.items() if not v)),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
