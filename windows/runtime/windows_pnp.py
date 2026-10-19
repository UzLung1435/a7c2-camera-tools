#!/usr/bin/env python3
"""Direct configuration-manager reads for the camera's USB and storage nodes.

The workflow steps used to ask PowerShell/WMI for device state. On the A7C II
test host a single Get-PnpDevice call took ~10 s and a disk-class query 25-45 s,
because the two camera LUNs make the disk classes block until they time out.
That broke two things at once: step timeouts fired during driver-store churn,
and a recovery poll loop could not be run more often than once every ten
seconds, which is far slower than the re-enumeration it is supposed to observe.

The registry keeps the same information the WMI classes project, and the
configuration manager answers in about a millisecond without starting a
process, so every binding decision is made here instead.

Only presence, problem state, service/driver binding and the storage
enumeration are read. Nothing is written and no device is opened.
"""

import ctypes
from ctypes import wintypes
import os
import winreg

VID = "054C"
ENUM_ROOT = r"SYSTEM\CurrentControlSet\Enum"

# CM_Get_DevNode_Status status bits (cfgmgr32.h / cfg.h). There is no
# "present" bit: CM_Locate_DevNode with CM_LOCATE_DEVNODE_NORMAL only finds
# live devnodes and returns CR_NO_SUCH_DEVNODE (13) for a node whose device is
# gone, which is what the two 054C service nodes report once the camera leaves
# service mode. Bit 0 is DN_ROOT_ENUMERATED, not presence.
DN_HAS_PROBLEM = 0x00000400
DN_STARTED = 0x00000008
CR_SUCCESS = 0
CM_LOCATE_DEVNODE_NORMAL = 0

_cm = None
if os.name == "nt":
    _cm = ctypes.WinDLL("cfgmgr32")
    _cm.CM_Locate_DevNodeW.argtypes = [ctypes.POINTER(wintypes.ULONG),
                                       wintypes.LPCWSTR, wintypes.ULONG]
    _cm.CM_Locate_DevNodeW.restype = wintypes.ULONG
    _cm.CM_Get_DevNode_Status.argtypes = [ctypes.POINTER(wintypes.ULONG),
                                          ctypes.POINTER(wintypes.ULONG),
                                          wintypes.ULONG, wintypes.ULONG]
    _cm.CM_Get_DevNode_Status.restype = wintypes.ULONG


def instance_id(pid, serial):
    """PnP instance of one camera node, e.g. USB\\VID_054C&PID_0E8A\\<serial>."""
    return "USB\\VID_" + VID + "&PID_" + pid.upper() + "\\" + serial.upper()


def _enum_key_path(instance):
    return ENUM_ROOT + "\\" + instance


def _values(instance):
    """Service/Driver/ConfigFlags of an enum instance, or {} when unreadable."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _enum_key_path(instance))
    except OSError:
        return {}
    result = {}
    try:
        for name in ("Service", "Driver", "DeviceDesc", "FriendlyName"):
            try:
                result[name.lower()] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                pass
        try:
            result["config_flags"] = int(winreg.QueryValueEx(key, "ConfigFlags")[0])
        except OSError:
            pass
    finally:
        key.Close()
    return result


def node(instance):
    """State of one live PnP node, or None when the device is not present.

    A devnode only resolves while its device is attached, so None is the
    authoritative "not present" answer even though the registry key survives
    an unplug. ``problem`` is the CM_PROB number, 0 when healthy.
    """
    if _cm is None:
        return None
    devinst = wintypes.ULONG()
    if _cm.CM_Locate_DevNodeW(ctypes.byref(devinst), instance,
                              CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS:
        return None
    status = wintypes.ULONG()
    problem = wintypes.ULONG()
    if _cm.CM_Get_DevNode_Status(ctypes.byref(status), ctypes.byref(problem),
                                 devinst.value, 0) != CR_SUCCESS:
        return None
    values = _values(instance)
    return {"instance": instance,
            "present": True,
            "started": bool(status.value & DN_STARTED),
            "problem": problem.value,
            "has_problem": bool(status.value & DN_HAS_PROBLEM),
            "service": values.get("service"),
            "driver": values.get("driver"),
            "config_flags": values.get("config_flags")}


def healthy(node_value):
    """Present, started, and no problem code reported by the config manager."""
    return bool(node_value and node_value["present"] and
                node_value["started"] and
                not node_value["has_problem"] and node_value["problem"] == 0)


def storage_instances(serial):
    """Present USBSTOR instances carrying this serial, e.g. '<serial>&0'.

    Registry entries survive unplugging, so presence is decided by the
    configuration manager, not by the key existing.
    """
    found = []
    needle = serial.upper()
    try:
        store = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               ENUM_ROOT + "\\USBSTOR")
    except OSError:
        return found
    try:
        for index in range(winreg.QueryInfoKey(store)[0]):
            try:
                class_name = winreg.EnumKey(store, index)
                class_key = winreg.OpenKey(store, class_name)
            except OSError:
                continue
            try:
                for inner in range(winreg.QueryInfoKey(class_key)[0]):
                    try:
                        instance = winreg.EnumKey(class_key, inner)
                    except OSError:
                        continue
                    if needle not in instance.upper():
                        continue
                    full = "USBSTOR\\" + class_name + "\\" + instance
                    state = node(full)
                    if state and state["present"]:
                        found.append(full)
            finally:
                class_key.Close()
    finally:
        store.Close()
    return found
