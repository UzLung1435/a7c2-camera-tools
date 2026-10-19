#!/usr/bin/env python3
"""Guarded, read-only Backup.bin/.bak snapshot on an ILCE-7CM2 in MSC mode.

Use --probe-json from mac_probe_fl23.py. Without --execute this only prints
preflight status. With --execute it switches Sony USB service mode, reads two
fixed camera paths, restores normal mode, and writes private host snapshots.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import mac_probe_fl23 as probe


def require(condition, message):
    if not condition:
        raise ValueError(message)


def report_identity(report):
    require(report.get("read_only") is True and report.get("format") == 1,
            "unrecognized first-stage diagnostic")
    sony = [x for x in report.get("usb", {}).get("sony_devices", [])
            if x.get("source") == "ioreg"]
    require(len(sony) == 1, "diagnostic must show exactly one IORegistry Sony device")
    camera = sony[0]
    require(camera.get("vendor_id", "").lower() == "0x054c" and
            camera.get("product_id", "").lower() == "0x0e8a" and
            camera.get("name") == "ILCE-7CM2",
            "diagnostic is not ILCE-7CM2 MSC 054c:0e8a")
    require(camera.get("serial_num"), "camera USB serial is absent")
    entries = []
    for disk in report.get("volumes", {}).get("external_disks", []):
        for part in disk.get("partitions", []):
            entries.append((disk.get("disk", {}), part))
    card = [(disk, part) for disk, part in entries
            if part.get("FilesystemName") == "ExFAT" and
            part.get("VolumeName") != "PMHOME" and part.get("VolumeUUID")]
    pmhome = [(disk, part) for disk, part in entries
              if part.get("VolumeName") == "PMHOME" and
              part.get("VolumeUUID") and disk.get("Writable") is False]
    require(len(card) == len(pmhome) == 1, "card/PMHOME volume identity ambiguous")
    return camera, card[0], pmhome[0]


def live_preflight(camera, card, pmhome):
    registry = probe.usb_registry_inventory()
    live_sony = registry.get("sony_devices", [])
    require(len(live_sony) == 1, "one Sony USB device must remain connected")
    live_camera = live_sony[0]
    for field in ("vendor_id", "product_id", "serial_num", "name"):
        require(live_camera.get(field) == camera.get(field),
                "camera USB identity changed: " + field)
    volumes = probe.volume_inventory()
    require(not volumes.get("error"), "diskutil volume inventory failed")
    live_disks = volumes.get("external_disks", [])
    matched_parts = []
    for expected_disk, expected_part in (card, pmhome):
        same = []
        for item in live_disks:
            disk = item.get("disk", {})
            if (disk.get("TotalSize") != expected_disk.get("TotalSize") or
                    disk.get("BusProtocol") != "USB" or
                    disk.get("Internal") is not False or
                    disk.get("RemovableMedia") is not True or
                    disk.get("Writable") != expected_disk.get("Writable") or
                    disk.get("MediaName") != expected_disk.get("MediaName")):
                continue
            for part in item.get("partitions", []):
                if (part.get("FilesystemName") == expected_part.get("FilesystemName") and
                        part.get("VolumeName") == expected_part.get("VolumeName") and
                        part.get("VolumeUUID") == expected_part.get("VolumeUUID") and
                        part.get("DeviceIdentifier")):
                    same.append(part)
        require(len(same) == 1, "camera volume UUID or physical capacity changed")
        matched_parts.append(same[0])
    raw_mounts, error = probe.run(["mount"], timeout=10)
    require(not error, "cannot verify host mount table")
    mounts = raw_mounts.decode("utf-8", "replace")
    return [part for part in matched_parts
            if f"/dev/{part['DeviceIdentifier']} on " in mounts]


def ensure_camera_volumes_unmounted(camera, card, pmhome):
    """Wait for stable MSC topology and unmount only the identified volumes."""
    for _ in range(4):
        mounted = wait_for_camera_volumes(camera, card, pmhome)
        if not mounted:
            return
        identifier = mounted[0]["DeviceIdentifier"]
        require(re.fullmatch(r"disk[0-9]+s[0-9]+", identifier) is not None,
                "unexpected camera partition identifier")
        result = subprocess.run(["diskutil", "unmount", identifier],
                                capture_output=True, text=True, timeout=30)
        require(result.returncode == 0,
                f"diskutil unmount {identifier} failed: {result.stderr.strip()[:200]}")
    require(not wait_for_camera_volumes(camera, card, pmhome),
            "camera volumes were remounted after repeated safe unmount attempts")


def wait_for_camera_volumes(camera, card, pmhome, timeout_seconds=90):
    """Require two matching observations after USB/disk arbitration settles."""
    started = time.monotonic()
    deadline = started + timeout_seconds
    previous = None
    last_error = "not yet observed"
    next_notice = started + 10
    while True:
        try:
            mounted = live_preflight(camera, card, pmhome)
            signature = tuple(sorted(part["DeviceIdentifier"] for part in mounted))
            if signature == previous:
                return mounted
            previous = signature
        except (OSError, ValueError) as exc:
            previous = None
            last_error = str(exc)
        now = time.monotonic()
        if now >= deadline:
            raise ValueError("camera MSC topology did not settle: " + last_error)
        if now >= next_notice:
            print("waiting_for_camera_msc_volumes:", int(now - started), "s", flush=True)
            next_notice = now + 10
        time.sleep(min(0.8, deadline - now))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-json", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "snapshots")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS required")
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = report_identity(report)
    if args.execute:
        ensure_camera_volumes_unmounted(camera, card, pmhome)
        current = []
    else:
        current = live_preflight(camera, card, pmhome)
    if current:
        print("unmount_required:")
        for part in current:
            print("  diskutil unmount", part["DeviceIdentifier"])
        print("rerun after both camera volumes are unmounted; do not eject USB")
        return 1
    libusb = probe.dependencies().get("libusb_library")
    require(libusb and Path(libusb).is_file(), "libusb-1.0.dylib unavailable")
    require(importlib.util.find_spec("usb") is not None,
            "PyUSB unavailable in this Python; install it in a virtual environment")
    require(importlib.util.find_spec("Cryptodome") is not None,
            "pycryptodomex unavailable in this Python")
    require((ROOT / "pmca" / "usb" / "sony.py").is_file(), "bundled PMCA module missing")
    print("preflight: ILCE-7CM2 054c:0e8a, same serial and two volume UUIDs, both unmounted")
    if not args.execute:
        print("camera_access: false; pass --execute to read only Backup.bin/.bak")
        return 0
    out_dir = args.out_dir.resolve()
    require(not out_dir.exists() or not any(out_dir.glob("a7c2-readonly-backup_*.bin")),
            "snapshot directory already contains backup files; review them before another run")
    child = ROOT / "sony-service-research" / "cp_backup_color_snapshot_ro_205.py"
    command = [sys.executable, str(child), "--execute",
               "--msc-volumes-unmounted", "--card-and-pmhome-verified",
               "--msc-pid", "0x0e8a", "--pmca-path", str(ROOT),
               "--libusb", str(libusb), "--out-dir", str(out_dir)]
    print("reading two fixed backup paths; camera service mode will be restored", flush=True)
    status = subprocess.call(command)
    if status:
        return status
    backup_bin = list(out_dir.glob("a7c2-readonly-backup_bin-*.bin"))
    backup_bak = list(out_dir.glob("a7c2-readonly-backup_bak-*.bin"))
    require(len(backup_bin) == len(backup_bak) == 1,
            "expected exactly one readback file for each backup")
    diagnostic = out_dir / "backup-diagnostic.json"
    print("analyzing the two saved BK4 files locally", flush=True)
    return subprocess.call([sys.executable, str(ROOT / "mac_probe_fl23.py"),
                            "--backup-bin", str(backup_bin[0]),
                            "--backup-bak", str(backup_bak[0]),
                            "--out", str(diagnostic)])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
