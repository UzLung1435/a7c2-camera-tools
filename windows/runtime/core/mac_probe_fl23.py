#!/usr/bin/env python3
"""Read-only A7C II USB, volume, p1 and BK4 inventory for macOS.

Default mode only runs system_profiler and diskutil. Optional --p1 and --backup-*
inputs are previously exported files; this script never writes to the camera.
"""

import argparse
import ctypes.util
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys
import zlib
import color_property_200 as color

PROPERTY_ID = 0x02A40001
PROPERTY_201_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"
PROPERTY_FL23_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(command, timeout=45):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if result.returncode:
        return None, result.stderr.decode("utf-8", "replace")[:400].strip() or f"exit {result.returncode}"
    return result.stdout, None


def usb_inventory():
    raw, error = run(["system_profiler", "SPUSBDataType", "-json"], timeout=70)
    if error:
        return {"system_profiler_error": error, **usb_registry_inventory()}
    try:
        tree = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return {"system_profiler_error": f"invalid system_profiler JSON: {exc}",
                **usb_registry_inventory()}
    found = []

    def walk(value, parents):
        if isinstance(value, list):
            for item in value:
                walk(item, parents)
        elif isinstance(value, dict):
            name = str(value.get("_name", ""))
            vendor_raw = value.get("vendor_id", "")
            vendor = str(vendor_raw)
            product = str(value.get("product_id", ""))
            text = " ".join((name, vendor, str(value.get("manufacturer", ""))))
            if (vendor_raw == 0x054c or "0x054c" in vendor.lower() or
                    "0x54c" in vendor.lower() or
                    re.search(r"sony|\bilce[- ]", text, re.I)):
                found.append({"path": parents + [name], "name": name,
                              "vendor_id": vendor, "product_id": product,
                              "manufacturer": value.get("manufacturer"),
                              "serial_num": value.get("serial_num"),
                              "location_id": value.get("location_id"),
                              "speed": value.get("device_speed")})
            for key, child in value.items():
                if key == "_items":
                    walk(child, parents + ([name] if name else []))

    walk(tree.get("SPUSBDataType", []), [])
    registry = usb_registry_inventory()
    found.extend(registry.pop("sony_devices", []))
    return {"sony_devices": found, "system_profiler_matches": len(found) -
            registry.get("ioreg_matches", 0), **registry}


def usb_registry_inventory():
    raw, error = run(["ioreg", "-a", "-r", "-c", "IOUSBHostDevice"], timeout=30)
    if error:
        return {"ioreg_error": error, "sony_devices": [], "ioreg_matches": 0}
    try:
        roots = plistlib.loads(raw)
    except (ValueError, TypeError) as exc:
        return {"ioreg_error": f"invalid IORegistry plist: {exc}",
                "sony_devices": [], "ioreg_matches": 0}
    found = []
    total = 0

    def walk(value):
        nonlocal total
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            if value.get("IOObjectClass") == "IOUSBHostDevice":
                total += 1
                vendor = value.get("idVendor")
                product = value.get("idProduct")
                name = str(value.get("USB Product Name", value.get("IORegistryEntryName", "")))
                maker = str(value.get("USB Vendor Name", ""))
                if (vendor == 0x054c or re.search(r"sony|\bilce[- ]", name + " " + maker, re.I)):
                    found.append({"source": "ioreg", "name": name,
                                  "manufacturer": maker,
                                  "vendor_id": f"0x{vendor:04x}" if isinstance(vendor, int) else str(vendor),
                                  "product_id": f"0x{product:04x}" if isinstance(product, int) else str(product),
                                  "serial_num": value.get("USB Serial Number"),
                                  "location_id": value.get("locationID")})
            for child in value.get("IORegistryEntryChildren", []):
                walk(child)

    walk(roots)
    return {"sony_devices": found, "ioreg_matches": len(found),
            "ioreg_usb_device_count": total}


def disk_info(identifier):
    raw, error = run(["diskutil", "info", "-plist", identifier], timeout=20)
    if error:
        return {"identifier": identifier, "error": error}
    try:
        info = plistlib.loads(raw)
    except (ValueError, TypeError) as exc:
        return {"identifier": identifier, "error": f"invalid diskutil plist: {exc}"}
    wanted = ("DeviceIdentifier", "DeviceNode", "VolumeName", "VolumeUUID",
              "DiskUUID", "Mounted", "MountPoint", "BusProtocol", "Internal",
              "RemovableMedia", "DeviceLocation", "TotalSize", "FilesystemName",
              "FileSystemPersonality", "MediaName", "ReadOnlyMedia", "Writable")
    return {key: info.get(key) for key in wanted if key in info}


def volume_inventory():
    raw, error = run(["diskutil", "list", "-plist"], timeout=30)
    if error:
        return {"error": error, "external_disks": []}
    try:
        listing = plistlib.loads(raw)
    except (ValueError, TypeError) as exc:
        return {"error": f"invalid diskutil list: {exc}", "external_disks": []}
    external = []
    for disk in listing.get("AllDisksAndPartitions", []):
        identifier = disk.get("DeviceIdentifier")
        if not identifier:
            continue
        whole = disk_info(identifier)
        if (whole.get("Internal") is False or
                str(whole.get("BusProtocol", "")).upper() == "USB" or
                whole.get("RemovableMedia") is True):
            parts = []
            for part in disk.get("Partitions", []):
                part_id = part.get("DeviceIdentifier")
                if part_id:
                    parts.append(disk_info(part_id))
            external.append({"disk": whole, "partitions": parts})
    return {"external_disks": external}


def dependencies():
    libusb = next((candidate for candidate in
                   ("/opt/homebrew/lib/libusb-1.0.dylib",
                    "/usr/local/lib/libusb-1.0.dylib")
                   if Path(candidate).is_file()), None)
    if libusb is None:
        try:
            import libusb_package
            packaged = libusb_package.get_library_path()
            if packaged is not None and Path(packaged).is_file():
                libusb = str(packaged)
        except ImportError:
            pass
    if libusb is None:
        libusb = ctypes.util.find_library("usb-1.0")
    return {"python": sys.version.split()[0],
            "libusb_library": libusb,
            "pyusb_importable": importlib.util.find_spec("usb") is not None,
            "pmca_importable": importlib.util.find_spec("pmca") is not None}


def bk4_report(path):
    raw = path.read_bytes()
    records = []
    cursor = 0
    while True:
        magic = raw.find(b"BK4\0", cursor)
        if magic < 0:
            break
        cursor = magic + 4
        base = magic - 12
        if base < 0 or base + 0x100 > len(raw):
            continue
        _, _, _, _, subs, props, data_at, data_size, stored = struct.unpack_from("<9I", raw, base)
        size = data_at + data_size
        if size < 0x100 or base + size > len(raw) or subs > 4096 or props > 100000:
            continue
        record = raw[base:base + size]
        actual = (sum(record[:0x20]) + sum(record[0x24:])) & 0xffffffff
        item = {"offset": hex(base), "size": size,
                "stored_checksum": f"{stored:08x}", "actual_checksum": f"{actual:08x}",
                "checksum_valid": actual == stored}
        if actual == stored and PROPERTY_ID >> 16 < subs:
            subsystem, index = PROPERTY_ID >> 16, PROPERTY_ID & 0xffff
            table = 0x100 + subsystem * 6
            if table + 6 <= size:
                count, first = struct.unpack_from("<HI", record, table)
                if index < count and first + index < props:
                    entry = 0x100 + subs * 6 + (first + index) * 6
                    if entry + 6 <= size:
                        attr, pointer = struct.unpack_from("<HI", record, entry)
                        if pointer != 0xffffffff:
                            length, start = pointer >> 24, pointer & 0xffffff
                            if length == 0xff and start + 2 <= size:
                                length = struct.unpack_from("<H", record, start)[0]
                                start += 2
                            elif length == 0 and start + 4 <= size:
                                length, maximum = struct.unpack_from("<HH", record, start)
                                if length > maximum:
                                    length = -1
                                start += 4
                            if length > 0 and data_at <= start and start + length <= size:
                                blob = record[start:start + length]
                                blob_sha = sha(blob)
                                item["color_property"] = {
                                    "id": "0x02a40001", "attribute": hex(attr),
                                    "size": length, "table_offset": hex(base + entry),
                                    "data_offset": hex(base + start), "sha256": blob_sha,
                                    "state": ("official_201" if blob_sha == PROPERTY_201_SHA else
                                              "fl23_target" if blob_sha == PROPERTY_FL23_SHA else "unknown")}
        records.append(item)
    matches = [item for item in records if "color_property" in item]
    result = {"path": str(path.resolve()), "size": len(raw), "sha256": sha(raw),
              "records": records, "unique_color_property": len(matches) == 1,
              "color_property": matches[0]["color_property"] if len(matches) == 1 else None}
    if (len(matches) == 1 and matches[0]["color_property"]["state"] == "official_201" and
            matches[0]["color_property"]["attribute"] == "0x8"):
        item = matches[0]
        start = int(item["color_property"]["data_offset"], 16)
        target = color.from_source(raw[start:start + 8192])
        if len(target) == 8192 and sha(target) == PROPERTY_FL23_SHA:
            base = int(item["offset"], 16)
            delta = sum(target) - sum(raw[start:start + 8192])
            if delta == 19569:
                candidate = bytearray(raw)
                candidate[start:start + 8192] = target
                old_sum = int(item["stored_checksum"], 16)
                new_sum = (old_sum + delta) & 0xffffffff
                struct.pack_into("<I", candidate, base + 0x20, new_sum)
                end = base + item["size"]
                actual = (sum(candidate[base:base + 0x20]) +
                          sum(candidate[base + 0x24:end])) & 0xffffffff
                result["offline_bk4_candidate"] = {
                    "validated": actual == new_sum and
                    candidate[:base] == raw[:base] and candidate[end:] == raw[end:],
                    "written_to_camera": False,
                    "checksum_delta": delta,
                    "old_checksum": f"{old_sum:08x}",
                    "new_checksum": f"{new_sum:08x}",
                    "changed_property_bytes": sum(a != b for a, b in zip(raw[start:start + 8192], target)),
                    "candidate_file_sha256": sha(candidate),
                }
    return result


def p1_report(path):
    raw = path.read_bytes()
    report = {"path": str(path.resolve()), "size": len(raw), "sha256": sha(raw),
              "crc32": f"{zlib.crc32(raw) & 0xffffffff:08x}"}
    if len(raw) < 512:
        return report
    sector = struct.unpack_from("<H", raw, 11)[0]
    cluster_sectors = raw[13]
    reserved = struct.unpack_from("<H", raw, 14)[0]
    fats = raw[16]
    root_entries = struct.unpack_from("<H", raw, 17)[0]
    fat_sectors = struct.unpack_from("<H", raw, 22)[0]
    total_sectors = struct.unpack_from("<H", raw, 19)[0]
    first_data = reserved + fats * fat_sectors + (root_entries * 32 + sector - 1) // sector if sector else 0
    geometry = (sector, cluster_sectors, reserved, fats, root_entries,
                fat_sectors, total_sectors, first_data)
    report["fat"] = {"sector_bytes": sector, "sectors_per_cluster": cluster_sectors,
                     "reserved_sectors": reserved, "fat_count": fats,
                     "root_entries": root_entries, "sectors_per_fat": fat_sectors,
                     "total_sectors": total_sectors, "first_data_sector": first_data,
                     "signature_55aa": raw[510:512] == b"\x55\xaa",
                     "matches_research_geometry": geometry ==
                     (512, 32, 1, 2, 512, 32, 38864, 97)}
    if not (sector == 512 and 1 <= reserved < 64 and 1 <= fats <= 4 and
            1 <= fat_sectors <= 1024 and first_data * sector < len(raw)):
        return report
    fat_at = reserved * sector
    fat_size = fat_sectors * sector
    fat = raw[fat_at:fat_at + fat_size]
    report["fat"]["fat_copies_equal"] = fats >= 2 and raw[fat_at + fat_size:fat_at + 2 * fat_size] == fat

    def chain(start):
        current, seen, values = start, set(), []
        while 2 <= current < 0xff0 and current not in seen and len(values) < 4096:
            seen.add(current)
            values.append(current)
            at = current * 3 // 2
            if at + 2 > len(fat):
                break
            pair = int.from_bytes(fat[at:at + 2], "little")
            current = pair >> 4 if current & 1 else pair & 0xfff
        return {"first": start, "count": len(values), "last": values[-1] if values else None,
                "terminated": 0xff8 <= current <= 0xfff,
                "contiguous": bool(values) and values == list(range(start, start + len(values)))}

    report["fat_chains"] = {"boot": chain(3), "initrd": chain(4), "p1chksum": chain(991)}
    initrd_at = (first_data + (4 - 2) * cluster_sectors) * sector
    checksum_at = (first_data + (991 - 2) * cluster_sectors) * sector
    if report["fat_chains"]["initrd"]["count"] == 581 and initrd_at + 9_519_104 <= len(raw):
        initrd = raw[initrd_at:initrd_at + 9_519_104]
        report["initrd"] = {"offset": initrd_at, "size": len(initrd),
                            "sha256": sha(initrd), "md5": hashlib.md5(initrd).hexdigest()}
    if checksum_at + 105 <= len(raw):
        entry = raw[checksum_at:checksum_at + 105]
        lines = entry.decode("ascii", "replace").splitlines()
        listed = lines[1][:32] if len(lines) == 2 else None
        report["p1chksum"] = {"offset": checksum_at, "sha256": sha(entry),
                              "initrd_md5_listed": listed,
                              "initrd_md5_matches": bool(listed and "initrd" in report and
                                                          listed == report["initrd"]["md5"])}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p1", type=Path, help="previously exported p1 image")
    parser.add_argument("--backup-bin", type=Path, help="previously exported Backup.bin")
    parser.add_argument("--backup-bak", type=Path, help="previously exported Backup.bak")
    parser.add_argument("--out", type=Path, help="output JSON path")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("macOS required")
    snapshots, missing = {}, []
    for name, path, reader in (("p1", args.p1, p1_report),
                               ("backup_bin", args.backup_bin, bk4_report),
                               ("backup_bak", args.backup_bak, bk4_report)):
        if path is None:
            missing.append(name)
        elif not path.is_file():
            parser.error(f"missing snapshot: {path}")
        else:
            snapshots[name] = reader(path)
    backs = [snapshots.get("backup_bin"), snapshots.get("backup_bak")]
    bk4_ready = all(
        item and item["unique_color_property"] and
        item["color_property"]["state"] == "official_201" and
        item["color_property"]["attribute"] == "0x8" and
        item["color_property"]["size"] == 8192 and
        all(record["checksum_valid"] for record in item["records"])
        for item in backs)
    report = {"format": 1, "utc": datetime.now(timezone.utc).isoformat(),
              "read_only": True, "camera_internal_storage_accessed": False,
              "dependencies": dependencies(), "usb": usb_inventory(),
              "volumes": volume_inventory(), "snapshots": snapshots,
              "missing_snapshot_types": missing,
              "bk4_layout_ready_for_review": bk4_ready,
              "body_specific_p1_review_required": True}
    out = args.out or Path.cwd() / ("mac_camera_probe_" +
                                  datetime.now().strftime("%Y%m%d_%H%M%S") + ".json")
    out = out.resolve()
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, default=str)
            stream.write("\n")
    except FileExistsError:
        parser.error(f"output already exists: {out}")
    print("output:", out)
    print("sony_usb_devices:", len(report["usb"].get("sony_devices", [])))
    print("external_disks:", len(report["volumes"].get("external_disks", [])))
    print("missing_snapshots:", ",".join(missing) or "none")
    print("bk4_layout_ready_for_review:", bk4_ready)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
