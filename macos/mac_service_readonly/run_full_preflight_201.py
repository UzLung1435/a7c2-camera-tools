#!/usr/bin/env python3
"""One entry for saved BK4 validation and new-body p1 read-only capture.

The p1 worker opens only /dev/cnflasha1 O_RDONLY. It stages bounded chunks
and preload text in the camera's temporary Work/tmpfs to obtain root read
access; it never writes the p1 block device or installs a firmware package.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sony-service-research"))
import mac_probe_fl23 as probe
import run_backup_snapshot_ro as identity
import p1_fixed_host_export_201 as p1
import p1_final_tmpfs_cleanup_201 as p1_cleanup

SNAPSHOTS = ROOT / "snapshots"
PROPERTY_201_SHA = "f6897866e2014a972d17383ea2c6fef4096fc5a3166f348eaff3c60f67a23ba1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ensure_private_snapshot_owner(allow_fix):
    info = SNAPSHOTS.lstat()
    owner = int(os.environ.get("SUDO_UID", os.geteuid()))
    group = int(os.environ.get("SUDO_GID", os.getegid()))
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
            "private snapshots directory missing or not mode 0700")
    require(info.st_uid == owner or
            (allow_fix and os.geteuid() == 0 and info.st_uid == 0 and owner > 0),
            "private snapshots directory owner differs")
    for label in ("backup_bin", "backup_bak"):
        found = list(SNAPSHOTS.glob(f"a7c2-readonly-{label}-*.bin"))
        require(len(found) == 1, f"expected exactly one {label} snapshot")
        item = found[0].lstat()
        require(stat.S_ISREG(item.st_mode) and stat.S_IMODE(item.st_mode) == 0o600
                and item.st_nlink == 1 and
                (item.st_uid == owner or (allow_fix and os.geteuid() == 0 and
                                          item.st_uid == 0 and owner > 0))
                and item.st_size == 2_390_264,
                label + " snapshot cannot be assigned to invoking user")
        if item.st_uid == 0:
            os.chown(found[0], owner, group, follow_symlinks=False)
    if info.st_uid == 0:
        os.chown(SNAPSHOTS, owner, group, follow_symlinks=False)


def saved_backups():
    files, reports = [], []
    owner = int(os.environ.get("SUDO_UID", os.geteuid()))
    for label in ("backup_bin", "backup_bak"):
        found = list(SNAPSHOTS.glob(f"a7c2-readonly-{label}-*.bin"))
        require(len(found) == 1, f"expected exactly one {label} snapshot")
        info = found[0].lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == owner and info.st_nlink == 1
                and info.st_size == 2_390_264,
                label + " snapshot identity or private mode changed")
        item = probe.bk4_report(found[0])
        prop = item.get("color_property") or {}
        candidate = item.get("offline_bk4_candidate") or {}
        require(item["unique_color_property"] and
                all(row["checksum_valid"] for row in item["records"]) and
                prop.get("sha256") == PROPERTY_201_SHA and
                prop.get("attribute") == "0x8" and prop.get("size") == 8192 and
                candidate.get("validated") is True and
                candidate.get("checksum_delta") == 19569,
                label + " BK4 property or offline write simulation differs")
        files.append(found[0])
        reports.append(item)
    return files, reports


def private_output(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        owner = int(os.environ.get("SUDO_UID", os.geteuid()))
        group = int(os.environ.get("SUDO_GID", os.getegid()))
        os.fchown(fd, owner, group)
        if os.write(fd, data) != len(data):
            raise OSError("short private report write")
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    global SNAPSHOTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-json", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume", metavar="CAPTURE_ID")
    parser.add_argument("--snapshots-dir", type=Path,
                        help="private per-camera snapshot directory")
    args = parser.parse_args()
    if args.snapshots_dir is not None:
        SNAPSHOTS = args.snapshots_dir.resolve()
    if sys.platform != "darwin":
        parser.error("macOS required")
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = identity.report_identity(report)
    if args.execute:
        require(os.geteuid() == 0, "sudo with this virtualenv's Python is required")
        identity.ensure_camera_volumes_unmounted(camera, card, pmhome)
    else:
        require(not identity.live_preflight(camera, card, pmhome),
                "camera card and PMHOME must be unmounted for dry-run")
    ensure_private_snapshot_owner(args.execute)
    files, backups = saved_backups()
    p1.select_target("cnflasha1")
    p1.BACKUP_DIR = SNAPSHOTS
    p1.set_probe_report(report)
    p1.configure_existing_transport()
    p1.producer.fixed_elf()
    print("bk4_offline_validated: 2 files; p1 profile: cnflasha1, 25100288 bytes, 3 windows")
    if not args.execute:
        print("camera_access: false; pass --execute for read-only p1 capture")
        return 0
    capture = args.resume or secrets.token_hex(16)
    require(len(capture) == 32 and all(c in "0123456789abcdef" for c in capture),
            "invalid p1 capture ID")
    print("p1_capture_id:", capture, flush=True)
    result = p1.run_capture(capture, resume=bool(args.resume),
                            progress=lambda row: print(json.dumps(row), flush=True))
    image = SNAPSHOTS / result["image_basename"]
    p1_details = probe.p1_report(image)
    require(image.stat().st_size == 25_100_288 and
            p1_details["sha256"] == result["image_sha256"],
            "p1 host image size/hash mismatch")
    cleanup_result = {"result": "pending"}
    try:
        cleanup_result = p1_cleanup.cleanup("cnflasha1", capture)
    except Exception as exc:
        cleanup_result = {"result": "failed", "error_type": type(exc).__name__}
    cleanup_done = cleanup_result.get("result") in ("cleaned", "already_cleaned")
    combined = {"format": 1, "camera": "ILCE-7CM2", "installed_version": "2.01",
                "camera_usb_serial": camera["serial_num"],
                "read_only_internal_device": "/dev/cnflasha1",
                "p1_capture_id": capture, "p1": p1_details,
                "p1_window_count": len(result["windows"]),
                "p1_all_windows_verified": len(result["windows"]) == 3,
                "backups": dict(zip(("backup_bin", "backup_bak"), backups)),
                "backup_files_written_to_camera": False,
                "p1_block_device_written": False,
                "temporary_camera_work_files_used": True,
                "final_tmpfs_window_cleanup_pending": not cleanup_done,
                "final_tmpfs_cleanup": cleanup_result,
                "firmware_install_performed": False}
    destination = SNAPSHOTS / f"full-preflight-{capture}.json"
    private_output(destination, combined)
    print("full_preflight_report:", destination, flush=True)
    print("p1_sha256:", result["image_sha256"], flush=True)
    print("final_tmpfs_window_cleanup_pending:", not cleanup_done, flush=True)
    return 0 if cleanup_done else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
