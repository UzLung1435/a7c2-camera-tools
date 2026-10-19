#!/usr/bin/env python3
"""Stage the selected A7C II 2.00 DAT on its photo card."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from windows_storage import volume_identity, sha_file
sys.path.insert(0, str(ROOT / "release"))
import feature_package_200 as feature_package

OFFICIAL_SHA = "eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31"
SIZE = 1_139_929_560


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--version-report", type=Path, required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--official", type=Path)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    version = json.loads(args.version_report.read_text(encoding="utf-8"))
    manifest = json.loads(args.p1_manifest.read_text(encoding="utf-8"))
    require(version.get("serial") == args.serial and
            version.get("dat4_hex") == "0102" and
            version.get("normal_mode_and_driver_verified_after_child_exit") is True and
            manifest.get("camera_usb_serial") == args.serial and
            manifest.get("source_camera_version") == "2.01" and
            manifest.get("target_package_version") == "2.00" and
            manifest.get("candidate_readback_verified") is True,
            "verified 2.01 version and per-camera p1 preparation required")
    card, home = volume_identity(args.serial)
    root = Path(card["drive"] + ":\\")
    require((root / "DCIM").is_dir() and
            card["free"] > (2 * SIZE if not (root / "BODYDATA.DAT").exists()
                            else SIZE) + 100_000_000,
            "identified photo card is absent or lacks free space")
    selected_package, selected_sha = feature_package.selected(args.package_manifest)
    feature_ids = json.loads(args.package_manifest.read_text(encoding="utf-8"))["feature_ids"]
    active = root / "BODYDATA.DAT"
    old = root / "BODYDATA_official201_backup.DAT"
    temp = root / "BODYDATA.FEATURES.COPYING"
    require(not active.is_symlink(), "active card package is a link")
    require(not active.exists() or
            (active.is_file() and active.stat().st_size == SIZE),
            "active photo card DAT has wrong size")
    active_sha = sha_file(active) if active.exists() else None
    if active_sha == selected_sha:
        require(old.is_file() and sha_file(old) == OFFICIAL_SHA and
                not temp.exists(), "staged card lacks verified official backup")
        output = args.p1_manifest.resolve().parent / "package_200_card_stage_receipt.json"
        if not output.exists():
            receipt = {"event": "package_200_card_staged", "serial": args.serial,
                       "card_volume_id": card["volume_id"],
                       "active_sha256": selected_sha,
                       "feature_ids": feature_ids,
                       "official_backup_sha256": OFFICIAL_SHA,
                       "active_path": str(active), "official_backup_path": str(old)}
            output.write_text(json.dumps(receipt, indent=2) + "\n",
                              encoding="utf-8")
        print(json.dumps({"event": "package_200_already_staged",
                          "serial": args.serial,
                          "card_volume_id": card["volume_id"]}))
        return 0
    require(not old.exists() and not temp.exists(),
            "card package backup or temporary file differs")
    require(active_sha in (None, OFFICIAL_SHA),
            "current card DAT is not the official 2.01")
    official = (args.official.resolve() if args.official else
                ROOT.parent / "ILCE-7CM2-v2.01-BODYDATA.DAT")
    if active_sha is None:
        require(official.is_relative_to(ROOT.parent.resolve()) and
                official.is_file() and official.stat().st_size == SIZE and
                sha_file(official) == OFFICIAL_SHA,
                "official 2.01 DAT missing beside BAT")
    print(json.dumps({"event": "fl23_200_stage_preflight",
                      "serial": args.serial,
                      "card_volume_id": card["volume_id"],
                      "source_sha256": active_sha, "target_sha256": selected_sha,
                      "camera_access": False}), flush=True)
    if not args.execute:
        return 0
    phrase = "STAGE A7C2 " + args.serial.upper()
    answer = args.confirm if args.confirm is not None else input(
        "输入 " + phrase + " 写入照片卡，或 Q 停止: ").strip()
    require(answer == phrase, "photo card stage confirmation differs")
    moved_old = False
    promoted = False
    created_old = False
    try:
        with selected_package.open("rb") as source, temp.open("xb") as target:
            shutil.copyfileobj(source, target, 8 * 1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        require(temp.stat().st_size == SIZE and sha_file(temp) == selected_sha,
                "temporary 2.00 DAT full card readback differs")
        require(volume_identity(args.serial)[0]["volume_id"] == card["volume_id"],
                "photo card identity changed during copy")
        if active_sha is None:
            with official.open("rb") as source, old.open("xb") as target:
                created_old = True
                shutil.copyfileobj(source, target, 8 * 1024 * 1024)
                target.flush()
                os.fsync(target.fileno())
            require(sha_file(old) == OFFICIAL_SHA,
                    "official card backup readback differs")
        else:
            active.rename(old)
        moved_old = True
        temp.rename(active)
        promoted = True
        require(sha_file(active) == selected_sha and sha_file(old) == OFFICIAL_SHA,
                "active 2.00 or official backup full card readback differs")
    except BaseException:
        if promoted and active.exists():
            active.unlink()
        if moved_old and not active.exists() and active_sha is not None:
            old.rename(active)
        if created_old and old.exists():
            old.unlink()
        if temp.exists():
            temp.unlink()
        raise
    receipt = {"event": "package_200_card_staged", "serial": args.serial,
               "card_volume_id": card["volume_id"],
               "active_sha256": selected_sha, "official_backup_sha256": OFFICIAL_SHA,
               "feature_ids": feature_ids,
               "active_path": str(active), "official_backup_path": str(old)}
    output = args.p1_manifest.resolve().parent / "package_200_card_stage_receipt.json"
    require(not output.exists(), "stage receipt already exists")
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
