#!/usr/bin/env python3
"""Offline verify CP RAM and two BK4 properties after a full camera cold boot."""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
import mac_probe_fl23 as probe

TARGET_SHA = "1035933d52e7198f9656181dc2e8242fa90fc95018eba3823a102c669e02f6f2"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--cp-report", type=Path, required=True)
    parser.add_argument("--bk4-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    cp_path, bk4_dir, output = (args.cp_report.resolve(), args.bk4_dir.resolve(),
                                args.out.resolve())
    require(all(path.is_relative_to(ROOT.resolve()) for path in
                (cp_path, bk4_dir, output)) and not output.exists(),
            "cold reports must be inside workspace and output must be new")
    cp = json.loads(cp_path.read_text(encoding="utf-8"))
    receipt = json.loads((bk4_dir / "windows-bk4-receipt.json").read_text(
        encoding="utf-8"))
    require(cp.get("serial") == receipt.get("serial") == args.serial and
            cp.get("normal_mode_and_driver_verified_after_child_exit") is True and
            receipt.get("normal_mode_and_driver_verified_after_child_exit") is True and
            cp.get("marker", {}).get("complete") is True and
            cp["marker"].get("block_sha256") == TARGET_SHA and
            set(receipt.get("results", {})) == {"backup_bin", "backup_bak"},
            "cold CP runtime or BK4 receipts incomplete")
    checksums, files = {}, {}
    for label in ("backup_bin", "backup_bak"):
        entry = receipt["results"][label]
        path = bk4_dir / entry["private_snapshot"]
        require(path.is_file() and not path.is_symlink(),
                label + " cold BK4 file absent")
        report = probe.bk4_report(path)
        color = report.get("color_property") or {}
        require(report.get("size") == 2_390_264 and
                report.get("sha256") == entry["file_sha256"] and
                report.get("unique_color_property") is True and
                len(report.get("records", [])) == 2 and
                all(item.get("checksum_valid") is True for item in report["records"]) and
                color.get("sha256") == entry["property_sha256"] == TARGET_SHA and
                color.get("size") == 8192 and color.get("attribute") == "0x8",
                label + " cold BK4 bytes, checksum or property differ")
        checksums[label] = report["records"][1]["stored_checksum"]
        files[label] = report["sha256"]
    result = {"camera_serial": args.serial,
              "cp_live_after_cold_sha256": TARGET_SHA,
              "bk4_property_sha256": TARGET_SHA,
              "bk4_checksums": checksums,
              "bk4_file_sha256": files,
              "coldboot_verified": True}
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"event": "windows_fl23_cold_verified",
                      "serial": args.serial, "property_sha256": TARGET_SHA,
                      "receipt": str(output)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
