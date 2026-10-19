#!/usr/bin/env python3
"""Start a 600-second 1.99 MENU return after local p1 gates are verified."""

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sony-service-research"))
import run_backup_snapshot_ro as identity
import mac_probe_fl23 as probe
import p1_gate_generic_200 as p1
import update_code_hold_200 as gate


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-json", type=Path, required=True)
    parser.add_argument("--full-preflight-json", type=Path, required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "darwin", "macOS required")
    p1.set_selected(args.package_manifest)
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = identity.report_identity(report)
    manifest = p1.load_manifest(args.p1_manifest, args.full_preflight_json, camera)
    gate.base.pinned_elf()
    libusb = probe.dependencies().get("libusb_library")
    require(libusb and Path(libusb).is_file(), "probe libusb path unavailable")
    if not args.execute:
        print(json.dumps({"camera_access": False,
                          "camera_serial": manifest["camera_usb_serial"],
                          "installed_version_required": "2.01",
                          "menu_version_return": "1.99", "seconds": 600}))
        return 0
    require(os.geteuid() == 0, "sudo with the configured Python is required")
    p1.verify_install_receipt(args.p1_manifest, manifest)
    p1.verify_card_package(camera, card, pmhome)
    identity.ensure_camera_volumes_unmounted(camera, card, pmhome)
    return gate.base.main(["--execute", "--msc-volumes-unmounted",
                           "--card-and-pmhome-verified", "--msc-pid", "0e8a",
                           "--pmca-path", str(ROOT), "--libusb", libusb])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
