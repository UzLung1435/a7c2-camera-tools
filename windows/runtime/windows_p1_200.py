#!/usr/bin/env python3
"""Guarded Windows apply/restore of one 2.01 camera's temporary 2.00 p1 gates."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as service
import build_p1_gate_200 as builder
import p1_gate_generic_200 as gate
import windows_p1_capture as capture
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb
sys.path.insert(0, str(ROOT / "release"))
import feature_package_200 as feature_package

SEQUENCES = {"install": gate.SEQUENCES["install"],
             "restore": gate.SEQUENCES["restore"]}


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def verified_manifest(path, serial):
    data = json.loads(path.read_text(encoding="utf-8"))
    source = Path(data.get("source_p1_path", ""))
    target = Path(data.get("target_p1_path", ""))
    require(data.get("camera_usb_serial") == serial and
            data.get("camera") == "ILCE-7CM2" and
            data.get("source_camera_version") == "2.01" and
            data.get("target_package_version") == "2.00" and
            data.get("candidate_readback_verified") is True and
            source.is_file() and target.is_file() and
            not source.is_symlink() and not target.is_symlink(),
            "rollback p1 manifest identity differs")
    raw = source.read_bytes()
    candidate, stages = builder.make_candidates(raw)
    require(hashlib.sha256(raw).hexdigest() == data["source_p1_sha256"] and
            hashlib.sha256(candidate).hexdigest() == data["target_p1_sha256"] and
            candidate == target.read_bytes() and stages == data["stages"],
            "p1 candidate no longer derives from live capture")
    with tempfile.TemporaryDirectory() as folder:
        expected = builder.build_worker_templates(Path(folder), stages,
                                                  raw, candidate)
        require(expected == data.get("workers"),
                "p1 worker manifest no longer derives from this candidate")
        for variants in expected.values():
            for item in variants.values():
                name = item["filename"]
                worker = path.parent / "workers" / name
                require(worker.is_file() and not worker.is_symlink() and
                        worker.read_bytes() ==
                        (Path(folder) / "workers" / name).read_bytes(),
                        "p1 worker bytes differ from local derivation")
    return data


def failure_reason(result, events):
    if result is None:
        return "camera returned no p1 result"
    producer = result.get("producer") or {}
    if producer.get("stop_reason") == "baseline_file_present_or_unreadable":
        states = result.get("baseline_files") or {}
        present = [name for name, value in states.items()
                   if value.get("state") != "not_found_or_unreadable"]
        return "camera Work baseline differs: " + ", ".join(present)
    if producer.get("trigger_request_maybe_sent"):
        return "camera worker triggered without a valid final status"
    failed = next((item for item in reversed(events)
                   if item.get("event") == "probe_failed"), None)
    if failed:
        return "USB/service probe: " + str(failed.get("error_code"))
    return "p1 worker proof incomplete"


def run_parent(args, manifest_path, manifest):
    require_winusb(args.serial)
    if args.action == "install":
        require(args.package_manifest is not None,
                "selected package manifest required for p1 install")
        _, selected_sha = feature_package.selected(args.package_manifest)
        card = json.loads((manifest_path.parent /
                           "package_200_card_stage_receipt.json").read_text(
                               encoding="utf-8"))
        require(card.get("serial") == args.serial and
                card.get("active_sha256") == selected_sha,
                "verified FL23 2.00 card staging receipt required")
    state_path = manifest_path.parent / f"windows_p1_200_{args.action}_state.json"
    steps = [f"{stage}:{mode}" for stage, mode in SEQUENCES[args.action]]
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        require(state.get("serial") == args.serial and
                state.get("action") == args.action and
                state.get("manifest_sha256") == capture.file_sha(manifest_path) and
                state.get("in_progress") is None and
                state.get("completed") == steps[:len(state.get("completed", []))],
                "p1 state differs or a write was interrupted; inspect before retry")
    else:
        recovered = []
        for stage, mode in SEQUENCES[args.action]:
            inspection_path = manifest_path.parent / f"p1_inspect_{stage}_{mode}.json"
            if not inspection_path.exists():
                break
            inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
            require(inspection.get("serial") == args.serial and
                    inspection.get("manifest_sha256") == capture.file_sha(manifest_path) and
                    inspection.get("stage") == stage and
                    inspection.get("mode") == mode and
                    inspection.get("worker_matches") is True and
                    inspection.get("status_verified") is True and
                    inspection.get("normal_mode_and_driver_verified_after_child_exit") is True,
                    "saved p1 step inspection differs")
            recovered.append(f"{stage}:{mode}")
        state = {"format": 1, "serial": args.serial,
                 "action": args.action, "manifest_sha256": capture.file_sha(manifest_path),
                 "completed": recovered, "in_progress": None}
        capture.save_json(state_path, state)
    for index in range(len(state["completed"]), len(steps)):
        stage, mode = SEQUENCES[args.action][index]
        label = steps[index]
        state["in_progress"] = label
        capture.save_json(state_path, state)
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--serial", args.serial, "--manifest", str(manifest_path),
                                "--action", args.action, "--step", str(index),
                                "--execute", "--child"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace",
                               timeout=300)
        log_path = manifest_path.parent / f"p1_{args.action}_{index}_{stage}_{mode}.log"
        log_path.write_text(child.stdout + child.stderr, encoding="utf-8")
        events = []
        for line in child.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        target = next((item for item in events
                       if item.get("event") == "target_verified"), None)
        if target is not None:
            verify_normal_in_new_process(args.serial, target["identity"]["address"])
        result = next((item for item in reversed(events)
                       if item.get("event") == "windows_p1_step"), None)
        require(result is not None and result.get("stage") == stage and
                result.get("mode") == mode and result.get("verified") is True,
                label + ": " + failure_reason(result, events) +
                "; state retained; log: " + str(log_path))
        state["completed"].append(label)
        state["in_progress"] = None
        capture.save_json(state_path, state)
        service.emit("windows_p1_step_verified", action=args.action,
                     completed=index + 1, total=len(steps), stage=stage, mode=mode)
    state["complete"] = True
    capture.save_json(state_path, state)
    service.emit("windows_p1_action_complete", action=args.action,
                 serial=args.serial, state=str(state_path))
    return 0


def run_child(args, manifest_path, manifest):
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import jiritsu_version_probe as version
    import windows_usb_adapter as adapter

    require_winusb(args.serial)
    require(args.step is not None and
            0 <= args.step < len(SEQUENCES[args.action]),
            "invalid p1 step index")
    stage, mode = SEQUENCES[args.action][args.step]
    config = gate.config_for(stage, mode, manifest, manifest_path)
    path = config["elf_path"]
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size == config["size"] and
            capture.file_sha(path) == config["sha256"],
            "p1 worker ELF hash differs")
    gate.configure_worker(config)
    gate.producer.parse_manifest = lambda raw: gate.parse_status(raw, config)
    usb_backend = windows_libusb.get_backend()
    require(usb_backend is not None, "libusb backend unavailable")
    backend = gate.P1Backend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=gate.P1Budget(), usb_backend=usb_backend,
        logger=version.safe_logger())
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    marker = backend.manifest_fields or {}
    verified = (backend.product_verified and backend.proof_verified and
                backend.cleanup_absence_verified and marker.get("phase") == 6 and
                marker.get("camera_status") == 0)
    baseline_files = {
        label: {"state": backend.files.get(label, ("unobserved", None))[0],
                "bytes": len(backend.files[label][1])
                if label in backend.files and
                isinstance(backend.files[label][1], bytes) else None}
        for label in ("ram_before", "manifest_before",
                      "tmp_preload_before", "etc_preload_before")
    }
    service.emit("windows_p1_step", stage=stage, mode=mode,
                 verified=verified, marker=marker,
                 baseline_files=baseline_files,
                 producer=gate.producer.summarize(
                     backend, lifecycle["normal_mode_and_driver_verified"]),
                 child_normal_verified=lifecycle["normal_mode_and_driver_verified"],
                 child_code=code)
    return 0 if verified else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--action", choices=tuple(SEQUENCES), required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--package-manifest", type=Path)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--step", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    manifest_path = args.manifest.resolve()
    require(manifest_path.is_relative_to(ROOT.resolve()),
            "rollback manifest must stay inside research workspace")
    manifest = verified_manifest(manifest_path, args.serial)
    if not args.execute:
        service.emit("offline_plan", camera_access=False, action=args.action,
                     steps=[f"{stage}:{mode}" for stage, mode in SEQUENCES[args.action]])
        return 0
    return (run_child(args, manifest_path, manifest) if args.child else
            run_parent(args, manifest_path, manifest))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
