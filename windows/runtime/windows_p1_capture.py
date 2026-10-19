#!/usr/bin/env python3
"""Resume-safe read-only cnflasha1 capture over three Windows WinUSB sessions."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "core" / "sony-service-research"))
import service_probe as service
from windows_service_probe import require_winusb, verify_normal_in_new_process
import windows_libusb


def require(ok, message):
    if not ok:
        raise service.ProbeError(message)


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    temp = path.with_name(path.name + ".writing")
    require(not temp.exists(), "stale host manifest write")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
    temp.replace(path)


def validate_window(out_dir, index, capture, previous):
    import p1_block_window_protocol_201 as wire
    meta_path = out_dir / f"window{index}.json"
    data_path = out_dir / f"window{index}.bin"
    require(meta_path.is_file() and data_path.is_file() and
            not meta_path.is_symlink() and not data_path.is_symlink(),
            "missing saved p1 window")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    manifest = meta.get("manifest") or {}
    start, count = wire.window_shape(wire.CN1, index)
    require(meta.get("serial") and meta.get("capture_id") == capture and
            meta.get("index") == index and manifest.get("window_index") == index and
            manifest.get("capture_id") == capture and
            manifest.get("window_start") == start and
            manifest.get("window_count") == count and
            meta.get("previous_manifest_sha256") == previous and
            meta.get("proof_verified") is True and
            meta.get("collection_verified") is True and
            len(meta.get("chunks", [])) == count and
            data_path.stat().st_size == count * wire.BLOCK and
            file_sha(data_path) == meta.get("window_file_sha256"),
            "saved p1 window metadata differs")
    rows = []
    with data_path.open("rb") as stream:
        for local, item in enumerate(meta["chunks"]):
            chunk = stream.read(wire.BLOCK)
            offset = (start + local) * wire.BLOCK
            require(len(chunk) == wire.BLOCK and
                    item.get("offset") == offset and
                    item.get("sha256") == hashlib.sha256(chunk).hexdigest() and
                    item.get("crc32") == zlib.crc32(chunk),
                    "p1 window chunk readback differs")
            rows.append({"index": start + local, "offset": offset, "data": chunk,
                         "sha256": item["sha256"], "crc32": item["crc32"]})
    wire.verify_window(wire.CN1, rows, manifest)
    return meta


def run_parent(args, out_dir):
    import p1_block_window_protocol_201 as wire
    require_winusb(args.serial)
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = out_dir / "p1-capture-state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        require(state.get("serial") == args.serial and
                re.fullmatch(r"[0-9a-f]{32}", state.get("capture_id", "")),
                "p1 capture state belongs to another camera")
    else:
        require(not list(out_dir.glob("window*")),
                "window files exist without capture state")
        state = {"format": 1, "serial": args.serial,
                 "capture_id": secrets.token_hex(16), "windows": [],
                 "complete": False}
        save_json(state_path, state)
    capture = state["capture_id"]
    previous = None
    for index in range(wire.CN1.windows):
        meta_path = out_dir / f"window{index}.json"
        data_path = out_dir / f"window{index}.bin"
        if not (meta_path.exists() and data_path.exists()):
            require(not meta_path.exists() and not data_path.exists(),
                    "incomplete host window files; inspect before retry")
            command = [sys.executable, str(Path(__file__).resolve()),
                       "--serial", args.serial, "--out-dir", str(out_dir),
                       "--execute", "--child", "--window", str(index),
                       "--capture-id", capture]
            if previous:
                command += ["--previous-manifest", previous]
            child = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=680)
            log_path = out_dir / f"window{index}.log"
            log_path.write_text(child.stdout + child.stderr, encoding="utf-8")
            events = []
            for line in child.stdout.splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            target = next((item for item in events
                           if item.get("event") == "target_verified"), None)
            require(target is not None, "p1 child never verified target")
            verify_normal_in_new_process(args.serial, target["identity"]["address"])
            require(any(item.get("event") == "windows_p1_window_saved" for item in events),
                    "p1 child did not validate and save window")
        meta = validate_window(out_dir, index, capture, previous)
        require(meta["serial"] == args.serial,
                "p1 window belongs to another camera")
        previous = meta["manifest"]["manifest_sha256"]
        if index not in state["windows"]:
            state["windows"].append(index)
            save_json(state_path, state)
        service.emit("owner_window_saved", source="cnflasha1", capture_id=capture,
                     completed=index + 1, total=wire.CN1.windows)
    image = out_dir / f"cnflasha1-{capture}-{wire.CN1.bytes}.img"
    if not image.exists():
        temporary = image.with_suffix(".assembling")
        require(not temporary.exists(), "stale p1 image assembly")
        digest = hashlib.sha256()
        with temporary.open("xb") as target:
            for index in range(wire.CN1.windows):
                with (out_dir / f"window{index}.bin").open("rb") as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        target.write(block)
                        digest.update(block)
            target.flush()
        require(temporary.stat().st_size == wire.CN1.bytes,
                "assembled p1 size differs")
        temporary.replace(image)
    final_sha = file_sha(image)
    require(image.stat().st_size == wire.CN1.bytes,
            "assembled p1 size differs")
    if args.expected_sha256:
        require(final_sha == args.expected_sha256,
                "live p1 differs from required exact SHA-256")
    baseline_offsets = []
    if args.baseline_p1:
        baseline = args.baseline_p1.resolve()
        require(baseline.is_file() and not baseline.is_symlink() and
                baseline.stat().st_size == wire.CN1.bytes and
                file_sha(baseline) == args.baseline_sha256,
                "saved p1 baseline file identity differs")
        live_bytes, old_bytes = image.read_bytes(), baseline.read_bytes()
        allowed = {0x82AE, 0x82B6, 0x82EE, 0x82F6}
        for index, name in ((5, b"DAT2       "), (7, b"DAT3       ")):
            at = 0x8200 + index * 32
            require(live_bytes[at:at + 11] == old_bytes[at:at + 11] == name,
                    "p1 FAT directory entry differs")
        baseline_offsets = [i for i, (new, old) in enumerate(zip(live_bytes, old_bytes))
                            if new != old]
        require(set(baseline_offsets) <= allowed,
                "live p1 differs outside DAT2/DAT3 FAT time low bytes")
    state.update(complete=True, image=str(image), sha256=final_sha,
                 baseline_sha256=args.baseline_sha256,
                 baseline_difference_offsets=[hex(i) for i in baseline_offsets])
    save_json(state_path, state)
    service.emit("windows_p1_capture_complete", serial=args.serial,
                 capture_id=capture, size=wire.CN1.bytes, sha256=final_sha,
                 image=str(image))
    return 0


def run_child(args, out_dir):
    import usb.core
    import usb.util
    import usb.backend.libusb1
    from pmca.usb.sony import SonySenserAuthDevice, SonySenserDevice, SonySenserCamera
    import p1_fixed_host_export_201 as p1
    import p1_block_window_protocol_201 as wire
    import cn10_window_producer_probe as producer
    import jiritsu_version_probe as version
    import windows_usb_adapter as adapter

    require_winusb(args.serial)
    require(args.window is not None and 0 <= args.window < wire.CN1.windows and
            re.fullmatch(r"[0-9a-f]{32}", args.capture_id or ""),
            "invalid p1 window request")
    if args.window == 0:
        require(args.previous_manifest is None,
                "first p1 window must not have previous manifest")
    else:
        require(args.previous_manifest is not None and
                re.fullmatch(r"[0-9a-f]{64}", args.previous_manifest),
                "previous p1 manifest SHA required")
    p1.select_target("cnflasha1")
    p1.configure_existing_transport()
    producer.fixed_elf()
    usb_backend = windows_libusb.get_backend()
    require(usb_backend is not None, "libusb backend unavailable")
    backend = p1.WindowBackend(
        usb.core, usb.util, SonySenserAuthDevice, SonySenserDevice,
        SonySenserCamera, version.MSC_PID, version.PRODUCT,
        budget=p1.WindowBudget(), usb_backend=usb_backend,
        logger=version.safe_logger(), capture_id=args.capture_id,
        window_index=args.window,
        previous_manifest_sha256=args.previous_manifest)
    adapter.install(backend, args.serial)
    code, lifecycle = service.run_probe(backend)
    start, count = wire.window_shape(wire.CN1, args.window)
    rows = [backend.validated.get(i) for i in range(start, start + count)]
    require(backend.proof_verified and backend.collection_verified and
            all(row is not None for row in rows) and
            backend.manifest_fields is not None,
            "camera p1 window proof or chunks incomplete")
    wire.verify_window(wire.CN1, rows, backend.manifest_fields)
    data_path = out_dir / f"window{args.window}.bin"
    meta_path = out_dir / f"window{args.window}.json"
    require(not data_path.exists() and not meta_path.exists(),
            "host p1 window already exists")
    digest = hashlib.sha256()
    with data_path.open("xb") as stream:
        for row in rows:
            stream.write(row["data"])
            digest.update(row["data"])
        stream.flush()
    meta = {"format": 1, "serial": args.serial,
            "capture_id": args.capture_id, "index": args.window,
            "previous_manifest_sha256": args.previous_manifest,
            "manifest": backend.manifest_fields,
            "proof_verified": backend.proof_verified,
            "collection_verified": backend.collection_verified,
            "window_file_sha256": digest.hexdigest(),
            "chunks": [{"offset": row["offset"], "sha256": row["sha256"],
                        "crc32": row["crc32"]} for row in rows],
            "child_normal_verified": lifecycle["normal_mode_and_driver_verified"],
            "child_code": code}
    save_json(meta_path, meta)
    service.emit("windows_p1_window_saved", index=args.window,
                 capture_id=args.capture_id, count=count,
                 window_sha256=digest.hexdigest())
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--baseline-p1", type=Path)
    parser.add_argument("--baseline-sha256")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--window", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--capture-id", help=argparse.SUPPRESS)
    parser.add_argument("--previous-manifest", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", args.serial),
            "12 hex digit camera USB serial required")
    if args.expected_sha256:
        require(re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256),
                "expected p1 SHA-256 format differs")
    if args.baseline_p1:
        require(re.fullmatch(r"[0-9a-f]{64}", args.baseline_sha256 or ""),
                "saved p1 baseline SHA-256 required")
    out_dir = args.out_dir.resolve()
    require(out_dir.is_relative_to(ROOT.resolve()),
            "p1 directory must be inside the Windows research workspace")
    if not args.execute:
        service.emit("offline_plan", camera_access=False,
                     source="cnflasha1", bytes=25_100_288, windows=3)
        return 0
    return run_child(args, out_dir) if args.child else run_parent(args, out_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError,
            service.ProbeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
