#!/usr/bin/env python3
"""Apply and restore locally derived A7C II 2.01 to 2.00 p1 gate workers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sony-service-research"))
import build_p1_gate_200 as builder
import run_backup_snapshot_ro as identity
import service_probe as base
import jiritsu_version_probe as version
import preload_work_preflight_probe as preflight
import raw13_full_producer_probe as producer
import p1_fixed_host_export_201 as p1_host

PACKAGE_SHA = "a3076b2bf3b29ffa879bd35904e4002de10e669721b913796025b27bb5e138de"
PACKAGE_SIZE = 1_139_929_560
STATUS = struct.Struct("<16sIIiIIIQQIIIIQQ")
PREFIX = preflight.PREFIX
SEQUENCES = {
    "inspect": (("dual", "verify_orig"),),
    "install": (("dual", "verify_orig"), ("dual", "apply"),
                ("dual", "verify_patch"), ("triple", "verify_orig"),
                ("triple", "apply"), ("triple", "verify_patch")),
    "restore": (("triple", "verify_patch"), ("triple", "restore"),
                ("triple", "verify_orig"), ("dual", "verify_patch"),
                ("dual", "restore"), ("dual", "verify_orig")),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_manifest(path, full_preflight_path, camera):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    source = Path(manifest.get("source_p1_path", ""))
    target = Path(manifest.get("target_p1_path", ""))
    require(manifest.get("format") == 1 and manifest.get("camera") == "ILCE-7CM2" and
            manifest.get("installed_version") == "2.01" and
            manifest.get("camera_access") is False and
            manifest.get("full_candidate_readback_verified") is True and
            manifest.get("camera_usb_serial") == camera.get("serial_num") and
            target.parent.resolve() == path.parent.resolve() and
            stat.S_ISREG(source.lstat().st_mode) and
            stat.S_ISREG(target.lstat().st_mode),
            "local p1 preparation manifest identity differs")
    preflight = builder.verify_source_report(full_preflight_path, source)
    fat = builder.validate_fat(source, preflight["p1"]["sha256"])
    source_bytes = source.read_bytes()
    candidate, stages = builder.make_candidates(source_bytes)
    require(fat["sha256"] == manifest.get("source_p1_sha256") and
            hashlib.sha256(candidate).hexdigest() == manifest.get("target_p1_sha256") and
            stages == manifest.get("stages") and
            builder.sha(target.read_bytes()) == manifest["target_p1_sha256"],
            "p1 candidate no longer derives from the saved source image")
    with tempfile.TemporaryDirectory() as folder:
        expected = builder.build_worker_templates(Path(folder), stages,
                                                  source_bytes, candidate)
        require(expected == manifest.get("workers"),
                "local p1 worker hashes or parameters differ")
        for stage, entries in expected.items():
            for mode, item in entries.items():
                actual = path.parent / "workers" / item["filename"]
                require(stat.S_ISREG(actual.lstat().st_mode) and
                        actual.read_bytes() ==
                        (Path(folder) / "workers" / item["filename"]).read_bytes(),
                        stage + ":" + mode + " worker bytes differ")
    return manifest


def config_for(stage, mode, manifest, manifest_path):
    detail = next(item for item in manifest["stages"] if item["stage"] == stage)
    worker = manifest["workers"][stage][mode]
    result = "writer" if mode == "apply" else mode
    source_crc = (detail["target_fragment_crc32"] if mode in
                  ("verify_patch", "restore") else detail["source_fragment_crc32"])
    target_crc = (detail["source_fragment_crc32"] if mode == "restore" else
                  detail["target_fragment_crc32"] if mode == "apply" else "00000000")
    return {"stage": stage, "mode": mode, "filename": worker["filename"],
            "elf_path": manifest_path.parent / "workers" / worker["filename"],
            "size": worker["size"], "sha256": worker["sha256"],
            "status": f"codex_p1_{stage}_gate_{result}_200.bin",
            "magic": {"verify_orig": b"CXDP1SIGVORV1\0\0\0",
                      "apply": b"CXDP1SIGLABV1\0\0\0",
                      "verify_patch": b"CXDP1SIGVPAV1\0\0\0",
                      "restore": b"CXDP1SIGRSTV1\0\0\0"}[mode],
            "nonce": (0xa7c2102000019912 if mode in ("verify_patch", "restore")
                      else 0xa7c2102000019911),
            "offset": detail["offset"], "bytes": detail["bytes"],
            "source_crc": int(source_crc, 16), "target_crc": int(target_crc, 16)}


def verify_card_package(camera, card, pmhome):
    mounted = identity.wait_for_camera_volumes(camera, card, pmhome)
    photos = [part for part in mounted if
              part.get("VolumeUUID") == card[1]["VolumeUUID"]]
    require(len(photos) == 1 and photos[0].get("MountPoint"),
            "identified camera photo card must be mounted for DAT readback")
    mountpoint = Path(photos[0]["MountPoint"]).resolve()
    package = mountpoint / "BODYDATA.DAT"
    info = package.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size == PACKAGE_SIZE and
            package.resolve().parent == mountpoint,
            "card BODYDATA.DAT is absent, a link, or the wrong size")
    digest = hashlib.sha256()
    with package.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    require(digest.hexdigest() == PACKAGE_SHA,
            "card BODYDATA.DAT full readback differs from the verified 2.00 package")
    print("card_bodydata_200_verified:", PACKAGE_SHA, flush=True)


def configure_worker(config):
    name = config["filename"]
    producer.ELF_PATH = config["elf_path"]
    producer.ELF_SIZE = config["size"]
    producer.ELF_SHA256 = config["sha256"]
    producer.RAM_PATH = PREFIX + b"/tmp_wbshd/" + name.encode()
    producer.MANIFEST_PATH = PREFIX + b"/tmp_wbshd/" + config["status"].encode()
    producer.ARM_TEXT = b"/tmp_wbshd/" + name.encode() + b"\n"
    producer.RAM_PATH_DATA = producer.PATH_PREFIX + producer.RAM_PATH
    producer.ARM_WRITE_DATA = producer.WRITE_PREFIX + producer.ARM_TEXT
    producer.PATH_BODIES = frozenset(producer.PATH_PREFIX + path for path in
                                     (producer.RAM_PATH, producer.MANIFEST_PATH,
                                      producer.TMP_PRELOAD_PATH, producer.ETC_PRELOAD_PATH))
    producer.MIN_OWNED_PREFIX = len(b"/tmp_wbshd/libcodex_p1_")
    producer.fixed_elf()


def parse_status(raw, config):
    require(isinstance(raw, bytes) and len(raw) == STATUS.size,
            "p1 status length differs")
    (magic, ver, phase, code, rollback, major, minor, capacity,
     patch_at, patch_bytes, source_crc, target_crc, reserved,
     checksum_at, nonce) = STATUS.unpack(raw)
    require(magic == config["magic"] and ver == 1 and phase in (6, 8, 9) and
            major == 252 and minor == 129 and capacity == 25_100_288 and
            patch_at == config["offset"] and patch_bytes == config["bytes"] and
            checksum_at == 16_253_440 and nonce == config["nonce"] and
            reserved == 0 and source_crc == config["source_crc"] and
            target_crc in (0, config["target_crc"]) and rollback in (0, 1),
            "p1 status identity or geometry differs")
    return {"phase": phase, "camera_status": code,
            "rollback_verified": rollback == 1,
            "p1_crc_before": source_crc, "p1_crc_after": target_crc,
            "status_sha256": hashlib.sha256(raw).hexdigest(),
            "selected_kernel_name": "cnflasha1",
            "selected_major": major, "selected_minor": minor}


class P1Session(producer.ProducerSession):
    def _read_fixed(self, dev, label, path):
        if label.startswith("manifest_result_"):
            deadline = time.monotonic() + 25
            while True:
                super()._read_fixed(dev, label, path)
                state, raw = self.backend.files[label]
                if (state == "present" and isinstance(raw, bytes) and
                        len(raw) == STATUS.size and STATUS.unpack(raw)[2] in (6, 8, 9)):
                    return
                if time.monotonic() >= deadline:
                    return
                time.sleep(0.1)
        return super()._read_fixed(dev, label, path)


class P1Budget(producer.ProducerBudget):
    def timeout_ms(self, requested=1000):
        if not self.long_trigger or self.recovering:
            return super().timeout_ms(requested)
        self.check()
        self.calls += 1
        self.work_calls += 1
        require(self.work_calls <= 2600, "p1 bounded USB work budget exceeded")
        return max(1, min(45000, int(self.remaining() * 1000)))


class P1Backend(producer.ProducerBackend):
    def open(self, info):
        self.require_known_pid(info)
        if info["pid"] in base.SERVICE_PIDS and info["pid"] != version.SERVICE_PID:
            raise version.JiritsuProbeError("unverified_service_pid")
        session = P1Session(self, info)
        self.sessions.append(session)
        return session.open()


def compact_logger():
    logger = version.safe_logger()
    def log(event, **fields):
        if event in ("target_verified", "probe_failed", "normal_mode_verified",
                     "probe_summary"):
            logger(event, **fields)
    return log


def run_variant(config, usb_parts):
    configure_worker(config)
    producer.parse_manifest = lambda raw: parse_status(raw, config)
    core, util, auth, senser, camera, explicit = usb_parts
    backend = P1Backend(core, util, auth, senser, camera,
                        version.MSC_PID, version.PRODUCT,
                        budget=P1Budget(), usb_backend=explicit,
                        logger=compact_logger())
    code, lifecycle = base.run_probe(backend)
    summary = producer.summarize(backend,
                                 lifecycle["normal_mode_and_driver_verified"])
    marker = backend.manifest_fields or {}
    require(code == 0 and summary["product_verified"] and
            summary["proof_verified"] and summary["cleanup_absence_verified"] and
            summary["normal_mode_and_driver_verified"] and
            marker.get("phase") == 6 and marker.get("camera_status") == 0 and
            marker.get("p1_crc_after") == config["target_crc"],
            "p1 phase failed or normal USB recovery unverified")
    print(json.dumps({"stage": config["stage"], "mode": config["mode"],
                      "status": "verified", "marker": marker}, sort_keys=True), flush=True)
    return marker


def receipt_path(manifest_path):
    return manifest_path.parent / "p1_gate_200_install_receipt.json"


def write_install_receipt(manifest_path, manifest, steps):
    data = {"format": 1, "camera_serial": manifest["camera_usb_serial"],
            "source_p1_sha256": manifest["source_p1_sha256"],
            "expected_triple_p1_sha256": manifest["target_p1_sha256"],
            "card_package_sha256": PACKAGE_SHA,
            "steps": steps, "all_steps_verified": True}
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    path = receipt_path(manifest_path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, int(os.environ.get("SUDO_UID", os.geteuid())),
                  int(os.environ.get("SUDO_GID", os.getegid())))
        require(os.write(fd, raw) == len(raw), "short p1 receipt write")
        os.fsync(fd)
    finally:
        os.close(fd)
    print("p1_install_receipt:", path, flush=True)


def verify_install_receipt(manifest_path, manifest):
    path = receipt_path(manifest_path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_nlink == 1, "p1 installation receipt identity differs")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    steps = receipt.get("steps") or []
    expected = [list(pair) for pair in SEQUENCES["install"]]
    actual = [[item.get("stage"), item.get("mode")] for item in steps]
    require(receipt.get("format") == 1 and
            receipt.get("camera_serial") == manifest["camera_usb_serial"] and
            receipt.get("source_p1_sha256") == manifest["source_p1_sha256"] and
            receipt.get("expected_triple_p1_sha256") == manifest["target_p1_sha256"] and
            receipt.get("card_package_sha256") == PACKAGE_SHA and
            receipt.get("all_steps_verified") is True and actual == expected and
            all(isinstance(item.get("status_sha256"), str) and
                len(item["status_sha256"]) == 64 for item in steps),
            "p1 installation receipt incomplete or belongs to another body")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-json", type=Path, required=True)
    parser.add_argument("--full-preflight-json", type=Path, required=True)
    parser.add_argument("--p1-manifest", type=Path, required=True)
    parser.add_argument("--action", choices=tuple(SEQUENCES), required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "darwin", "macOS required")
    report = json.loads(args.probe_json.read_text(encoding="utf-8"))
    camera, card, pmhome = identity.report_identity(report)
    manifest = load_manifest(args.p1_manifest, args.full_preflight_json, camera)
    variants = [config_for(stage, mode, manifest, args.p1_manifest)
                for stage, mode in SEQUENCES[args.action]]
    if not args.execute:
        print(json.dumps({"camera_access": False, "action": args.action,
                          "camera_serial": camera["serial_num"],
                          "steps": [c["stage"] + ":" + c["mode"] for c in variants]}))
        return 0
    require(os.geteuid() == 0, "sudo with the configured Python is required")
    if args.action == "install":
        path = receipt_path(args.p1_manifest)
        require(not path.exists() and not path.is_symlink(),
                "p1 install receipt already exists; inspect before another write")
        verify_card_package(camera, card, pmhome)
    p1_host.set_probe_report(report)
    usb_parts = p1_host._usb_backend()
    completed = []
    for index, config in enumerate(variants, 1):
        print(f"p1_step: {index}/{len(variants)} {config['stage']}:{config['mode']}", flush=True)
        identity.ensure_camera_volumes_unmounted(camera, card, pmhome)
        marker = run_variant(config, usb_parts)
        completed.append({"stage": config["stage"], "mode": config["mode"],
                          "status_sha256": marker["status_sha256"]})
    if args.action == "install":
        write_install_receipt(args.p1_manifest, manifest, completed)
    print("p1_action_complete:", args.action, flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error:", exc, file=sys.stderr)
        raise SystemExit(1)
