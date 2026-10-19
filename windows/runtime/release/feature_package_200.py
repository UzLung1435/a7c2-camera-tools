"""Build and identify the selected A7C II 2.00 feature package."""

import argparse
import json
from pathlib import Path

import sound_package_200 as sound

firmware = sound.firmware
MANIFEST_NAME = sound.MANIFEST_NAME
FL23_SHA = "a3076b2bf3b29ffa879bd35904e4002de10e669721b913796025b27bb5e138de"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def features(fl23, audio_mode):
    require(type(fl23) is bool and audio_mode in ("none", "stock", "custom") and
            (fl23 or audio_mode != "none"), "feature selection is empty or invalid")
    return (["fl2_fl3"] if fl23 else []) + (
        [] if audio_mode == "none" else ["electronic_shutter_sound"] +
        (["custom_audio"] if audio_mode == "custom" else []))


def selected(manifest_path, audio=None):
    manifest_path = Path(manifest_path)
    require(not manifest_path.is_symlink() and manifest_path.name == MANIFEST_NAME and
            manifest_path.is_file(), "selected package manifest is missing or linked")
    report = json.loads(manifest_path.read_text(encoding="utf-8"))
    fl23 = report.get("fl23") if "fl23" in report else \
        "fl2_fl3" in report.get("feature_ids", [])
    mode = report.get("audio_mode")
    ids = features(fl23, mode)
    require(report.get("format") == 2 and report.get("feature_ids") == ids and
            report.get("source_official_sha256") == firmware.SOURCE_SHA and
            report.get("package_version") == "2.00" and
            report.get("full_decrypt_verified") is True and
            report.get("output_size") == sound.PACKAGE_SIZE,
            "selected package manifest differs")
    if mode == "none":
        output = Path(report.get("output_path", ""))
        require(fl23 and output.name == firmware.OUT_NAME and
                report.get("output_sha256") == FL23_SHA,
                "FL2/FL3 package identity differs")
    else:
        output = manifest_path.with_name(sound.OUTPUT_NAME)
        expected_base = FL23_SHA if fl23 else firmware.SOURCE_SHA
        require(report.get("base_package_sha256") == expected_base and
                report.get("sound_patch_spec_sha256") == sound.SPEC_SHA and
                type(report.get("volume_percent")) is int and
                1 <= report["volume_percent"] <= 100 and
                (mode == "custom" or report["volume_percent"] == 100),
                "sound package identity differs")
        if mode == "stock":
            require(report.get("source_audio_sha256") is None and
                    report.get("encoded_audio_sha256") is None and
                    report.get("cp", {}).get("sys_sound_sha256") ==
                    sound.spec_data()["original_sys_sound_sha256"] and
                    report.get("registration_length_bytes") == 0x4c0,
                    "stock camera sound was changed")
        else:
            require(all(isinstance(report.get(field), str) and
                        len(report[field]) == 64 for field in
                        ("source_audio_sha256", "encoded_audio_sha256")) and
                    isinstance(report.get("registration_length_bytes"), int) and
                    0 < report["registration_length_bytes"] <= 0xffff,
                    "custom sound proof differs")
            if audio is not None:
                require(firmware.sha_file(Path(audio)) ==
                        report["source_audio_sha256"],
                        "selected custom audio changed")
    require(not output.is_symlink() and output.is_file() and
            output.stat().st_size == sound.PACKAGE_SIZE,
            "selected DAT is missing or has the wrong size: " + str(output))
    actual = firmware.sha_file(output)
    if actual != report.get("output_sha256"):
        # A package that fails its own DEND CRC is damaged on disk, not merely
        # a different build: the build is deterministic, so the only correct
        # recovery is to rebuild it from the untouched official 2.01 DAT.
        try:
            firmware.parse_dat(output)
        except ValueError as exc:
            raise ValueError(
                "selected DAT is corrupt (" + str(exc) + ") at " + str(output) +
                "; hash " + actual[:16] + "... differs from the recorded " +
                str(report.get("output_sha256"))[:16] +
                "... - rebuild it from the official 2.01 DAT") from exc
        raise ValueError(
            "selected DAT full hash differs: " + actual +
            " != " + str(report.get("output_sha256")) + " at " + str(output))
    return output, report["output_sha256"]


def build(official, run_dir, fl23, audio_mode, audio=None, volume_percent=100):
    official, run_dir = Path(official), Path(run_dir)
    require(not official.is_symlink() and not run_dir.is_symlink(),
            "official DAT or run directory is a link")
    official, run_dir = official.resolve(), run_dir.resolve()
    ids = features(fl23, audio_mode)
    require(official.is_file() and not official.is_symlink() and
            firmware.sha_file(official) == firmware.SOURCE_SHA and
            run_dir.is_dir() and not run_dir.is_symlink(),
            "official 2.01 or private run directory differs")
    manifest = run_dir / MANIFEST_NAME
    if audio_mode == "none":
        require(audio is None and volume_percent == 100,
                "FL2/FL3-only selection has sound options")
        output = firmware.build(official)
        require(firmware.sha_file(output) == FL23_SHA,
                "FL2/FL3 output hash differs")
        report = {"format": 2, "feature_ids": ids, "fl23": True,
                  "audio_mode": "none", "volume_percent": 100,
                  "source_official_sha256": firmware.SOURCE_SHA,
                  "output_path": str(output), "output_sha256": FL23_SHA,
                  "output_size": sound.PACKAGE_SIZE,
                  "package_version": "2.00", "full_decrypt_verified": True,
                  "camera_access": False}
        if manifest.exists():
            require(json.loads(manifest.read_text(encoding="utf-8")) == report,
                    "existing selected feature plan differs")
        else:
            with manifest.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
    else:
        output, report = sound.build(official, fl23, audio_mode, audio,
                                     volume_percent, run_dir / sound.OUTPUT_NAME)
        require(report["feature_ids"] == ids, "built sound features differ")
    verified, digest = selected(manifest, audio)
    require(verified == output and digest == report["output_sha256"],
            "selected package does not match its builder")
    return verified, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--fl23", action="store_true")
    parser.add_argument("--audio-mode", choices=("none", "stock", "custom"),
                        required=True)
    parser.add_argument("--audio", type=Path)
    parser.add_argument("--volume", type=int, default=100)
    args = parser.parse_args()
    output, manifest = build(args.official, args.out_dir, args.fl23,
                             args.audio_mode, args.audio, args.volume)
    print(json.dumps({"event": "feature_package_200_built",
                      "output": str(output), "manifest": str(manifest),
                      "sha256": selected(manifest)[1],
                      "feature_ids": features(args.fl23, args.audio_mode),
                      "camera_access": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser_error = f"error: {exc}"
        raise SystemExit(parser_error)
