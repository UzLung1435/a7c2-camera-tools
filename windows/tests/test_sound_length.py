from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "windows" / "runtime" / "release"))
import sound_package_200 as sound


class SoundLengthTests(unittest.TestCase):
    def test_duration_is_preserved_and_only_last_frame_is_padded(self):
        settings = sound.spec_data()["audio"]
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "user.wav"
            source.write_bytes(b"audio input")
            for samples, expected_bytes, padding in (
                    (12_000, 12_416, 28),
                    (45_600, 47_072, 1),
                    (48_000, 49_568, 19)):
                pcm = np.zeros(samples, dtype="<f4")
                pcm[0], pcm[-1] = 0.5, -0.5
                decoded = SimpleNamespace(returncode=0, stdout=pcm.tobytes(), stderr=b"")
                with patch.object(sound, "ffmpeg_executable", return_value="ffmpeg"), \
                        patch.object(sound.subprocess, "run", return_value=decoded):
                    result, report = sound.encode_audio(source, settings)
                self.assertEqual((len(result), report["samples"],
                                  report["tail_padding_samples"]),
                                 (expected_bytes, samples, padding))
                last = (samples - 1) // 31 * 32 + 1 + (samples - 1) % 31
                self.assertEqual(result[last], 156)

    def test_registration_length_tracks_resource(self):
        cave = next(item for item in sound.spec_data()["app_spans"]
                    if item["name"] == "registration_cave")
        self.assertEqual(sound.replacement_for(cave, 47_776),
                         bytes.fromhex(cave["new"]))
        modified = sound.replacement_for(cave, 49_568)
        self.assertEqual((struct.unpack("<I", modified[:4])[0] >> 5) & 0xffff,
                         49_568)
        self.assertEqual(modified[4:], bytes.fromhex(cave["new"])[4:])

    def test_percentage_scales_custom_audio_without_changing_duration(self):
        settings = sound.spec_data()["audio"]
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "fah.wav"
            source.write_bytes(b"audio input")
            pcm = np.linspace(-0.5, 0.5, 2400, dtype="<f4")
            decoded = SimpleNamespace(returncode=0, stdout=pcm.tobytes(), stderr=b"")
            with patch.object(sound, "ffmpeg_executable", return_value="ffmpeg"), \
                    patch.object(sound.subprocess, "run", return_value=decoded):
                full, full_report = sound.encode_audio(source, settings, 100)
                half, half_report = sound.encode_audio(source, settings, 50)
            full_samples = np.frombuffer(full, dtype=np.uint8).reshape(-1, 32)[:, 1:].view(np.int8)
            half_samples = np.frombuffer(half, dtype=np.uint8).reshape(-1, 32)[:, 1:].view(np.int8)
            self.assertEqual((len(full), full_report["samples"]),
                             (len(half), half_report["samples"]))
            self.assertEqual((np.max(np.abs(full_samples.astype(np.int16))),
                              np.max(np.abs(half_samples.astype(np.int16)))),
                             (100, 50))
            self.assertEqual((set(full[::32]), set(half[::32])), ({5}, {5}))
            with self.assertRaisesRegex(ValueError, "1..100"):
                sound.encode_audio(source, settings, 101)


if __name__ == "__main__":
    unittest.main()
