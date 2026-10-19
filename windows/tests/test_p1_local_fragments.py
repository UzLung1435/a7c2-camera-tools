import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "core"))
import build_p1_gate_200 as builder


class LocalFragmentTests(unittest.TestCase):
    def test_repository_templates_have_empty_fragment_slots(self):
        self.assertEqual(list(builder.ASSETS.glob("frag*.bin")), [])
        for stage in builder.FRAGMENTS:
            for mode, (size, expected_hash, _, slot, _) in \
                    builder.TEMPLATES[stage["stage"]].items():
                template = (builder.ASSETS / "templates" /
                            f"libcodex_p1_{stage['stage']}_gate_{mode}_template_200.so")
                raw = template.read_bytes()
                self.assertEqual(len(raw), size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected_hash)
                self.assertEqual(raw[slot:slot + stage["size"]],
                                 bytes(stage["size"]))
                for sites in builder.CONSTANT_SITES[stage["stage"]][mode]:
                    for at in sites:
                        word = struct.unpack_from("<I", raw, at)[0]
                        self.assertEqual((word >> 5) & 0xffff, 0)

    def test_source_must_appear_once_in_the_captured_p1_data(self):
        fragment = zlib.compress(b"camera-owned-test-data" * 32, 9)
        spec = {"stage": "sample", "size": len(fragment),
                "source_sha256": hashlib.sha256(fragment).hexdigest()}
        location, found = builder.source_fragment(b"padding" + fragment, spec)
        self.assertEqual((location, found), (7, fragment))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            builder.source_fragment(fragment + fragment, spec)

    def test_generated_fragment_has_no_trailing_compressed_bytes(self):
        plain = b"test-data" * 200
        compressor = zlib.compressobj(level=9)
        expected = (compressor.compress(plain[:100]) +
                    compressor.flush(zlib.Z_SYNC_FLUSH) +
                    compressor.compress(plain[100:]) +
                    compressor.flush(zlib.Z_FINISH))
        result = builder.compress_fragment(
            plain, {"stage": "sample", "size": len(expected), "sync_at": 100})
        decoder = zlib.decompressobj()
        self.assertEqual(decoder.decompress(result) + decoder.flush(), plain)
        self.assertTrue(decoder.eof)
        self.assertEqual(decoder.unused_data, b"")


if __name__ == "__main__":
    unittest.main()
