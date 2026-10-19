import argparse
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mac_service_readonly"))
import a7c2_200_oneclick as flow
import ui


class SoundOnlyFlowTests(unittest.TestCase):
    def test_builtin_sound_choice_needs_no_file(self):
        console = ui.Console("en")
        with patch.object(ui, "key", side_effect=["2", "1"]), \
                patch.object(console, "_prompt"), \
                patch.object(console, "_clear_prompt"):
            plan = console.features()
        self.assertEqual(plan, {"fl23": False, "audio_mode": "stock",
                                "audio_path": None, "volume_percent": 100})

    def test_after_p1_restore_skips_color_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = {"status": "p1_restored", "feature_plan": {
                "fl23": False, "audio_mode": "stock", "audio_path": None,
                "volume_percent": 100},
                "full_preflight_json": str(root / "preflight.json"),
                "p1_manifest": str(root / "p1.json")}
            actions = []

            class Screen:
                def selected_features(self, plan):
                    pass

                def progress(self, status):
                    pass

                def manual(self, label):
                    actions.append(label)
                    return True

                def action(self, label):
                    pass

                def note_pair(self, pair):
                    pass

            def save(_path, current, status, **fields):
                current.update(fields, status=status)

            camera = {"serial_num": "D11D00738A68"}
            with patch.object(flow, "SCREEN", Screen()), \
                    patch.object(flow, "probe_camera", return_value=(
                        root / "probe.json", camera, root)), \
                    patch.object(flow, "load_state", return_value=(
                        root / "workflow.json", state)), \
                    patch.object(flow.gate, "load_manifest", return_value={}), \
                    patch.object(flow, "save_state", side_effect=save), \
                    patch.object(flow, "cp_runtime_action",
                                 side_effect=AssertionError("unexpected CP access")), \
                    patch.object(flow, "run_file",
                                 side_effect=AssertionError("unexpected camera worker")):
                flow.resume_run(argparse.Namespace(
                    official=None, full_preflight_json=None))

            self.assertEqual(state["status"], "complete")
            self.assertTrue(state["sound_cold_verified"])
            self.assertEqual(actions, ["COLD", "SOUND OK"])


if __name__ == "__main__":
    unittest.main()
