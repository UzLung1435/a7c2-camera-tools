import sys
from pathlib import Path
import unittest
from unittest.mock import patch

RUNTIME = Path(__file__).resolve().parents[1] / "runtime"
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME / "core"))
sys.path.insert(0, str(RUNTIME / "core" / "sony-service-research"))
import service_probe as base
import windows_service_probe as windows
import windows_usb_adapter as adapter


class FakeBudget:
    recovering = False
    end = 1e18


class FakeDevice:
    def __init__(self, pid, address=5, ports=(1,), bus=2):
        self.idProduct = pid
        self.address = address
        self.port_numbers = ports
        self.bus = bus


class FakeCore:
    def __init__(self, devices):
        self.devices = devices

    def find(self, find_all=False, idVendor=None, backend=None):
        return list(self.devices)


class FakeBackend:
    """Minimal stand-in for the p1/bk4/cp backends the adapter patches."""

    def __init__(self, devices=()):
        self.budget = FakeBudget()
        self.expected_pid = 0x0E8A
        self.usb_core = FakeCore(devices)
        self.usb_backend = None
        self.events = []

    def log(self, event, **fields):
        self.events.append((event, fields))

    def check_target(self, info, initial=None, service=False):
        pass


class AdapterBindingTests(unittest.TestCase):
    """One implementation only.

    The adapter used to carry its own copy of the recovery enumerate and
    verify steps. The copy kept the obsolete "address must change" restore
    test, so every p1/bk4/cp child rejected a camera that had restored
    correctly while the module's own copy had already been fixed.
    """

    def patched(self, devices=()):
        backend = FakeBackend(devices)
        with patch.object(adapter, "require_winusb", return_value={"devices": [],
                                                                  "disks": []}):
            adapter.install(backend, "D11D0075B240")
        return backend

    def test_adapter_binds_the_module_implementation(self):
        backend = self.patched()
        self.assertIs(backend.enumerate.__func__, windows.recovery_enumerate)
        self.assertIs(backend.verify_normal_driver.__func__,
                      windows.windows_verify_normal)
        self.assertIs(backend.wait_service.__func__, windows.windows_wait_service)
        self.assertIs(windows.WindowsBackend.enumerate, windows.recovery_enumerate)
        self.assertIs(windows.WindowsBackend.verify_normal_driver,
                      windows.windows_verify_normal)

    def test_unchanged_usb_address_still_verifies(self):
        backend = self.patched()
        backend.windows_initial_address = 5
        info = {"pid": 0x0E8A, "address": 5, "bus": 2, "ports": (1,)}
        with patch.object(windows, "require_winusb",
                          return_value={"devices": [], "disks": []}) as gate:
            backend.verify_normal_driver(info, False)
        self.assertEqual(gate.call_count, 1)
        self.assertEqual(backend.events[0][0], "normal_winusb_verified")
        self.assertFalse(backend.events[0][1]["address_changed"])

    def test_overlapping_reenumeration_is_not_an_ambiguity(self):
        backend = self.patched([FakeDevice(0x0336), FakeDevice(0x0E8A)])
        backend.budget.recovering = True
        self.assertIsNone(backend.enumerate())
        self.assertEqual(backend.events[0][0], "recovery_reenumeration_overlap")

    def test_recovered_node_is_reported_once_per_pid(self):
        backend = self.patched([FakeDevice(0x0E8A)])
        backend.budget.recovering = True
        info = backend.enumerate()
        self.assertEqual(info["pid"], 0x0E8A)
        self.assertEqual(info["class"], base.MSC_CLASS)
        self.assertEqual(info["address"], 5)


class StaleStagingResetTests(unittest.TestCase):
    """The window-0 self-heal must run the reset probe as its own process.

    ``windows_p1_window_reset.main()`` parses ``sys.argv`` and takes no
    arguments, so calling it in-process both raised TypeError and would have
    parsed the capture's own command line.
    """

    def setUp(self):
        import windows_p1_capture
        self.capture = windows_p1_capture

    def run_with(self, stdout, stderr=""):
        done = self.capture.subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=stderr)
        with patch.object(self.capture.subprocess, "run", return_value=done) as run, \
                patch.object(self.capture.service, "emit"), \
                patch.object(self.capture, "verify_normal_in_new_process"):
            self.capture.reset_stale_staging("D11D0075B240")
        return run

    def test_reset_runs_as_a_separate_process(self):
        import json
        receipt = {"event": "windows_p1_window_reset", "serial": "D11D0075B240",
                   "product_verified": True, "reset_complete": True,
                   "deleted": ["ram", "request"],
                   "stale_request": {"capture_id": "b13c268a6407", "window_index": 0}}
        run = self.run_with(json.dumps(receipt) + "\n")
        command = run.call_args[0][0]
        self.assertEqual(Path(command[1]).name, "windows_p1_window_reset.py")
        self.assertEqual(command[2:], ["--serial", "D11D0075B240", "--execute"])
        self.assertEqual(run.call_args[1]["timeout"], 420)

    def test_incomplete_receipt_is_a_loud_failure(self):
        import json
        receipt = {"event": "windows_p1_window_reset", "product_verified": True,
                   "reset_complete": False, "deleted": [],
                   "ram_before": {"state": "present", "bytes": 9520},
                   "request_before": {"state": "present", "bytes": 64},
                   "child_code": 3}
        with self.assertRaises(base.ProbeError) as caught:
            self.run_with(json.dumps(receipt) + "\n")
        message = str(caught.exception)
        self.assertIn("could not be reset", message)
        self.assertIn("child_code=3", message)

    def test_missing_receipt_keeps_the_child_error(self):
        with self.assertRaises(base.ProbeError) as caught:
            self.run_with("", "error: target 0e8a must be present and bound to WinUSB\n")
        self.assertIn("no receipt", str(caught.exception))
        self.assertIn("bound to WinUSB", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
