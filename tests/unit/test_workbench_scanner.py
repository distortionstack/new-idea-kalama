from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from kalama.target.models import CommandResult, ImageIdentity, ImageSourceKind
from kalama.target.trivy_scanner import scan_image
from kalama.target.victim_manager import Step2OperationError, SubprocessCommandRunner
from kalama.target.workbench import WorkbenchToolRunner


class RecordingRunner:
    def __init__(self):
        self.calls = []
        self.result = None

    def run(self, argv, *, timeout=None):
        args = tuple(argv)
        self.calls.append(args)
        if self.result is not None:
            return self.result
        payload = json.dumps({"SchemaVersion": 2, "Results": []})
        return CommandResult(args, 0, payload, "", payload.encode("utf-8"), b"")


class WorkbenchScannerTests(unittest.TestCase):
    def image(self):
        return ImageIdentity("example:1", "sha256:immutable", (), None, ("example:1",),
                             "linux/amd64", ImageSourceKind.LOCAL_EXISTING)

    def test_trivy_is_routed_to_workbench_with_existing_arguments(self):
        base = RecordingRunner()
        runner = WorkbenchToolRunner(base)
        with tempfile.TemporaryDirectory() as root:
            artifact = scan_image(self.image(), Path(root) / "scan.json", runner)
        command = base.calls[0]
        self.assertEqual(command[:4], ("docker", "exec", "kalama-workbench-modern", "trivy"))
        self.assertEqual(command[4:6], ("image", "--scanners"))
        self.assertIn("vuln", command)
        self.assertIn("--list-all-pkgs", command)
        self.assertIn("--format", command)
        self.assertNotIn("--output", command)
        self.assertEqual(command[-1], "sha256:immutable")
        self.assertEqual(artifact.schema_version, 2)

    def test_non_trivy_commands_remain_host_commands_and_no_fallback_exists(self):
        base = RecordingRunner()
        runner = WorkbenchToolRunner(base)
        runner.run(("docker", "image", "inspect", "example"))
        self.assertEqual(base.calls, [("docker", "image", "inspect", "example")])

    def test_utf8_json_survives_windows_cp874_incompatible_bytes(self):
        payload = json.dumps({"SchemaVersion": 2, "Results": [],
                              "Metadata": {"label": "scan ok \u2713"}},
                             ensure_ascii=False).encode("utf-8")
        with self.assertRaises(UnicodeDecodeError):
            payload.decode("cp874")
        base = RecordingRunner()
        base.result = CommandResult(("docker", "exec", "kalama-workbench-modern", "trivy"),
                                    0, payload.decode("utf-8"), "", payload, b"")
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "scan.json"
            artifact = scan_image(self.image(), output, WorkbenchToolRunner(base))
            self.assertEqual(artifact.schema_version, 2)
            self.assertEqual(output.read_bytes(), payload)

    def test_invalid_utf8_scanner_output_is_structured_json_failure(self):
        base = RecordingRunner()
        base.result = CommandResult(("docker", "exec", "kalama-workbench-modern", "trivy"),
                                    0, "", "", b"\x9c", b"")
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "scan.json"
            with self.assertRaises(Step2OperationError) as caught:
                scan_image(self.image(), output, WorkbenchToolRunner(base))
            self.assertEqual(caught.exception.issue.code.value, "TRIVY_INVALID_JSON")
            self.assertIn("utf-8", caught.exception.issue.message)
            self.assertFalse(output.exists())

    def test_subprocess_failure_preserves_stderr_without_stdout(self):
        completed = subprocess.CompletedProcess(("docker", "exec"), 2, stdout=None,
                                                stderr=b"trivy failed \x9c")
        with patch("kalama.target.victim_manager.subprocess.run", return_value=completed) as run:
            result = SubprocessCommandRunner().run(("docker", "exec"))
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stdout_bytes, b"")
        self.assertIn("trivy failed", result.stderr)
        self.assertEqual(result.stderr_bytes, b"trivy failed \x9c")
        self.assertFalse(run.call_args.kwargs["text"])

    def test_subprocess_timeout_bytes_are_decoded_for_diagnostics(self):
        error = subprocess.TimeoutExpired(("docker", "exec"), 1,
                                          output=b"partial \xe2\x9c\x93",
                                          stderr=None)
        with patch("kalama.target.victim_manager.subprocess.run", side_effect=error):
            result = SubprocessCommandRunner().run(("docker", "exec"), timeout=1)
        self.assertEqual(result.exit_code, 124)
        self.assertIn("partial \u2713", result.stdout)
        self.assertEqual(result.stderr, "command timed out")


if __name__ == "__main__":
    unittest.main()
