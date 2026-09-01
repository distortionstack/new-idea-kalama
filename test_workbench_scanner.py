from pathlib import Path
import json
import tempfile
import unittest

from src.app.kalama.target.models import CommandResult, ImageIdentity, ImageSourceKind
from src.app.kalama.target.trivy_scanner import scan_image
from src.app.kalama.target.workbench import WorkbenchToolRunner


class RecordingRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout=None):
        args = tuple(argv)
        self.calls.append(args)
        payload = json.dumps({"SchemaVersion": 2, "Results": []})
        return CommandResult(args, 0, payload, "")


class WorkbenchScannerTests(unittest.TestCase):
    def test_trivy_is_routed_to_workbench_with_existing_arguments(self):
        base = RecordingRunner()
        runner = WorkbenchToolRunner(base)
        image = ImageIdentity("example:1", "sha256:immutable", (), None, ("example:1",),
                              "linux/amd64", ImageSourceKind.LOCAL_EXISTING)
        with tempfile.TemporaryDirectory() as root:
            artifact = scan_image(image, Path(root) / "scan.json", runner)
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


if __name__ == "__main__":
    unittest.main()
