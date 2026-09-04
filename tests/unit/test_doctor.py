from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kalama.doctor import run_doctor
from kalama.target.models import CommandResult


class FakeRunner:
    def __init__(self, failures=(), *, stopped=False):
        self.failures = set(failures)
        self.stopped = stopped
        self.calls = []

    def run(self, argv, *, timeout=None):
        args = tuple(argv)
        self.calls.append(args)
        key = {
            ("docker", "--version"): "docker_cli",
            ("docker", "info"): "docker_daemon",
            ("docker", "network"): "network",
        }.get(args[:2], "running")
        if args[:3] == ("docker", "container", "inspect"):
            key = "workbench" if args[-1] == "kalama-workbench-modern" else "container"
        elif args[:4] == ("docker", "exec", "kalama-workbench-modern", "trivy"):
            key = "trivy"
        elif args[:4] == ("docker", "exec", "kalama-workbench-modern", "docker"):
            key = "workbench_docker"
        if key in self.failures:
            code = 127 if key in ("docker_cli", "trivy") else 1
            return CommandResult(args, code, "", f"{key} failed")
        if key == "running":
            return CommandResult(args, 0, "false\n" if self.stopped else "true\n", "")
        if key == "trivy":
            return CommandResult(args, 0, "Version: 0.74.0\n", "")
        return CommandResult(args, 0, "1.0\n", "")


class DoctorTests(unittest.TestCase):
    def report(self, failures=(), *, create_root=True, stopped=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "output"
        if create_root:
            root.mkdir()
        runner = FakeRunner(failures, stopped=stopped)
        return run_doctor(root, runner=runner), runner

    def test_all_checks_pass(self):
        report, _ = self.report()
        self.assertTrue(report.ready)

    def test_trivy_missing(self):
        report, _ = self.report(("trivy",))
        self.assertFalse(report.ready)

    def test_docker_cli_missing(self):
        report, _ = self.report(("docker_cli",))
        self.assertFalse(report.ready)

    def test_docker_daemon_unreachable(self):
        report, _ = self.report(("docker_daemon",))
        self.assertFalse(report.ready)

    def test_network_missing(self):
        report, _ = self.report(("network",))
        self.assertFalse(report.ready)

    def test_msf_container_missing_or_stopped(self):
        missing, _ = self.report(("container",))
        stopped, _ = self.report(stopped=True)
        self.assertFalse(missing.ready)
        self.assertFalse(stopped.ready)

    def test_workbench_missing_or_socket_unreachable(self):
        missing, _ = self.report(("workbench",))
        socket, _ = self.report(("workbench_docker",))
        self.assertFalse(missing.ready)
        self.assertFalse(socket.ready)

    def test_host_trivy_is_irrelevant_when_workbench_trivy_works(self):
        report, runner = self.report()
        self.assertTrue(report.ready)
        self.assertNotIn(("trivy", "--version"), runner.calls)
        self.assertIn(("docker", "exec", "kalama-workbench-modern", "trivy", "--version"),
                      runner.calls)

    def test_output_root_missing(self):
        report, _ = self.report(create_root=False)
        self.assertFalse(report.ready)

    def test_output_root_unwritable(self):
        with patch("kalama.doctor.tempfile.NamedTemporaryFile",
                   side_effect=PermissionError("denied")):
            report, _ = self.report()
        self.assertFalse(report.ready)
        self.assertIn("OUTPUT_ROOT_UNWRITABLE",
                      next(x.message for x in report.checks if x.check_id == "OUTPUT_ROOT"))

    def test_doctor_commands_are_read_only(self):
        _, runner = self.report()
        forbidden = {"create", "run", "start", "rm", "pull", "prune", "apt", "pip"}
        for command in runner.calls:
            self.assertTrue(forbidden.isdisjoint(command), command)


if __name__ == "__main__":
    unittest.main()
