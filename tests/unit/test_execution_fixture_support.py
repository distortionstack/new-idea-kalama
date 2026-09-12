import tempfile
import unittest
from pathlib import Path

from kalama.execution.executor import DockerMetasploitExecutor
from kalama.execution.models import ExecutionPlan, OperationState
from kalama.metasploit_fixtures import build_registry
from kalama.target.models import CommandResult


class FakeRunner:
    def __init__(self, *, cp_exit=0):
        self.calls = []
        self.cp_exit = cp_exit

    def run(self, argv, *, timeout=None):
        args = tuple(str(x) for x in argv)
        self.calls.append(args)
        if args[:2] == ("docker", "cp") and self.cp_exit != 0:
            return CommandResult(args, self.cp_exit, "", "copy failed")
        if args[:3] == ("docker", "exec", "msf-resolver-host") and "msfconsole" in args:
            return CommandResult(args, 0, "[+] target vulnerable\n", "")
        return CommandResult(args, 0, "", "")


def plan(**overrides):
    values = dict(
        cve_id="CVE-2099-0001",
        rank=1,
        module="exploit/test/example",
        target_index=0,
        target_name="Automatic",
        module_options=(("RHOSTS", "172.18.0.3"), ("RPORT", 9200)),
        payload=None,
        payload_options=(),
        run_check=True,
        run_exploit=False,
        session_confirmation_expected=False,
        precondition_commands=(),
        precondition_target=None,
        precondition_required=False,
        pre_attack_command=None,
        pre_attack_target=None,
    )
    values.update(overrides)
    return ExecutionPlan(**values)


class DockerMetasploitFixtureExecutorTests(unittest.TestCase):
    def fixture_registry(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name) / "modules"
        module = root / "exploits" / "test" / "example_compat.rb"
        module.parent.mkdir(parents=True)
        module.write_text("class MetasploitModule < Msf::Exploit::Remote\nend\n", encoding="utf-8")
        return build_registry([root])

    def tearDown(self):
        temp = getattr(self, "temp", None)
        if temp is not None:
            temp.cleanup()

    def test_stock_execution_does_not_load_fixture_paths(self):
        runner = FakeRunner()
        executor = DockerMetasploitExecutor(runner, fixture_registry=build_registry([]))
        result = executor.check(plan(), timeout=30)
        msf_call = runner.calls[-1]

        self.assertEqual(result.operation.state, OperationState.EXECUTED)
        self.assertNotIn("loadpath", msf_call[-1])
        self.assertIn("use exploit/test/example", msf_call[-1])
        self.assertFalse(any(call[:2] == ("docker", "cp") for call in runner.calls))

    def test_fixture_execution_loads_approved_path_and_preserves_identity(self):
        registry = self.fixture_registry()
        fixture = registry.module("exploit/test/example_compat")
        runner = FakeRunner()
        executor = DockerMetasploitExecutor(runner, fixture_registry=registry)
        result = executor.check(plan(
            module="exploit/test/example_compat",
            module_source="lab_fixture",
            fixture_source_path=fixture.source_path,
            fixture_sha256=fixture.sha256,
        ), timeout=30)
        msf_call = runner.calls[-1]

        self.assertEqual(result.operation.state, OperationState.EXECUTED)
        self.assertTrue(any(call[:2] == ("docker", "cp") for call in runner.calls))
        self.assertIn(f"loadpath {fixture.container_modules_root}", msf_call[-1])
        self.assertIn("use exploit/test/example_compat", msf_call[-1])

    def test_fixture_copy_failure_does_not_fall_back_to_stock(self):
        registry = self.fixture_registry()
        fixture = registry.module("exploit/test/example_compat")
        runner = FakeRunner(cp_exit=1)
        executor = DockerMetasploitExecutor(runner, fixture_registry=registry)
        result = executor.check(plan(
            module="exploit/test/example_compat",
            module_source="lab_fixture",
            fixture_source_path=fixture.source_path,
            fixture_sha256=fixture.sha256,
        ), timeout=30)

        self.assertEqual(result.operation.state, OperationState.EXECUTION_ERROR)
        self.assertIn("failed to copy fixture modules", result.operation.stderr)
        self.assertFalse(any("msfconsole" in " ".join(call) for call in runner.calls))

    def test_fixture_hash_mismatch_is_rejected_before_msfconsole(self):
        registry = self.fixture_registry()
        fixture = registry.module("exploit/test/example_compat")
        runner = FakeRunner()
        executor = DockerMetasploitExecutor(runner, fixture_registry=registry)
        result = executor.check(plan(
            module="exploit/test/example_compat",
            module_source="lab_fixture",
            fixture_source_path=fixture.source_path,
            fixture_sha256="0" * 64,
        ), timeout=30)

        self.assertEqual(result.operation.state, OperationState.EXECUTION_ERROR)
        self.assertIn("SHA-256 mismatch", result.operation.stderr)
        self.assertFalse(any(call[:2] == ("docker", "cp") for call in runner.calls))
        self.assertFalse(any("msfconsole" in " ".join(call) for call in runner.calls))

    def test_missing_fixture_configuration_is_rejected(self):
        runner = FakeRunner()
        executor = DockerMetasploitExecutor(runner, fixture_registry=build_registry([]))
        result = executor.check(plan(
            module="exploit/test/example_compat",
            module_source="lab_fixture",
            fixture_sha256="f" * 64,
        ), timeout=30)

        self.assertEqual(result.operation.state, OperationState.EXECUTION_ERROR)
        self.assertIn("not present in approved", result.operation.stderr)
        self.assertFalse(any("msfconsole" in " ".join(call) for call in runner.calls))


if __name__ == "__main__":
    unittest.main()
