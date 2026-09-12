"""Focused tests for BEFORE same-invocation session/impact attribution.

Covers the ephemeral-msfconsole blocker: reverse-shell sessions died with
the one-shot exploit process, so the later separate `sessions -l` inventory
structurally returned [].  The fix runs check+exploit+post-listing in one
msfconsole invocation and attributes only stdout events confirmed by the
same-invocation listing.
"""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import yaml

from tests.integration import test_attack_form_submission as task3_helpers
from kalama.execution.attempt import execute_attempt
from kalama.execution.executor import (
    SingleInvocationResult,
    attribute_same_invocation,
    extract_command_impact,
    parse_session_opened_events,
)
from kalama.execution.models import (
    CheckEvidence, CheckVerdict, CommandEvidence, ExecutionPlan,
    ImpactEvidenceStatus, OperationState,
)
from kalama.execution.orchestrator import BeforeExploitOrchestrator
from kalama.resolver.config import validate_exploit_config
from kalama.resolver.config_models import (
    ConfirmationStatus, ExploitValue, FieldSource,
)
from kalama.resolution.config_codec import exploit_config_from_dict
from kalama.state.models import ArtifactKind
from kalama.state.store import StateStore
from kalama.target.models import CommandResult

NOW = task3_helpers.NOW
TARGET_IP = "172.18.0.3"


def make_plan(module="exploit/a", lhost=None, lport=None):
    options = ()
    payload_options = tuple(
        (name, value) for name, value in (("LHOST", lhost), ("LPORT", lport))
        if value is not None)
    return ExecutionPlan(
        cve_id="CVE-2099-0001", rank=1, module=module, target_index=0,
        target_name="target", module_options=options, payload="payload/a",
        payload_options=payload_options, run_check=True, run_exploit=True,
        session_confirmation_expected=True, precondition_commands=(),
        precondition_target=None, precondition_required=False,
        pre_attack_command=None, pre_attack_target=None)


def facts(ip=TARGET_IP):
    return {"ip_address": ip, "container_name": "victim-aB3x9"}


class FakeSingleMsf:
    """Single-invocation double: old sessions()/check()/exploit() must not fire."""

    def __init__(self, *, check=CheckVerdict.VULNERABLE, baseline=(), post=(),
                 details=None, exploit_stdout="", exploit_state=OperationState.EXECUTED,
                 available=True):
        self.check_verdict = check
        self.baseline = tuple(baseline)
        self.post = tuple(post)
        self.details = dict(details or {})
        self.exploit_stdout = exploit_stdout
        self.exploit_state = exploit_state
        self.available = available
        self.attempt_calls: list = []
        self.legacy_calls: list = []

    def backend_available(self):
        return self.available

    def sessions(self, *, timeout):
        self.legacy_calls.append("sessions")
        raise AssertionError("single-invocation path must not call sessions()")

    def check(self, plan, *, timeout):
        # Check-only protocols (run_exploit=False) keep the legacy
        # check() path; single-invocation is only for exploit attempts.
        self.legacy_calls.append(("check", plan.rank))
        return CheckEvidence(self.check_verdict,
                             CommandEvidence(OperationState.EXECUTED, exit_code=0,
                                             submitted=True))

    def exploit(self, plan, *, timeout):
        self.legacy_calls.append("exploit")
        raise AssertionError("single-invocation path must not call exploit()")

    def run_attempt(self, plan, *, target_facts, run_check, timeout, settle_seconds=None):
        self.attempt_calls.append(plan.rank)
        stdout = self.exploit_stdout
        operation = CommandEvidence(self.exploit_state, exit_code=0, stdout=stdout,
                                    stderr="", submitted=True)
        if run_check:
            check = CheckEvidence(self.check_verdict, operation)
        else:
            check = CheckEvidence(CheckVerdict.NOT_RUN,
                                  CommandEvidence(OperationState.NOT_RUN))
        sessions = attribute_same_invocation(
            baseline_ids=self.baseline, post_ids=self.post,
            session_details=self.details, stdout=stdout, plan=plan,
            target_facts=target_facts)
        impact = extract_command_impact(
            stdout=stdout, stderr="", plan=plan, target_facts=target_facts,
            exploit_state=self.exploit_state)
        return SingleInvocationResult(check, operation, sessions, impact)


class FakeCommands:
    def __init__(self, state=OperationState.EXECUTED):
        self.state = state

    def execute(self, target, command, *, timeout):
        return CommandEvidence(self.state, exit_code=0, submitted=True)


class SameInvocationParsingTests(unittest.TestCase):
    def test_1_same_invocation_listing_parsed_and_attributed(self):
        plan = make_plan(lhost="10.0.0.1", lport=14711)
        stdout = ("[*] Started reverse TCP handler on 10.0.0.1:14711 \n"
                  "[*] Command shell session 1 opened "
                  "(10.0.0.1:14711 -> 10.0.0.5:54924) at 2026-09-08 22:52:15 +0000\n"
                  "[*] Session 1 created in the background.\n")
        events = parse_session_opened_events(stdout)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["session_id"], "1")
        self.assertEqual(events[0]["peer_host"], "10.0.0.5")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=("1",),
            session_details={"1": {"tunnel_peer": "10.0.0.5:54924",
                                   "tunnel_local": "10.0.0.1:14711"}},
            stdout=stdout, plan=plan,
            target_facts={"ip_address": "10.0.0.5", "container_name": "victim"})
        self.assertEqual(result.attribution, "TARGET_MATCH")
        self.assertEqual(result.attributable_ids, ("1",))
        self.assertEqual(result.mismatched_ids, ())
        self.assertEqual(result.new_ids, ("1",))

    def test_2_stdout_session_wrong_peer_or_port_not_attributed(self):
        plan = make_plan(lhost="10.0.0.1", lport=14711)
        # Wrong peer IP.
        wrong_peer = ("[*] Command shell session 1 opened "
                      "(10.0.0.1:14711 -> 10.0.0.9:1111)\n")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=("1",),
            session_details={"1": {"tunnel_peer": "10.0.0.9:1111"}},
            stdout=wrong_peer, plan=plan,
            target_facts={"ip_address": "10.0.0.5", "container_name": "victim"})
        self.assertEqual(result.attributable_ids, ())
        self.assertEqual(result.mismatched_ids, ("1",))
        self.assertNotEqual(result.attribution, "TARGET_MATCH")
        # Right peer but wrong LPORT.
        wrong_port = ("[*] Command shell session 1 opened "
                      "(10.0.0.1:9999 -> 10.0.0.5:1111)\n")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=("1",),
            session_details={"1": {"tunnel_peer": "10.0.0.5:1111"}},
            stdout=wrong_port, plan=plan,
            target_facts={"ip_address": "10.0.0.5", "container_name": "victim"})
        self.assertEqual(result.attributable_ids, ())
        # Session id mismatch: stdout claims 9, listing confirms 3.
        id_mismatch = ("[*] Command shell session 9 opened "
                       "(10.0.0.1:14711 -> 10.0.0.5:1111)\n")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=("3",),
            session_details={"3": {"tunnel_peer": "10.0.0.5:1111"}},
            stdout=id_mismatch, plan=plan,
            target_facts={"ip_address": "10.0.0.5", "container_name": "victim"})
        self.assertEqual(result.attributable_ids, ())

    def test_7_stdout_only_without_listing_confirmation_is_not_attributed(self):
        plan = make_plan(lhost="10.0.0.1", lport=14711)
        stdout = ("[*] Command shell session 1 opened "
                  "(10.0.0.1:14711 -> 10.0.0.5:54924)\n")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=(),
            session_details={}, stdout=stdout, plan=plan,
            target_facts={"ip_address": "10.0.0.5", "container_name": "victim"})
        self.assertEqual(result.attributable_ids, ())
        self.assertEqual(result.new_ids, ())

    def test_ambiguous_command_output_does_not_confirm_impact(self):
        plan = make_plan()
        impact = extract_command_impact(
            stdout="[+] Command executed\n<html>ok</html>", stderr="",
            plan=plan, target_facts=facts(),
            exploit_state=OperationState.EXECUTED)
        self.assertEqual(impact.status, ImpactEvidenceStatus.NOT_COLLECTED)
        self.assertFalse(impact.confirmed)

    def test_verbose_session_block_parsed_and_attributed(self):
        # Verbatim shape from the live Ng16e BEFORE run (sessions -l -v -x
        # prints per-session blocks, not the legacy table).
        from kalama.execution.executor import DockerMetasploitExecutor
        post = ("Active sessions\n===============\n\n"
                "  Session ID: 1\n"
                "        Name: \n"
                "        Type: shell unix\n"
                "        Info: \n"
                "      Tunnel: 172.18.0.3:14811 -> 172.18.0.17:34166 (172.18.0.17)\n"
                "         Via: exploit/multi/http/struts2_content_type_ognl\n"
                "   Encrypted: No\n"
                "        UUID: \n"
                "     CheckIn: <none>\n"
                "  Registered: No\n")
        self.assertEqual(DockerMetasploitExecutor._session_ids(post), ("1",))
        self.assertEqual(DockerMetasploitExecutor._session_ids(
            "Active sessions\n===============\n\nNo active sessions.\n"), ())
        details = dict(DockerMetasploitExecutor._parse_session_details(post))
        values = dict(details["1"])
        self.assertEqual(values["tunnel_local"], "172.18.0.3:14811")
        self.assertEqual(values["tunnel_peer"], "172.18.0.17:34166")
        self.assertEqual(values["via_exploit"],
                         "exploit/multi/http/struts2_content_type_ognl")
        plan = make_plan(module="exploit/multi/http/struts2_content_type_ognl",
                         lhost="172.18.0.3", lport=14811)
        stdout = ("[*] Command shell session 1 opened "
                  "(172.18.0.3:14811 -> 172.18.0.17:34166) at 2026-09-08 23:45:45 +0000\n")
        result = attribute_same_invocation(
            baseline_ids=(), post_ids=("1",),
            session_details={"1": values}, stdout=stdout, plan=plan,
            target_facts={"ip_address": "172.18.0.17",
                          "container_name": "victim-Ng16e"})
        self.assertEqual(result.attribution, "TARGET_MATCH")
        self.assertEqual(result.attributable_ids, ("1",))


class BeforeExploitHarness:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root)
        helper = task3_helpers.AttackFormSubmissionTests()
        helper.root, helper.store = self.root, self.store
        helper.helper = task3_helpers.step4_helpers.Step4OrchestrationTests()
        helper.helper.root, helper.helper.store = self.root, self.store
        state = helper.waiting_run()
        form = yaml.safe_load(Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_bytes())
        cve = form["cves"]["CVE-2099-0001"]
        cve["module"]["confirmed"] = "exploit/a"
        cve["execution_protocol"]["confirmed"] = True
        submission = self.root / "submission.yaml"
        submission.write_text(yaml.safe_dump(form, sort_keys=False), encoding="utf-8")
        self.state = helper.apply(submission)
        self.helper = helper

    def tearDown(self):
        self.temp.cleanup()

    def make_exploit_protocol(self, *, run_check=False):
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        artifact = json.loads(Path(ref.path).read_bytes())
        config = exploit_config_from_dict(artifact["cves"][0]["exploit_config"])
        protocol = replace(config.invariant.execution_protocol, run_check=run_check,
                           run_exploit=True,
                           confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED)
        payload = replace(config.invariant.payload,
                          payload=ExploitValue("cmd/unix/generic", None,
                                               FieldSource.HUMAN_ATTACK_FORM,
                                               ConfirmationStatus.HUMAN_CONFIRMED,
                                               required=True))
        config = replace(config, invariant=replace(config.invariant,
                                                    execution_protocol=protocol, payload=payload))
        validation = validate_exploit_config(config)
        config = replace(config, readiness=validation.readiness)
        artifact["cves"][0].update(exploit_config=config.to_dict(),
                                   validation=validation.to_dict(), status="READY_TO_EXECUTE")
        Path(ref.path).write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")
        import hashlib
        new_ref = replace(ref, sha256=hashlib.sha256(Path(ref.path).read_bytes()).hexdigest())
        self.store.save(state.with_artifact(new_ref, state.updated_at))
        return new_ref

    def execute_pipeline(self, msf, env=None, commands=None):
        from kalama.execution.models import EnvironmentValidation as EV
        validator = env if env is not None else (lambda *_: EV(True))
        return BeforeExploitOrchestrator(
            self.store, validator, msf, commands or FakeCommands(),
            clock=lambda: NOW).run("aB3x9")

    def attack(self, state):
        return json.loads(Path(state.artifact(ArtifactKind.ATTACK_BEFORE).path).read_bytes())


class SameInvocationPipelineTests(BeforeExploitHarness, unittest.TestCase):
    def _valid_env(self, *_):
        from kalama.execution.models import EnvironmentValidation as EV
        return EV(True)

    def test_3_check_vulnerable_plus_attributable_session_is_exploit_succeeded(self):
        self.make_exploit_protocol(run_check=True)
        stdout = ("[+] 172.18.0.3:8080 - The target is vulnerable.\n"
                  "[*] Command shell session 3 opened "
                  f"(172.18.0.9:14711 -> {TARGET_IP}:51234)\n")
        msf = FakeSingleMsf(
            check=CheckVerdict.VULNERABLE, baseline=("1", "2"), post=("1", "2", "3"),
            details={"3": {"tunnel_peer": f"{TARGET_IP}:51234",
                           "via_exploit": "exploit/a"}},
            exploit_stdout=stdout)
        state = self.execute_pipeline(msf, env=self._valid_env)
        entry = self.attack(state)["cves"][0]
        self.assertEqual(msf.legacy_calls, [])
        self.assertEqual(entry["attempt"]["session_evidence"]["attributable_session_ids"], ["3"])
        self.assertEqual(entry["oracle"]["verdict"], "VULNERABLE")
        self.assertEqual(entry["oracle"]["evidence_basis"], "ATTRIBUTABLE_SESSION")
        self.assertEqual(state.cves[0].resolver_status, "EXPLOIT_SUCCEEDED")
        self.assertTrue(entry["metric_eligibility"]["eligible"])

    def test_4_check_vulnerable_without_impact_is_inconclusive(self):
        self.make_exploit_protocol(run_check=True)
        msf = FakeSingleMsf(
            check=CheckVerdict.VULNERABLE, baseline=("7",), post=("7",),
            details={}, exploit_stdout="[+] Command executed\n<html>ok</html>")
        state = self.execute_pipeline(msf, env=self._valid_env)
        entry = self.attack(state)["cves"][0]
        self.assertEqual(entry["oracle"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(entry["oracle"]["evidence_basis"], "CHECK_WITHOUT_ATTRIBUTABLE_IMPACT")
        self.assertFalse(entry["metric_eligibility"]["eligible"])
        self.assertEqual(state.cves[0].resolver_status, "INCONCLUSIVE")
        self.assertIsNone(entry["attempt"]["impact_evidence"])

    def test_5_not_vulnerable_complete_negative_is_exploit_failed(self):
        self.make_exploit_protocol(run_check=True)
        msf = FakeSingleMsf(
            check=CheckVerdict.SAFE, baseline=("7",), post=("7",), details={},
            exploit_stdout="[*] exploit completed without session")
        state = self.execute_pipeline(msf, env=self._valid_env)
        entry = self.attack(state)["cves"][0]
        self.assertEqual(entry["oracle"]["verdict"], "NOT_VULNERABLE")
        self.assertEqual(entry["oracle"]["evidence_basis"], "COMPLETE_NEGATIVE_OBSERVATION")
        self.assertTrue(entry["metric_eligibility"]["eligible"])
        self.assertEqual(state.cves[0].resolver_status, "EXPLOIT_FAILED")

    def test_6_user_skipped_remains_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = StateStore(root)
            helper = task3_helpers.AttackFormSubmissionTests()
            helper.root, helper.store = root, store
            helper.helper = task3_helpers.step4_helpers.Step4OrchestrationTests()
            helper.helper.root, helper.helper.store = root, store
            state = helper.waiting_run(("CVE-2099-0002", "CVE-2099-0003"))

            def mixed(form):
                ready = form["cves"]["CVE-2099-0002"]
                ready["module"]["confirmed"] = "exploit/a"
                ready["execution_protocol"]["confirmed"] = True
                skipped = form["cves"]["CVE-2099-0003"]
                skipped["decision"]["confirmed"] = "skip"
                skipped["decision"]["reason"] = "operator declined validation"

            state = helper.apply(helper.submission(state, mixed, "skip-before-exploit.yaml"))
            from kalama.execution.models import EnvironmentValidation as EV
            msf = FakeSingleMsf(check=CheckVerdict.SAFE, baseline=("7",), post=("7",))
            result = BeforeExploitOrchestrator(
                store, lambda *_: EV(True), msf, FakeCommands(),
                clock=lambda: NOW).run("aB3x9")
            attack = json.loads(
                Path(result.artifact(ArtifactKind.ATTACK_BEFORE).path).read_bytes())
            skipped = next(x for x in attack["cves"] if x["cve_id"] == "CVE-2099-0003")
            self.assertEqual(msf.legacy_calls, [("check", 1)])
            self.assertEqual(msf.attempt_calls, [])
            self.assertEqual(skipped["config_status"], "USER_SKIPPED")
            self.assertEqual(skipped["disposition"], "NOT_EXECUTED")
            self.assertEqual(skipped["metric_eligibility"],
                             {"eligible": False, "exclusion_reason": "USER_SKIPPED"})

    def test_7_old_stdout_only_path_still_inconclusive(self):
        # Legacy double without run_attempt: stdout-only session claim plus
        # empty separate inventories must not become success.
        from tests.integration.test_before_exploit import FakeMsf
        self.make_exploit_protocol(run_check=True)
        stdout = "[*] Meterpreter session 1 opened (172.18.0.3:4444 -> 172.18.0.6:45278)"
        msf = FakeMsf(sessions=((), ()), check=CheckVerdict.VULNERABLE,
                      exploit_stdout=stdout)
        self.assertFalse(hasattr(msf, "run_attempt"))
        state = self.execute_pipeline(msf, env=self._valid_env)
        entry = self.attack(state)["cves"][0]
        self.assertEqual(entry["attempt"]["session_evidence"]["new_session_ids"], [])
        self.assertEqual(entry["oracle"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(state.cves[0].resolver_status, "INCONCLUSIVE")

    def test_7b_single_invocation_stdout_only_without_listing_is_inconclusive(self):
        self.make_exploit_protocol(run_check=True)
        stdout = ("[*] Command shell session 1 opened "
                  f"(172.18.0.9:14711 -> {TARGET_IP}:51234)\n")
        msf = FakeSingleMsf(check=CheckVerdict.VULNERABLE, baseline=(), post=(),
                            details={}, exploit_stdout=stdout)
        state = self.execute_pipeline(msf, env=self._valid_env)
        entry = self.attack(state)["cves"][0]
        self.assertEqual(entry["attempt"]["session_evidence"]["attributable_session_ids"], [])
        self.assertEqual(entry["oracle"]["verdict"], "INCONCLUSIVE")
        self.assertEqual(state.cves[0].resolver_status, "INCONCLUSIVE")


class SingleInvocationCommandTests(unittest.TestCase):
    def test_single_resource_captures_baseline_exploit_and_post_before_exit(self):
        from kalama.execution.executor import (
            DockerMetasploitExecutor, MARK_BASELINE_BEGIN, MARK_POST_BEGIN,
        )
        seen = {}

        class RecordingRunner:
            def run(self, argv, *, timeout=None):
                seen["argv"] = tuple(argv)
                seen["timeout"] = timeout
                stdout = (f"{MARK_BASELINE_BEGIN}\n"
                          "Active sessions\n"
                          f"{MARK_POST_BEGIN}\n"
                          "Active sessions\n"
                          "  1  shell  cmd/unix  10.0.0.1:14711 -> 10.0.0.5:9 (10.0.0.5)\n"
                          "[*] Command shell session 1 opened "
                          "(10.0.0.1:14711 -> 10.0.0.5:9)\n")
                return CommandResult(tuple(argv), 0, stdout, "")

        from kalama.metasploit_fixtures import ApprovedFixtureRegistry
        executor = DockerMetasploitExecutor(
            RecordingRunner(), fixture_registry=ApprovedFixtureRegistry(roots=(), modules={}))
        plan = make_plan(lhost="10.0.0.1", lport=14711)
        resource, _ = executor._single_invocation_commands(
            plan, run_check=True, settle_seconds=7)
        self.assertIn("sessions -l -v -x", resource)
        self.assertEqual(resource.count("sessions -l -v -x"), 2)
        self.assertIn("run -z", resource)
        self.assertIn("check", resource)
        self.assertIn("sleep 7", resource)
        self.assertIn(MARK_BASELINE_BEGIN, resource)
        self.assertIn(MARK_POST_BEGIN, resource)
        self.assertTrue(resource.strip().endswith("exit -y"))


if __name__ == "__main__":
    unittest.main()
