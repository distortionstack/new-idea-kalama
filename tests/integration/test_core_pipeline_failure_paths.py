"""Critical failure-path tests for the core Kalama/VIPER pipeline.

Each test drives the REAL production orchestrators through the E2E harness
(:mod:`tests.integration.test_core_e2e_pipeline`) with one fault injected
at an external boundary. They prove the pipeline fails closed:

* scan failure is never confused with "no vulnerabilities";
* an inconclusive BEFORE exploit never counts as confirmed evidence;
* a patch failure never proceeds to AFTER validation;
* an unavailable patched service is an environment error, never mitigation;
* stale target identity is rejected, never silently reused;
* an interrupted run resumes from persisted state with identical results.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import yaml

from kalama.dispatcher import dispatch_stage, DispatchError
from kalama.evaluation.orchestrator import EvaluationOrchestrator
from kalama.execution.models import EnvironmentValidation
from kalama.execution.orchestrator import BeforeExploitOrchestrator
from kalama.orchestrator import PrioritizationOrchestrator
from kalama.remediation.execution_orchestrator import PatchExecutionOrchestrator
from kalama.remediation.orchestrator import PatchPlanningOrchestrator
from kalama.reexploit.orchestrator import ReexploitOrchestrator
from kalama.resolution.orchestrator import ResolverOrchestrator
from kalama.state.models import ArtifactKind, PipelineStage, RunStatus, StageStatus
from kalama.verification.orchestrator import AfterScanOrchestrator

from tests.integration.test_after_scan import FakeScanner, report
from tests.integration.test_before_exploit import CheckVerdict, FakeCommands, FakeMsf
from tests.integration.test_core_e2e_pipeline import (
    CVE_ID, NOW, RUN_ID, E2EPipeline, E2EStep2, E2EStep3,
    clean_negative_after_msf, compensate_after_facts_for_fake_backend,
    confirm_attack_form, payload_introspector, resolver_processor,
    successful_before_msf,
)
from tests.integration.test_patch_execution import FakePatchBackend
from tests.integration.test_patch_planning import FakeProvider

from kalama.resolution.confirmation_orchestrator import AttackFormOrchestrator


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FailingStep2(E2EStep2):
    def __call__(self, request):
        self.calls.append(request)
        raise RuntimeError("Trivy failed")


class CoreFailurePathTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.pipeline = E2EPipeline(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def _drive_to_before_exploit_boundary(self):
        """Happy path up to the confirmed BEFORE-exploit boundary."""
        self.pipeline.start()
        waiting = self.pipeline.run_resolver()
        self.assertEqual(waiting.status, RunStatus.WAITING_FOR_USER_INPUT)
        return self.pipeline.submit_attack_confirmation()

    # Scanner failure ------------------------------------------------------
    def test_scan_failure_is_not_no_vulnerabilities(self):
        store = self.pipeline.store
        orchestrator = PrioritizationOrchestrator(
            store, FailingStep2(), E2EStep3(), clock=lambda: NOW,
            run_id_generator=lambda: RUN_ID)
        state = orchestrator.run("victim:test")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertEqual(state.stage(PipelineStage.STEP_2_TARGET_SCAN).status,
                         StageStatus.FAILED)
        self.assertEqual(state.errors[-1].code, "STEP_2_FAILED")
        # Nothing was committed: this is a failure, not an empty finding.
        self.assertIsNone(state.artifact(ArtifactKind.TRIVY_BEFORE))
        self.assertIsNone(state.artifact(ArtifactKind.TOP30_BEFORE))
        self.assertNotEqual(state.warnings[-1].code if state.warnings else None,
                            "NO_RANKABLE_CVES")
        # The run cannot continue: it is not at any executable boundary.
        self.assertNotEqual(state.status, RunStatus.PAUSED)
        with self.assertRaises((DispatchError, AssertionError)):
            reloaded = store.load(RUN_ID)
            if reloaded.status != RunStatus.PAUSED:
                raise AssertionError("run is not continuable")
            dispatch_stage(reloaded)

    # BEFORE exploit inconclusive ------------------------------------------
    def test_inconclusive_before_exploit_never_counts_as_confirmed(self):
        self._drive_to_before_exploit_boundary()
        # Check-positive without attributable impact: INCONCLUSIVE, not success.
        from tests.integration.test_core_e2e_pipeline import force_ready_exploit_protocol

        state = self.pipeline.store.load(RUN_ID)
        ref = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        artifact = json.loads(Path(ref.path).read_bytes())
        from kalama.resolution.config_codec import exploit_config_from_dict
        from kalama.resolver.config import validate_exploit_config
        from kalama.resolver.config_models import ConfirmationStatus
        config = exploit_config_from_dict(artifact["cves"][0]["exploit_config"])
        protocol = replace(config.invariant.execution_protocol, run_check=True,
                           run_exploit=True,
                           confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED)
        config = replace(config, invariant=replace(config.invariant,
                                                   execution_protocol=protocol))
        validation = validate_exploit_config(config)
        config = replace(config, readiness=validation.readiness)
        artifact["cves"][0].update(exploit_config=config.to_dict(),
                                   validation=validation.to_dict(),
                                   status="READY_TO_EXECUTE")
        Path(ref.path).write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")
        self.pipeline.store.save(state.with_artifact(
            replace(ref, sha256=_sha(Path(ref.path))), state.updated_at))

        state = self.pipeline.run_before_exploit(
            msf=FakeMsf(sessions=(("7",), ("7",)), check=CheckVerdict.VULNERABLE))
        attack = json.loads(Path(state.artifact(
            ArtifactKind.ATTACK_BEFORE).path).read_bytes())
        self.assertEqual(attack["cves"][0]["oracle"]["verdict"], "INCONCLUSIVE")
        self.assertFalse(attack["cves"][0]["metric_eligibility"]["eligible"])
        self.assertEqual(state.cves[0].resolver_status, "INCONCLUSIVE")

        # With no EXPLOIT_SUCCEEDED evidence the planner must not produce an
        # executable plan: the run parks with zero remediation targets.
        planned = PatchPlanningOrchestrator(
            self.pipeline.store, FakeProvider(), clock=lambda: NOW).run(RUN_ID)
        self.assertEqual(planned.status, RunStatus.PAUSED)
        self.assertEqual(planned.current_stage, PipelineStage.STEP_5_PATCH_PLAN)
        self.assertEqual(planned.waiting_reason,
                         "NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS")
        self.assertIsNone(planned.artifact(ArtifactKind.PATCH_RESULT))
        self.assertIsNone(planned.artifact(ArtifactKind.TRIVY_AFTER))
        self.assertIsNone(planned.artifact(ArtifactKind.REMEDIATION_RESULT))
        # Duplicate continuation from this parked state is rejected.
        with self.assertRaises(Exception):
            PatchPlanningOrchestrator(
                self.pipeline.store, FakeProvider(), clock=lambda: NOW).run(RUN_ID)

    # Patch failure ---------------------------------------------------------
    def test_patch_failure_never_proceeds_to_after_validation(self):
        self._drive_to_before_exploit_boundary()
        self.pipeline.run_before_exploit()
        self.pipeline.run_patch_plan()
        self.pipeline.submit_patch_confirmation()
        failed = self.pipeline.run_patch_execution(
            backend=FakePatchBackend(action_success=False))
        self.assertEqual(failed.status, RunStatus.FAILED_FATAL)
        self.assertEqual(failed.errors[-1].code, "PATCH_ACTION_FAILED")
        self.assertIsNotNone(failed.artifact(ArtifactKind.PATCH_RESULT))
        self.assertIsNone(failed.patched_image)
        self.assertIsNone(failed.after_target)
        # AFTER scan is unreachable: the boundary guard rejects the run and
        # no AFTER artifact is fabricated.
        with self.assertRaises(Exception) as caught:
            AfterScanOrchestrator(
                self.pipeline.store, FakeScanner(report()),
                lambda _: {"image_id": "sha256:other", "repo_digests": ()},
                clock=lambda: NOW).run(RUN_ID)
        self.assertEqual(getattr(caught.exception, "code", ""), "INVALID_RUN_STATE")
        reloaded = self.pipeline.store.load(RUN_ID)
        self.assertIsNone(reloaded.artifact(ArtifactKind.TRIVY_AFTER))
        self.assertIsNone(reloaded.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT))
        self.assertIsNone(reloaded.artifact(ArtifactKind.ATTACK_AFTER))

    # Patched service unavailable -------------------------------------------
    def test_unavailable_patched_service_is_environment_error_not_mitigation(self):
        self._drive_to_before_exploit_boundary()
        self.pipeline.run_before_exploit()
        self.pipeline.run_patch_plan()
        self.pipeline.submit_patch_confirmation()
        self.pipeline.run_patch_execution()
        self.pipeline.run_after_scan()
        state = self.pipeline.run_reexploit(
            msf=clean_negative_after_msf(),
            env=lambda *_: EnvironmentValidation(
                False, "ENVIRONMENT_BINDING_STALE", "patched service unavailable"))
        attack_after = json.loads(Path(state.artifact(
            ArtifactKind.ATTACK_AFTER).path).read_bytes())
        entry = attack_after["cves"][0]
        self.assertEqual(entry["disposition"], "AFTER_ENVIRONMENT_UNRESOLVED")
        self.assertFalse(entry["metric_eligibility"]["eligible"])
        self.assertEqual(entry["metric_eligibility"]["exclusion_reason"],
                         "ENVIRONMENT_BINDING_STALE")
        final = json.loads(Path(state.artifact(
            ArtifactKind.REMEDIATION_RESULT).path).read_bytes())
        # Environment failure must remain non-validated, never VERIFIED.
        self.assertEqual(final["cves"][0]["final"]["status"], "INCONCLUSIVE")
        self.assertEqual(state.cves[0].remediation_status, "INCONCLUSIVE")
        completed = self.pipeline.run_evaluation()
        self.assertEqual(completed.status, RunStatus.COMPLETED)
        metrics = json.loads(Path(completed.artifact(
            ArtifactKind.EVALUATION_METRICS).path).read_bytes())
        self.assertEqual(metrics["remediation"]["verified"], 0)

    # Stale target identity ---------------------------------------------------
    def test_stale_after_target_is_rejected(self):
        self._drive_to_before_exploit_boundary()
        self.pipeline.run_before_exploit()
        self.pipeline.run_patch_plan()
        self.pipeline.submit_patch_confirmation()
        self.pipeline.run_patch_execution()
        state = self.pipeline.store.load(RUN_ID)
        # Simulate a stale BEFORE container being presented as the AFTER target.
        stale_facts = dict(state.after_target.facts or {})
        stale_facts.update(container_id="stale-before-container-id",
                           ip_address="172.18.0.3")
        self.pipeline.store.save(replace(
            state, after_target=replace(state.after_target, facts=stale_facts)))
        # The rejection fails closed: FAILED_FATAL with an integrity code,
        # and no AFTER artifact is fabricated.
        rejected = self.pipeline.store.load(RUN_ID)
        self.assertEqual(rejected.status, RunStatus.PAUSED)
        scanner_calls: list = []

        class _SpyScanner(FakeScanner):
            def __call__(self, image, output_path):
                scanner_calls.append(str(output_path))
                return super().__call__(image, output_path)

        result = AfterScanOrchestrator(
            self.pipeline.store, _SpyScanner(report()),
            lambda _: {"image_id": state.patched_image["image_id"],
                       "repo_digests": ()},
            clock=lambda: NOW).run(RUN_ID)
        self.assertEqual(result.status, RunStatus.FAILED_FATAL)
        self.assertIn(result.errors[-1].code,
                      ("PATCH_RESULT_INTEGRITY_ERROR", "AFTER_TARGET_IMAGE_MISMATCH",
                       "ARTIFACT_INTEGRITY_ERROR", "PATCHED_IMAGE_IDENTITY_MISMATCH"))
        self.assertEqual(scanner_calls, [])
        reloaded = self.pipeline.store.load(RUN_ID)
        self.assertIsNone(reloaded.artifact(ArtifactKind.TRIVY_AFTER))
        self.assertIsNone(reloaded.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT))

    def test_reexploit_rejects_wrong_run_lineage(self):
        self.pipeline.drive_full()
        state = self.pipeline.store.load(RUN_ID)
        # Corrupt the AFTER config lineage: it must not be accepted.
        ref = state.artifact(ArtifactKind.EXPLOIT_CONFIG_AFTER)
        payload = json.loads(Path(ref.path).read_bytes())
        payload["artifact"]["run_id"] = "ZZZZZ"
        Path(ref.path).write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(Exception):
            ReexploitOrchestrator(
                self.pipeline.store, lambda *_: EnvironmentValidation(True),
                clean_negative_after_msf(), FakeCommands(),
                clock=lambda: NOW).run(RUN_ID)

    # Resume after interruption ----------------------------------------------
    def test_interrupted_run_resumes_from_persisted_state(self):
        self.pipeline.start()
        self.pipeline.run_resolver()
        self.pipeline.submit_attack_confirmation()
        paused = self.pipeline.run_before_exploit()
        self.assertEqual(paused.waiting_reason, "PATCH_PLAN_REQUIRED")
        paused_hashes = {item.kind: item.sha256 for item in paused.artifacts}

        # Simulate a process restart: entirely new orchestrator instances over
        # the same persisted state directory.
        resumed = E2EPipeline(self.pipeline.root)
        state = resumed.run_patch_plan()
        self.assertEqual(state.waiting_reason, "PATCH_FORM")
        resumed.submit_patch_confirmation()
        resumed.run_patch_execution()
        resumed.run_after_scan()
        resumed.run_reexploit()
        completed = resumed.run_evaluation()
        self.assertEqual(completed.status, RunStatus.COMPLETED)

        # Resumed execution preserves every upstream artifact bit-for-bit.
        for kind, digest in paused_hashes.items():
            self.assertEqual(completed.artifact(kind).sha256, digest, kind.value)
        # And matches an uninterrupted run's terminal evidence.
        # (Artifact paths embed the temp directory, so only the semantic
        # evidence — classifications, summary, CVE summaries — is compared.)
        with tempfile.TemporaryDirectory() as other:
            reference = E2EPipeline(Path(other)).drive_full()
            completed_final = json.loads(Path(completed.artifact(
                ArtifactKind.REMEDIATION_RESULT).path).read_bytes())
            reference_final = json.loads(Path(reference.artifact(
                ArtifactKind.REMEDIATION_RESULT).path).read_bytes())
            self.assertEqual(completed_final["cves"], reference_final["cves"])
            self.assertEqual(completed_final["summary"], reference_final["summary"])
            self.assertEqual(completed.cves, reference.cves)


if __name__ == "__main__":
    unittest.main()
