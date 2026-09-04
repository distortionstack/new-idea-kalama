import hashlib
import json
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.integration import test_before_exploit as task4_helpers
from kalama.remediation.models import FixType, PatchStrategy, RemediationCandidate
from kalama.remediation.orchestrator import PatchPlanningOrchestrator
from kalama.remediation.planner import build_patch_plan
from kalama.state.models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, PipelineStage, RunStatus, StageStatus,
)


class FakeProvider:
    def __init__(self, candidate=None):
        self.value, self.calls = candidate, []

    def candidate(self, **kwargs):
        self.calls.append(kwargs)
        return self.value


def occurrence(cve, package="openssl", *, result_class="os-pkgs", result_type="debian",
               installed="1.0", fixed=("1.1",), purl=None):
    return {"canonical_cve_id": cve, "package_name": package,
            "package_purl": purl, "installed_version": installed,
            "fixed_versions": list(fixed), "result_class": result_class,
            "result_type": result_type}


class PurePlannerTests(unittest.TestCase):
    def test_selection_coalescing_overlap_and_fixed_version_is_not_confirmation(self):
        ranked = [
            {"rank": 1, "cve_id": "CVE-2099-0001",
             "occurrences": [occurrence("CVE-2099-0001")]},
            {"rank": 2, "cve_id": "CVE-2099-0002",
             "occurrences": [occurrence("CVE-2099-0002")]},
            {"rank": 3, "cve_id": "CVE-2099-0003",
             "occurrences": [occurrence("CVE-2099-0003")]},
        ]
        plan = build_patch_plan("aB3x9", ((1, "CVE-2099-0001"), (2, "CVE-2099-0002")),
                                ranked, FakeProvider())
        self.assertEqual(len(plan.actions), 1)
        action = plan.actions[0]
        self.assertEqual(action.target_cves, ("CVE-2099-0001", "CVE-2099-0002"))
        self.assertEqual(action.incidental_cves, ("CVE-2099-0003",))
        self.assertEqual(action.fix_type, FixType.C)
        self.assertEqual(action.scanner_fixed_versions, ("1.1",))
        self.assertEqual(action.status.value, "WAITING_FOR_USER_INPUT")
        self.assertIsNone(action.candidate)

    def test_same_branch_ready_and_major_fallback_requires_confirmation(self):
        ranked = [{"rank": 1, "cve_id": "CVE-2099-0001",
                   "occurrences": [occurrence("CVE-2099-0001", installed="2.3.31")]}]
        same = RemediationCandidate("2.3.32", FixType.C, PatchStrategy.PACKAGE_MANAGER,
                                    "official_repository", "debian-security", trusted=True,
                                    same_branch=True)
        ready = build_patch_plan("aB3x9", ((1, "CVE-2099-0001"),), ranked,
                                 FakeProvider(same)).actions[0]
        self.assertEqual(ready.status.value, "READY_FOR_PATCH_EXECUTION")
        fallback = replace(same, target_version="7.0.0", same_branch=False,
                           fallback_used=True, fallback_reason="branch is EOL")
        waiting = build_patch_plan("aB3x9", ((1, "CVE-2099-0001"),), ranked,
                                   FakeProvider(fallback)).actions[0]
        self.assertIn("MAJOR_VERSION_CONFIRMATION_REQUIRED",
                      [x.value for x in waiting.input_reasons])
        self.assertTrue(waiting.candidate.fallback_used)


class PatchPlanningIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.helper = task4_helpers.BeforeExploitTests()
        self.helper.setUp()
        self.root, self.store = self.helper.root, self.helper.store
        self.helper.make_exploit_protocol()
        self.state = self.helper.execute_pipeline(
            task4_helpers.FakeMsf(sessions=(("1",), ("1", "2"))))
        top_ref = self.state.artifact(ArtifactKind.TOP30_BEFORE)
        top = json.loads(Path(top_ref.path).read_bytes())
        top["ranked_cves"][0]["occurrences"] = [occurrence("CVE-2099-0001")]
        Path(top_ref.path).write_text(json.dumps(top), encoding="utf-8")
        top_ref = replace(top_ref, sha256=hashlib.sha256(Path(top_ref.path).read_bytes()).hexdigest())
        trivy = self.root / "trivy" / "before" / "scan.json"
        trivy.parent.mkdir(parents=True, exist_ok=True)
        trivy.write_text(json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8")
        trivy_ref = ArtifactReference(ArtifactKind.TRIVY_BEFORE, str(trivy),
                                      hashlib.sha256(trivy.read_bytes()).hexdigest(), 2,
                                      "2026-08-31T09:30:00Z", PipelineStage.STEP_2_TARGET_SCAN)
        state = self.store.load("aB3x9").with_artifact(top_ref, self.state.updated_at)
        self.store.save(state.with_artifact(trivy_ref, state.updated_at))

    def tearDown(self):
        self.helper.tearDown()

    def run_plan(self, provider):
        return PatchPlanningOrchestrator(self.store, provider,
                                         clock=lambda: task4_helpers.NOW).run("aB3x9")

    def test_ready_plan_pauses_at_execution_boundary_without_mutation(self):
        candidate = RemediationCandidate("1.1", FixType.C, PatchStrategy.PACKAGE_MANAGER,
                                         "official_repository", "debian-security",
                                         trusted=True, same_branch=True)
        state = self.run_plan(FakeProvider(candidate))
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.current_stage, PipelineStage.STEP_5_PATCH_EXECUTION)
        self.assertEqual(state.waiting_reason, "PATCH_EXECUTION_NOT_INTEGRATED")
        self.assertEqual(state.stage(PipelineStage.STEP_5_PATCH_PLAN).status, StageStatus.SUCCEEDED)
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_PLAN))
        self.assertIsNone(state.artifact(ArtifactKind.PATCH_FORM))
        plan = json.loads(Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        self.assertTrue(plan["source_image"]["do_not_delete_source_image"])
        self.assertEqual(plan["planned_after"]["container_name"], "victim-after-aB3x9")

    def test_unresolved_plan_generates_form_and_form_failure_is_fatal(self):
        state = self.run_plan(FakeProvider())
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.waiting_reason, "PATCH_FORM")
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_PLAN))
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_FORM))

        # Start a fresh fixture to exercise publication ordering.
        self.tearDown()
        self.setUp()
        with patch("kalama.remediation.orchestrator.write_patch_form_immutable",
                   side_effect=OSError("form replace failed")):
            failed = self.run_plan(FakeProvider())
        self.assertEqual(failed.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(failed.artifact(ArtifactKind.PATCH_PLAN))
        self.assertIsNone(failed.artifact(ArtifactKind.PATCH_FORM))

    def test_no_successful_exploit_produces_valid_empty_plan(self):
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.ATTACK_BEFORE)
        artifact = json.loads(Path(ref.path).read_bytes())
        artifact["cves"][0]["disposition"] = "EXPLOIT_FAILED"
        Path(ref.path).write_text(json.dumps(artifact), encoding="utf-8")
        ref = replace(ref, sha256=hashlib.sha256(Path(ref.path).read_bytes()).hexdigest())
        state = state.with_artifact(ref, state.updated_at)
        self.store.save(replace(state, cves=(
            CVEStateSummary("CVE-2099-0001", 1, "EXPLOIT_FAILED"),)))
        state = self.run_plan(FakeProvider())
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.waiting_reason, "NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS")
        plan = json.loads(Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        self.assertEqual(plan["actions"], [])
        self.assertIsNone(state.artifact(ArtifactKind.PATCH_FORM))


if __name__ == "__main__":
    unittest.main()
