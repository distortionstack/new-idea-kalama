import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.integration import test_patch_execution as task5b
from tests.integration import test_patch_planning as planning
from kalama.prioritizer.trivy_parser import parse_trivy_report
from kalama.remediation.execution_orchestrator import PatchExecutionOrchestrator
from kalama.remediation.models import FixType, PatchStrategy, RemediationCandidate
from kalama.state.models import ArtifactKind, PipelineStage, RunStatus, StageStatus
from kalama.target.models import TrivyArtifact
from kalama.verification.comparison import compare_remediation_targets
from kalama.verification.orchestrator import AfterScanOrchestrator


NOW = planning.task4_helpers.NOW
CVE_A = "CVE-2099-0001"
CVE_B = "CVE-2099-0002"


def finding(cve, package="openssl", installed="1.0", fixed="1.1"):
    return {"VulnerabilityID": cve, "PkgName": package,
            "InstalledVersion": installed, "FixedVersion": fixed,
            "PkgIdentifier": {"PURL": f"pkg:deb/{package}"}}


def report(*findings, version="0.72.0", metadata=True):
    value = {"SchemaVersion": 2, "Trivy": {"Version": version},
             "CreatedAt": "2026-08-31T09:30:00Z",
             "Results": [] if not findings else [{"Target": "rootfs", "Class": "os-pkgs",
                                                    "Type": "debian",
                                                    "Vulnerabilities": list(findings)}]}
    if metadata:
        value["Metadata"] = {"OS": {"Family": "debian"},
                             "DB": {"UpdatedAt": "2026-08-31T00:00:00Z"}}
    return value


class FakeScanner:
    def __init__(self, artifact, *, fail=False):
        self.artifact, self.fail, self.calls = artifact, fail, []

    def __call__(self, image, output_path):
        self.calls.append((image.canonical_identity, str(output_path)))
        if self.fail:
            raise RuntimeError("Trivy failed")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(self.artifact, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        return TrivyArtifact("trivy", self.artifact.get("Trivy", {}).get("Version"),
                             image.canonical_identity, image.requested_reference, image.image_id,
                             image.selected_digest, str(output_path), digest, 2,
                             self.artifact.get("CreatedAt"))


class PureComparisonTests(unittest.TestCase):
    def test_found_not_found_multiple_occurrences_and_fixed_version_is_not_oracle(self):
        before = parse_trivy_report(report(
            finding(CVE_A, "openssl", "1.0"), finding(CVE_A, "libssl", "1.0"),
            finding(CVE_B, "curl", "1.0")))
        after = parse_trivy_report(report(
            finding(CVE_A, "libssl", "1.1", "1.1")))
        value = compare_remediation_targets((CVE_A, CVE_B), (), before, after)
        by_id = {item["cve_id"]: item for item in value["intended_targets"]}
        self.assertEqual(by_id[CVE_A]["scanner_status"], "FOUND")
        self.assertEqual(len(by_id[CVE_A]["after_occurrences"]), 1)
        self.assertEqual(by_id[CVE_B]["scanner_status"], "NOT_FOUND")
        self.assertTrue(by_id[CVE_B]["scanner_remediation_verified"])
        self.assertFalse(by_id[CVE_B]["empirical_remediation_verified"])
        self.assertEqual(value["summary"], {"intended_total": 2, "found": 1,
                                             "not_found": 1, "unknown": 0})

    def test_malformed_after_evidence_is_unknown_and_incidental_is_separate(self):
        before = parse_trivy_report(report(finding(CVE_A), finding(CVE_B, "curl")))
        malformed = report(finding("CVE-2099-BROKEN", "unknown"))
        value = compare_remediation_targets((CVE_A,), (CVE_B,), before,
                                            parse_trivy_report(malformed))
        self.assertEqual(value["intended_targets"][0]["scanner_status"], "UNKNOWN")
        self.assertEqual(value["summary"]["not_found"], 0)
        self.assertEqual(value["incidental_effects"][0]["intent"], "INCIDENTAL")

    def test_empty_valid_after_is_not_found_and_permutation_is_deterministic(self):
        before = parse_trivy_report(report(finding(CVE_A)))
        empty = parse_trivy_report(report())
        first = compare_remediation_targets((CVE_A,), (), before, empty)
        second = compare_remediation_targets(reversed((CVE_A,)), (), before, empty)
        self.assertEqual(first, second)
        self.assertEqual(first["intended_targets"][0]["scanner_status"], "NOT_FOUND")


class AfterScanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = planning.PatchPlanningIntegrationTests()
        self.fixture.setUp()
        self.store, self.root = self.fixture.store, self.fixture.root
        # Establish real before occurrence evidence before PatchPlan records its SHA.
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.TRIVY_BEFORE)
        Path(ref.path).write_text(json.dumps(report(finding(CVE_A))), encoding="utf-8")
        from dataclasses import replace
        ref = replace(ref, sha256=hashlib.sha256(Path(ref.path).read_bytes()).hexdigest())
        self.store.save(state.with_artifact(ref, state.updated_at))
        candidate = RemediationCandidate("1.1", FixType.C, PatchStrategy.PACKAGE_MANAGER,
                                         "official_repository", "debian-security",
                                         trusted=True, same_branch=True)
        self.fixture.run_plan(planning.FakeProvider(candidate))
        self.backend = task5b.FakePatchBackend()
        self.state = PatchExecutionOrchestrator(
            self.store, self.backend, clock=lambda: NOW).run("aB3x9")
        self.prior_hashes = {kind: self.state.artifact(kind).sha256 for kind in (
            ArtifactKind.TRIVY_BEFORE, ArtifactKind.TOP30_BEFORE,
            ArtifactKind.ATTACK_BEFORE, ArtifactKind.EXPLOIT_CONFIG_BEFORE,
            ArtifactKind.PATCH_PLAN, ArtifactKind.PATCH_RESULT)}

    def tearDown(self):
        self.fixture.tearDown()

    def inspector(self, subject):
        self.inspected = subject
        return {"image_id": self.state.patched_image["image_id"], "repo_digests": ()}

    def test_success_scans_exact_state_identity_and_pauses_at_step7(self):
        scanner = FakeScanner(report(version="0.73.0"))
        state = AfterScanOrchestrator(
            self.store, scanner, self.inspector, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(scanner.calls[0][0], self.state.patched_image["image_id"])
        self.assertEqual(self.inspected, self.state.patched_image["image_id"])
        self.assertEqual(state.stage(PipelineStage.STEP_6_AFTER_SCAN).status,
                         StageStatus.SUCCEEDED)
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.current_stage, PipelineStage.STEP_7_REEXPLOIT)
        self.assertEqual(state.waiting_reason, "REEXPLOIT_NOT_INTEGRATED")
        self.assertIsNotNone(state.artifact(ArtifactKind.TRIVY_AFTER))
        result_ref = state.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT)
        result = json.loads(Path(result_ref.path).read_bytes())
        self.assertEqual(result["intended_targets"][0]["scanner_status"], "NOT_FOUND")
        self.assertFalse(result["empirical_remediation_verified"])
        self.assertIn("TRIVY_VERSION_CHANGED", result["warnings"])
        self.assertEqual(state.cves[0].resolver_status, "EXPLOIT_SUCCEEDED")
        self.assertEqual(state.cves[0].patch_action_status, "SUCCEEDED")
        self.assertEqual(state.cves[0].after_scan_status, "NOT_FOUND")
        for kind, digest in self.prior_hashes.items():
            self.assertEqual(state.artifact(kind).sha256, digest)

    def test_found_is_successful_stage_not_fatal(self):
        state = AfterScanOrchestrator(
            self.store, FakeScanner(report(finding(CVE_A, installed="1.1"))),
            self.inspector, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.PAUSED)
        result = json.loads(Path(state.artifact(
            ArtifactKind.REMEDIATION_SCAN_RESULT).path).read_bytes())
        self.assertEqual(result["summary"]["found"], 1)

    def test_identity_mismatch_and_systemic_failure_do_not_fabricate_results(self):
        scanner = FakeScanner(report())
        state = AfterScanOrchestrator(
            self.store, scanner,
            lambda _: {"image_id": "sha256:other", "repo_digests": ()},
            clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertEqual(state.errors[-1].code, "PATCHED_IMAGE_IDENTITY_MISMATCH")
        self.assertEqual(scanner.calls, [])
        self.assertIsNone(state.artifact(ArtifactKind.TRIVY_AFTER))

        self.tearDown()
        self.setUp()
        state = AfterScanOrchestrator(
            self.store, FakeScanner(report(), fail=True), self.inspector,
            clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNone(state.artifact(ArtifactKind.TRIVY_AFTER))
        self.assertIsNone(state.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT))

    def test_comparison_publication_failure_preserves_committed_trivy_after(self):
        with patch("kalama.verification.orchestrator.write_remediation_scan_result",
                   side_effect=OSError("replace failed")):
            state = AfterScanOrchestrator(
                self.store, FakeScanner(report()), self.inspector,
                clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(state.artifact(ArtifactKind.TRIVY_AFTER))
        self.assertTrue(Path(state.artifact(ArtifactKind.TRIVY_AFTER).path).is_file())
        self.assertIsNone(state.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT))


if __name__ == "__main__":
    unittest.main()
