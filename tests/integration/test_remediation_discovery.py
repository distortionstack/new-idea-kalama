"""Deterministic Automatic Remediation Discovery unit tests.

Uses fake command runners; no live Docker. Covers the OS-package, source-build, and
prebuilt boundaries, plus the safety/integration invariants (no Human confirmation,
no success verdict, no guessed tags).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest

from kalama.remediation.discovery import (
    AutomaticRemediationProvider, ClassificationStatus, DiscoveryClassification,
    ExecutionReadiness, RemediationDiscoveryService, ProvenanceCategory, CandidateStatus,
    VersionStatus,
)
from kalama.remediation.discovery.os_package import (
    OsPackageProvider, build_availability_query, parse_availability, select_same_branch_fixed,
)
from kalama.remediation.discovery.models import AvailabilityStatus
from kalama.remediation.discovery.source_build import SourceBuildProvider
from kalama.remediation.models import RemediationCandidate


def occurrence(*, cve, package, installed, fixed, result_class, result_type, purl=None):
    return {"canonical_cve_id": cve, "package_name": package,
            "package_purl": purl, "installed_version": installed,
            "fixed_versions": list(fixed), "result_class": result_class,
            "result_type": result_type}


class FakeRunner:
    """Command runner whose responses are keyed by the last token in argv."""

    def __init__(self):
        self.calls = []
        self.responses = {}  # command-prefix -> CommandResult-like
        self.raise_on = set()

    def when(self, signature, *, stdout="", stderr="", exit_code=0, raise_exc=None):
        self.responses[signature] = (stdout, stderr, exit_code, raise_exc)

    def run(self, argv, *, timeout=None):
        key = argv[-1] if argv else ""
        self.calls.append((tuple(argv), timeout))
        if key in self.raise_on:
            raise TimeoutError("timeout")
        if key not in self.responses:
            stdout, stderr, exit_code, exc = "", "", 0, None
        else:
            stdout, stderr, exit_code, exc = self.responses[key]
        if exc is not None:
            raise exc
        return type("R", (), {"exit_code": exit_code, "stdout": stdout, "stderr": stderr})


class SelectFixedVersionTests(unittest.TestCase):
    def test_same_branch_selection_prefers_matching_minor(self):
        self.assertEqual(select_same_branch_fixed("2.3.30", ["2.3.32", "2.5.10.1"]), (
            "2.3.32", True, "same major AND minor release branch match"))

    def test_no_silent_major_jump(self):
        target, same, reason = select_same_branch_fixed("2.3.30", ["3.0.0"])
        self.assertIsNone(target)
        self.assertFalse(same)
        self.assertIn("major", reason or "")

    def test_no_fixed_version(self):
        target, same, reason = select_same_branch_fixed("1.0", [])
        self.assertIsNone(target)
        self.assertIsNone(same)

    def test_installed_unknown_is_ambiguous(self):
        target, same, reason = select_same_branch_fixed(None, ["2.3.32"])
        self.assertIsNone(target)
        self.assertIsNone(same)


class ParseAvailabilityTests(unittest.TestCase):
    def test_available_when_fixed_version_present(self):
        self.assertEqual(
            parse_availability("apt", "7.52.1-5+deb9u10",
                               "curl:\n  Installed: 7.52.1-5+deb9u9\n  Candidate: 7.52.1-5+deb9u10\n",
                               "", 0),
            AvailabilityStatus.AVAILABLE)

    def test_unavailable_when_fixed_version_absent(self):
        self.assertEqual(
            parse_availability("apt", "7.52.1-5+deb9u10",
                               "curl:\n  Installed: 7.52.1-5+deb9u9\n  Candidate: 7.52.1-5+deb9u9\n",
                               "", 0),
            AvailabilityStatus.PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES)

    def test_not_found_marker(self):
        self.assertEqual(
            parse_availability("apt", "7.52.1-5+deb9u10", "",
                               "E: Unable to locate package curl", 100),
            AvailabilityStatus.UNAVAILABLE)


class OsPackageProviderTests(unittest.TestCase):
    def build(self, runner, **kw):
        return OsPackageProvider(runner, container_name="victim-X", **kw)

    def test_A_debian_available_is_executable_candidate(self):
        runner = FakeRunner()
        runner.when("apt-cache policy curl",
                    stdout="curl:\n  Candidate: 7.52.1-5+deb9u10\n", exit_code=0)
        prov = self.build(runner)
        d = prov.discover("CVE-1", [occurrence(
            cve="CVE-1", package="curl", installed="7.52.1-5+deb9u9",
            fixed=["7.52.1-5+deb9u10"], result_class="os-pkgs", result_type="debian")],
            {"container_name": "victim-X"})
        self.assertEqual(d.classification, DiscoveryClassification.OS_PACKAGE)
        self.assertEqual(d.classification_status, ClassificationStatus.RESOLVED)
        self.assertEqual(d.version_status, VersionStatus.RESOLVED)
        self.assertEqual(d.candidate_status, CandidateStatus.DISCOVERED)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.HUMAN_CONFIRMATION_REQUIRED)
        self.assertEqual(d.fixed_version, "7.52.1-5+deb9u10")
        self.assertEqual(d.availability.status.value, "AVAILABLE")
        self.assertIn(ProvenanceCategory.PACKAGE_MANAGER_METADATA,
                      {e.provenance for e in d.evidence})
        self.assertTrue(any(e.fact == "availability_query_attempted" for e in d.evidence))
        self.assertEqual(prov.query_count, 1)

    def test_B_fixed_version_but_repo_unavailable(self):
        runner = FakeRunner()
        runner.when("apt-cache policy curl",
                    stdout="curl:\n  Candidate: 7.52.1-5+deb9u9\n", exit_code=0)
        prov = self.build(runner)
        d = prov.discover("CVE-1", [occurrence(
            cve="CVE-1", package="curl", installed="7.52.1-5+deb9u9",
            fixed=["7.52.1-5+deb9u10"], result_class="os-pkgs", result_type="debian")], None)
        self.assertEqual(d.classification, DiscoveryClassification.OS_PACKAGE)
        self.assertEqual(d.classification_status, ClassificationStatus.RESOLVED)
        self.assertEqual(d.version_status, VersionStatus.RESOLVED)
        self.assertEqual(d.candidate_status, CandidateStatus.UNAVAILABLE)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_READY)
        self.assertEqual(d.availability.status.value, "PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES")

    def test_C_query_timeout_no_hang_no_executable(self):
        runner = FakeRunner()
        runner.raise_on.add("apt-cache policy curl")
        prov = self.build(runner, query_timeout=0.5)
        d = prov.discover("CVE-1", [occurrence(
            cve="CVE-1", package="curl", installed="7.52.1-5+deb9u9",
            fixed=["7.52.1-5+deb9u10"], result_class="os-pkgs", result_type="debian")], None)
        self.assertEqual(d.candidate_status, CandidateStatus.UNAVAILABLE)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_READY)
        self.assertEqual(d.availability.status.value, "QUERY_TIMEOUT")

    def test_D_no_fixed_version_is_unresolved_version(self):
        runner = FakeRunner()
        prov = self.build(runner)
        d = prov.discover("CVE-1", [occurrence(
            cve="CVE-1", package="curl", installed="7.52.1-5+deb9u9", fixed=[],
            result_class="os-pkgs", result_type="debian")], None)
        self.assertEqual(d.classification, DiscoveryClassification.OS_PACKAGE)
        self.assertEqual(d.version_status, VersionStatus.UNRESOLVED)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_READY)
        self.assertEqual(prov.query_count, 0)

    def test_E_multiple_packages_preserved(self):
        runner = FakeRunner()
        for p in ("curl", "libcurl3", "libcurl3-gnutls"):
            runner.when(f"apt-cache policy {p}", stdout=f"{p}:\n  Candidate: 7.52.1-5+deb9u10\n",
                        exit_code=0)
        prov = self.build(runner)
        occs = [occurrence(cve="CVE-1", package=p, installed="7.52.1-5+deb9u9",
                           fixed=["7.52.1-5+deb9u10"], result_class="os-pkgs",
                           result_type="debian") for p in ("curl", "libcurl3", "libcurl3-gnutls")]
        d = prov.discover("CVE-1", occs, None)
        self.assertEqual(set(d.packages), {"curl", "libcurl3", "libcurl3-gnutls"})
        self.assertEqual(prov.query_count, 3)
        # Each package retains an availability probe in combined evidence.
        probe_facts = [e for e in d.evidence if e.fact == "availability_query_attempted"]
        self.assertEqual(len(probe_facts), 3)

    def test_F_unsupported_distro_no_fabricated_command(self):
        runner = FakeRunner()
        prov = self.build(runner)
        d = prov.discover("CVE-1", [occurrence(
            cve="CVE-1", package="curl", installed="1.0", fixed=["1.1"],
            result_class="os-pkgs", result_type="suse")], None)
        self.assertEqual(d.classification, DiscoveryClassification.UNSUPPORTED)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_EXECUTABLE)
        self.assertEqual(prov.query_count, 0)
        # No availability query could have been attempted for an unknown manager.
        self.assertIsNone(build_availability_query("suse", "curl", "1.1"))


class SourceBuildProviderTests(unittest.TestCase):
    def maven_occ(self, *, installed="2.3.30", fixed=("2.3.32", "2.5.10.1")):
        return occurrence(
            cve="CVE-2017-5638", package="org.apache.struts:struts2-core", installed=installed,
            fixed=list(fixed), result_class="lang-pkgs", result_type="jar",
            purl="pkg:maven/org.apache.struts/struts2-core@2.3.30")

    def test_G_with_local_manifest_proposal_not_ready(self):
        prov = SourceBuildProvider(source_root=None)
        manifests = [{"name": "pom.xml", "detail": "/src/pom.xml"}]
        d = prov.discover("CVE-2017-5638", [self.maven_occ()], manifests)
        self.assertEqual(d.classification, DiscoveryClassification.SOURCE_BUILD)
        self.assertEqual(d.fix_type, "A")
        self.assertEqual(d.strategy, "REBUILD")
        self.assertEqual(d.fixed_version, "2.3.32")
        self.assertEqual(d.build_system, "maven")
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_READY)
        self.assertEqual(d.candidate_status, CandidateStatus.DISCOVERED)
        self.assertTrue(any(e.fact == "local_manifest" and e.provenance ==
                            ProvenanceCategory.LOCAL_SOURCE_METADATA for e in d.evidence))

    def test_H_no_manifest_prebuilt_knowledge_required(self):
        prov = SourceBuildProvider(source_root=None)
        d = prov.discover("CVE-2017-9805", [self.maven_occ(
            installed="2.5.12", fixed=("2.3.34", "2.5.13"))], [])
        self.assertEqual(d.classification, DiscoveryClassification.PREBUILT_IMAGE)
        self.assertEqual(d.fix_type, "B")
        self.assertEqual(d.fixed_version, "2.5.13")
        self.assertEqual(d.candidate_status, CandidateStatus.KNOWLEDGE_REQUIRED)
        self.assertEqual(d.execution_readiness, ExecutionReadiness.NOT_READY)

    def test_K_prebuilt_has_fixed_version_but_no_image_candidate(self):
        prov = SourceBuildProvider(source_root=None)
        d = prov.discover("CVE-2017-9805", [self.maven_occ(
            installed="2.5.12", fixed=("2.3.34", "2.5.13"))], [])
        self.assertEqual(d.fixed_version, "2.5.13")
        self.assertIsNone(d.source_identifier)
        self.assertIsNone(d.availability)

    def test_L_no_guessed_repo_tag_generated(self):
        prov = SourceBuildProvider(source_root=None)
        d = prov.discover("CVE-2017-9805", [self.maven_occ(
            installed="2.5.12", fixed=("2.3.34", "2.5.13"))], [])
        # There must be no image identity/tag anywhere in the evidence output.
        text = json.dumps(d.to_dict())
        self.assertNotIn("rest-showcase", text)
        self.assertNotIn("vulhub/struts2:2.5.13", text)

    def test_I_ambiguous_branch_no_major_jump(self):
        prov = SourceBuildProvider(source_root=None)
        d = prov.discover("CVE-X", [self.maven_occ(installed="2.3.30",
                                                   fixed=("3.0.0",))], [{"name": "pom.xml"}])
        self.assertIsNone(d.fixed_version)
        self.assertEqual(d.same_branch, False)

    def test_J_no_shell_build_command_generated(self):
        prov = SourceBuildProvider(source_root=None)
        d = prov.discover("CVE-2017-5638", [self.maven_occ()], [{"name": "pom.xml"}])
        text = json.dumps(d.to_dict())
        self.assertNotIn("mvn", text)
        self.assertNotIn("apt-get", text)
        self.assertNotIn("docker build", text)


class ServiceIntegrationTests(unittest.TestCase):
    def make_service(self, runner, container="victim-X", source_root=None):
        return RemediationDiscoveryService(runner=runner, container_name=container,
                                           source_root=source_root)

    def test_M_discovery_never_marks_human_confirmation(self):
        runner = FakeRunner()
        runner.when("apt-cache policy curl", stdout="curl:\n  Candidate: 1.1\n", exit_code=0)
        service = self.make_service(runner)
        provider = AutomaticRemediationProvider(service, output_root=None)
        cand = provider.candidate(package_name="curl", ecosystem="debian",
                                  installed_versions=["1.0"], scanner_fixed_versions=["1.1"],
                                  occurrences=[occurrence(
                                      cve="CVE-1", package="curl", installed="1.0",
                                      fixed=["1.1"], result_class="os-pkgs",
                                      result_type="debian")],
                                  target_facts={"container_name": "victim-X"})
        self.assertIsInstance(cand, RemediationCandidate)
        self.assertFalse(cand.trusted)
        self.assertEqual(cand.source_authority, "remediation_discovery")
        self.assertEqual(cand.source_type, "auto_discovered")
        self.assertEqual(cand.human_confirmed_fields if hasattr(cand, "human_confirmed_fields") else [], [])
        self.assertEqual(cand.execution_readiness, "HUMAN_CONFIRMATION_REQUIRED")

    def test_N_discovery_never_produces_success_verdict(self):
        runner = FakeRunner()
        runner.when("apt-cache policy curl", stdout="curl:\n  Candidate: 1.1\n", exit_code=0)
        provider = AutomaticRemediationProvider(self.make_service(runner), output_root=None)
        cand = provider.candidate(package_name="curl", ecosystem="debian",
                                  installed_versions=["1.0"], scanner_fixed_versions=["1.1"],
                                  occurrences=[occurrence(
                                      cve="CVE-1", package="curl", installed="1.0",
                                      fixed=["1.1"], result_class="os-pkgs",
                                      result_type="debian")],
                                  target_facts={"container_name": "victim-X"})
        self.assertNotIn(cand.execution_readiness, {"VERIFIED", "PATCH_SUCCEEDED"})
        self.assertNotIn("CVE_REMOVED", cand.evidence)

    def test_auto_provider_writes_discovery_artifact(self):
        runner = FakeRunner()
        runner.when("apt-cache policy curl", stdout="curl:\n  Candidate: 1.1\n", exit_code=0)
        with tempfile.TemporaryDirectory() as root:
            provider = AutomaticRemediationProvider(self.make_service(runner),
                                                    output_root=Path(root))
            provider.candidate(package_name="curl", ecosystem="debian",
                               installed_versions=["1.0"], scanner_fixed_versions=["1.1"],
                               occurrences=[occurrence(
                                   cve="CVE-1", package="curl", installed="1.0",
                                   fixed=["1.1"], result_class="os-pkgs", result_type="debian")],
                               target_facts={"container_name": "victim-X"})
            written = provider.write_discovery_artifact("aB3x9")
            self.assertIsNotNone(written)
            path, sha = written
            data = json.loads(Path(path).read_bytes())
            self.assertEqual(data["schema"], "kalama.remediation-discovery/v1")
            self.assertEqual(data["run_id"], "aB3x9")
            self.assertEqual(len(data["targets"]), 1)
            self.assertTrue(data["targets"][0]["evidence"])


class OrchestratorDiscoveryIntegrationTests(unittest.TestCase):
    """Runs the real PatchPlanningOrchestrator against a discovery-backed provider."""

    def setUp(self):
        from tests.integration import test_patch_planning as planning
        self.fixture = planning.PatchPlanningIntegrationTests()
        self.fixture.setUp()
        self.store = self.fixture.store

    def tearDown(self):
        self.fixture.tearDown()

    def test_orchestrator_persists_discovery_artifact_and_plan_when_available(self):
        runner = FakeRunner()
        runner.when("apt-cache policy openssl", stdout="openssl:\n  Candidate: 1.1\n", exit_code=0)
        service = RemediationDiscoveryService(runner=runner, container_name="victim-aB3x9")
        provider = AutomaticRemediationProvider(service, output_root=self.store.output_root)
        state = self.fixture.run_plan(provider)
        from kalama.state.models import ArtifactKind, RunStatus, PipelineStage
        ref = state.artifact(ArtifactKind.REMEDIATION_DISCOVERY)
        self.assertIsNotNone(ref)
        data = json.loads(Path(ref.path).read_bytes())
        self.assertIn("targets", data)
        # Human confirmation remains mandatory even for an available OS candidate.
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.current_stage, PipelineStage.STEP_5_PATCH_PLAN)
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_FORM))
        # Discovery pre-populates the suggested fields; human must still confirm.
        plan = json.loads(Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        action = next(x for x in plan["actions"] if x["target_cves"] == ["CVE-2099-0001"])
        self.assertEqual(action["candidate"]["fix_type"], "C")
        self.assertEqual(action["candidate"]["strategy"], "PACKAGE_MANAGER")
        self.assertEqual(action["candidate"]["target_version"], "1.1")
        self.assertEqual(action["candidate"]["candidate_status"], "DISCOVERED")
        self.assertEqual(action["candidate"]["execution_readiness"],
                         "HUMAN_CONFIRMATION_REQUIRED")


if __name__ == "__main__":
    unittest.main()