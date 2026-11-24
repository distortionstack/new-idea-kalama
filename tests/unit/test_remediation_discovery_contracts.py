from __future__ import annotations

import copy
import json
import unittest

from kalama.remediation.discovery.codec import (
    artifact_from_dict, artifact_to_dict, legacy_dict_to_v2, v2_to_legacy_candidate,
)
from kalama.remediation.discovery.contracts import (
    DiscoveryRequest, PackageIdentity, ProviderResult, ProviderStatus, RepositoryContext,
    RepositoryContextStatus, ResourceChecksum, ResourceKind, ResourceLocationStatus,
    ResourceRecord, UnifiedDiscoveryResult, UnifiedDiscoveryStatus, VerificationDimension,
    VerificationResult, VerificationStatus,
)
from kalama.remediation.discovery.service import RemediationDiscoveryService


class FakeRunner:
    def run(self, argv, *, timeout=None):
        package = str(argv[-1]).split()[-1]
        versions = {"alpha": "1.1", "beta": "2.1"}
        return type("R", (), {
            "exit_code": 0,
            "stdout": f"Candidate: {versions.get(package, 'UNKNOWN')}\n",
            "stderr": "",
        })


def request() -> DiscoveryRequest:
    return DiscoveryRequest(
        "request-1", "CVE-2099-0001", "occurrence-1",
        (("package_uid", "uid-1"), ("scanner", "trivy")),
        "sha256:image", "pkg:npm/%40scope/name@1.0.0?arch=x86_64#src/lib",
        "pkg:npm/%40scope/name@1.0.0?arch=x86_64#src/lib",
        PackageIdentity("npm", "@scope", "name", (("arch", "x86_64"),), "src/lib"),
        "1.0.0", "1.1.0",
        RepositoryContext(architecture="amd64", status=RepositoryContextStatus.PARTIAL,
                          missing_fields=("distro",)),
    )


def result() -> UnifiedDiscoveryResult:
    item = request()
    resource = ResourceRecord(
        "resource-1", item.package, item.requested_fixed_version, "1.1.0", "amd64", None,
        "fixture-provider", "1.0", ResourceKind.BINARY_PACKAGE,
        "https://user:password@example.test/name.tgz?token=secret",
        ResourceLocationStatus.EVIDENCE_BACKED, "name.tgz", 12,
        (ResourceChecksum("sha256", "a" * 64, "registry metadata"),),
    )
    unknown = VerificationDimension(VerificationStatus.UNVERIFIED,
                                    error_code="CONTENT_NOT_CHECKED")
    verified = VerificationDimension(VerificationStatus.VERIFIED,
                                     evidence="exact registry metadata", source="fixture")
    verification = VerificationResult(
        item.request_id, resource.resource_id, verified, verified, unknown, unknown,
        verified, unknown, unknown, (), ("content checksum",),
    )
    provider = ProviderResult(
        item.request_id, "fixture-provider", "1.0", ProviderStatus.RESOLVED,
        (resource,), (),
        {"Authorization": "Bearer secret", "url": resource.url, "body": "x" * 20000},
    )
    return UnifiedDiscoveryResult(item, (provider,), (verification,),
                                  ("content checksum",), UnifiedDiscoveryStatus.UNVERIFIED)


class DiscoveryContractTests(unittest.TestCase):
    def test_v2_round_trip_preserves_identity_and_provenance(self):
        original = result()
        artifact = artifact_to_dict("aB3x9", (original,))
        encoded = json.dumps(artifact)
        self.assertNotIn("Bearer secret", encoded)
        self.assertNotIn("user:password@", encoded)
        self.assertTrue(artifact["results"][0]["provider_results"][0]
                        ["raw_evidence_truncated"])
        restored = artifact_from_dict(artifact)[0]
        self.assertEqual(restored.request.package, original.request.package)
        self.assertEqual(restored.request.occurrence_provenance,
                         original.request.occurrence_provenance)
        self.assertEqual(restored.request.request_id, original.request.request_id)

    def test_v2_provider_error_status_remains_replay_compatible(self):
        artifact = artifact_to_dict("aB3x9", (result(),))
        artifact["results"][0]["status"] = UnifiedDiscoveryStatus.PROVIDER_ERROR.value
        artifact["results"][0]["provider_results"][0]["status"] = (
            ProviderStatus.PROVIDER_ERROR.value
        )

        restored = artifact_from_dict(artifact)[0]
        self.assertEqual(restored.status, UnifiedDiscoveryStatus.PROVIDER_ERROR)
        self.assertEqual(restored.provider_results[0].status,
                         ProviderStatus.PROVIDER_ERROR)

    def test_v1_replay_marks_unknown_fields_without_inventing_provenance(self):
        legacy = {
            "schema": "kalama.remediation-discovery/v1", "run_id": "aB3x9",
            "targets": [{
                "cve_id": "CVE-1", "classification": "OS_PACKAGE",
                "package_or_product": "curl", "current_version": "1.0",
                "fixed_version": "1.1", "candidate_status": "DISCOVERED",
                "evidence": [],
            }],
        }
        restored = artifact_from_dict(legacy)[0]
        self.assertEqual(restored.request.occurrence_provenance, ())
        self.assertIsNone(restored.request.original_purl)
        self.assertIn("occurrence_provenance", restored.request.missing_fields)
        self.assertEqual(restored.status, UnifiedDiscoveryStatus.UNVERIFIED)
        self.assertEqual(restored.verification_results[0].identity.status,
                         VerificationStatus.UNVERIFIED)

    def test_multiple_packages_and_fixed_versions_get_distinct_requests(self):
        occurrences = [
            {"canonical_cve_id": "CVE-1", "package_name": "alpha",
             "package_uid": "alpha-uid", "installed_version": "1.0",
             "fixed_versions": ["1.1", "1.2"], "result_class": "os-pkgs",
             "result_type": "debian"},
            {"canonical_cve_id": "CVE-1", "package_name": "beta",
             "package_uid": "beta-uid", "installed_version": "2.0",
             "fixed_versions": ["2.1"], "result_class": "os-pkgs",
             "result_type": "debian"},
        ]
        service = RemediationDiscoveryService(runner=FakeRunner(), container_name="victim-X")
        values = service.discover_unified([], occurrences, {"image_id": "sha256:image"})
        self.assertEqual(len(values), 3)
        self.assertEqual(len({x.request.request_id for x in values}), 3)
        self.assertEqual({x.request.requested_fixed_version for x in values},
                         {"1.1", "1.2", "2.1"})
        self.assertEqual({x.request.occurrence_id for x in values},
                         {"alpha-uid", "beta-uid"})

    def test_unknown_status_and_malformed_enum_are_rejected(self):
        artifact = artifact_to_dict("aB3x9", (result(),))
        broken = copy.deepcopy(artifact)
        broken["results"][0]["status"] = "READY"
        with self.assertRaisesRegex(ValueError, "invalid unified discovery status"):
            artifact_from_dict(broken)
        broken = copy.deepcopy(artifact)
        broken["results"][0]["provider_results"][0]["resources"][0]["kind"] = "URL"
        with self.assertRaisesRegex(ValueError, "invalid resource enum"):
            artifact_from_dict(broken)

        legacy = {
            "schema": "kalama.remediation-discovery/v1",
            "targets": [{"cve_id": "CVE-1", "candidate_status": "READY"}],
        }
        with self.assertRaisesRegex(ValueError, "invalid legacy discovery enum"):
            artifact_from_dict(legacy)

    def test_verification_must_reference_resource_in_same_request(self):
        artifact = artifact_to_dict("aB3x9", (result(),))
        artifact["results"][0]["verification_results"][0]["resource_id"] = "other"
        with self.assertRaisesRegex(ValueError, "not linked"):
            artifact_from_dict(artifact)

    def test_v2_legacy_projection_never_derives_strategy_or_trust(self):
        projected = v2_to_legacy_candidate(result())
        self.assertIsNone(projected.fix_type)
        self.assertIsNone(projected.strategy)
        self.assertFalse(projected.trusted)

    def test_legacy_adapter_is_deterministic(self):
        value = {"cve_id": "CVE-1", "package_or_product": "curl",
                 "fixed_version": "1.1", "candidate_status": "DISCOVERED"}
        self.assertEqual(legacy_dict_to_v2(value), legacy_dict_to_v2(value))


if __name__ == "__main__":
    unittest.main()
