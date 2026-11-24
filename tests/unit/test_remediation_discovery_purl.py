from __future__ import annotations

import json
import unittest

from packageurl import PackageURL

from kalama.remediation.discovery.codec import artifact_from_dict, artifact_to_dict
from kalama.remediation.discovery.contracts import ProviderStatus, UnifiedDiscoveryStatus
from kalama.remediation.discovery.purl import (
    NormalizationErrorCode, compare_debian_versions, normalize_purl, versions_equal,
)
from kalama.remediation.discovery.service import RemediationDiscoveryService


class FailingRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout=None):
        self.calls.append(tuple(argv))
        raise AssertionError("malformed PURL reached OS provider")


class PurlNormalizationTests(unittest.TestCase):
    def test_round_trip_preserves_namespace_qualifiers_subpath_and_encoding(self):
        value = normalize_purl(
            "pkg:npm/%40scope/name@1.0.0?arch=x86_64&download_url="
            "https%3A%2F%2Fexample.test%2Fa%20b#src%2Flib",
            "1.1.0",
        )
        self.assertTrue(value.ok)
        self.assertEqual(value.package.package_type, "npm")
        self.assertEqual(value.package.namespace, "@scope")
        self.assertEqual(value.package.name, "name")
        self.assertEqual(dict(value.package.qualifiers)["arch"], "x86_64")
        self.assertEqual(value.package.subpath, "src/lib")
        self.assertIn("%40scope", value.fixed_version_purl)
        self.assertIn("@1.1.0", value.fixed_version_purl)
        self.assertIn("download_url=https://example.test/a%20b", value.fixed_version_purl)
        self.assertTrue(value.fixed_version_purl.endswith("#src/lib"))

        reparsed = PackageURL.from_string(value.fixed_version_purl)
        self.assertEqual(reparsed.type, "npm")
        self.assertEqual(reparsed.namespace, "@scope")
        self.assertEqual(reparsed.name, "name")
        self.assertEqual(reparsed.version, "1.1.0")
        self.assertEqual(
            dict(reparsed.qualifiers),
            {"arch": "x86_64", "download_url": "https://example.test/a b"},
        )
        self.assertEqual(reparsed.subpath, "src/lib")

    def test_nonexistent_version_is_preserved_and_not_aliased(self):
        value = normalize_purl("pkg:pypi/requests@2.31.0", "999.0-does-not-exist")
        self.assertTrue(value.ok)
        self.assertEqual(value.scanner_requested_version, "999.0-does-not-exist")
        self.assertIn("@999.0-does-not-exist", value.fixed_version_purl)
        self.assertIsNone(value.registry_normalized_version)
        self.assertIsNone(value.provider_resolved_version)

    def test_ecosystem_version_forms_are_preserved(self):
        cases = (
            ("pkg:deb/debian/curl@1", "2:7.88.1-10+deb12u1"),
            ("pkg:apk/alpine/busybox@1", "1.36.1-r1"),
            ("pkg:golang/github.com/example/module@v1.0.0", "v1.2.3"),
            ("pkg:composer/vendor/name@1.0.0", "v2.0.0"),
        )
        for original, requested in cases:
            with self.subTest(original=original):
                value = normalize_purl(original, requested)
                self.assertTrue(value.ok)
                self.assertEqual(value.scanner_requested_version, requested)
                self.assertIn(requested.replace("+", "%2B"), value.fixed_version_purl)

    def test_version_comparison_policy_is_ecosystem_specific(self):
        self.assertTrue(versions_equal("deb", "1.0", "0:1.0-0"))
        self.assertGreater(compare_debian_versions("2:1.0", "1:9.9"), 0)
        self.assertGreater(compare_debian_versions("1.0-1ubuntu2", "1.0-1ubuntu1"), 0)
        self.assertFalse(versions_equal("apk", "1.2.3-r0", "1.2.3-r1"))
        self.assertFalse(versions_equal("golang", "v1.2.3", "1.2.3"))
        self.assertFalse(versions_equal("composer", "v2.0.0", "2.0.0"))

    def test_debian_and_ubuntu_version_suffixes_survive_purl_round_trip(self):
        cases = (
            ("pkg:deb/ubuntu/openssl@1", "1.1.1f-1ubuntu2.22"),
            ("pkg:deb/debian/curl@1", "2:7.88.1-10+deb12u1"),
            ("pkg:deb/debian/libssl3@1", "3.0.11-1~deb12u2+b1"),
            ("pkg:deb/debian/libssl3@1", "3.0.11-1~deb12u2+b2"),
        )
        for original, requested in cases:
            with self.subTest(requested=requested):
                value = normalize_purl(original, requested)
                self.assertTrue(value.ok)
                reparsed = PackageURL.from_string(value.fixed_version_purl)
                self.assertEqual(reparsed.version, requested)

        self.assertLess(
            compare_debian_versions(
                "3.0.11-1~deb12u2+b1", "3.0.11-1~deb12u2+b2"
            ),
            0,
        )
        self.assertFalse(
            versions_equal(
                "deb", "3.0.11-1~deb12u2+b1", "3.0.11-1~deb12u2+b2"
            )
        )

    def test_malformed_purl_returns_structured_error_and_skips_provider(self):
        runner = FailingRunner()
        service = RemediationDiscoveryService(runner=runner, container_name="victim-X")
        results = service.discover_unified([], [{
            "canonical_cve_id": "CVE-1", "package_name": "curl",
            "package_purl": "not-a-purl", "installed_version": "1.0",
            "fixed_versions": ["1.1"], "result_class": "os-pkgs",
            "result_type": "debian",
        }])
        self.assertEqual(runner.calls, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, UnifiedDiscoveryStatus.INVALID_REQUEST)
        self.assertEqual(results[0].provider_results[0].status,
                         ProviderStatus.INVALID_REQUEST)
        self.assertEqual(results[0].provider_results[0].errors[0].code,
                         NormalizationErrorCode.PURL_INVALID.value)
        self.assertIsNone(results[0].request.original_purl)
        self.assertNotIn("package_purl", dict(results[0].request.occurrence_provenance))

    def test_credential_bearing_qualifier_is_rejected_without_echo(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url=https://user:secret@example.test/repo",
            "1.1.0",
        )
        self.assertFalse(value.ok)
        self.assertEqual(value.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)
        self.assertNotIn("secret", value.error.safe_message)
        self.assertIsNone(value.original_purl)

    def test_sensitive_query_parameter_in_url_qualifier_is_rejected(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https://example.test/repo%3Ftoken%3Dquery-secret",
            "1.1.0",
        )
        self.assertFalse(value.ok)
        self.assertEqual(value.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)
        self.assertNotIn("query-secret", value.error.safe_message)
        self.assertIsNone(value.original_purl)

    def test_single_encoded_credential_url_is_rejected(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https%3A%2F%2Fexample.test%2Frepo%3Ftoken%3Dsingle-secret",
            "1.1.0",
        )
        self.assertFalse(value.ok)
        self.assertEqual(value.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)
        self.assertNotIn("single-secret", value.error.safe_message)
        self.assertIsNone(value.original_purl)

    def test_double_encoded_credential_url_is_rejected(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https%253A%252F%252Fexample.test%252Frepo%253Fapi_key%253Ddouble-secret",
            "1.1.0",
        )
        self.assertFalse(value.ok)
        self.assertEqual(value.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)
        self.assertNotIn("double-secret", value.error.safe_message)
        self.assertIsNone(value.original_purl)

        selectively_encoded = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https://example.test/repo%253Fpassword%253Ddouble-secret",
            "1.1.0",
        )
        self.assertFalse(selectively_encoded.ok)
        self.assertEqual(selectively_encoded.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)

    def test_url_encoding_beyond_decode_budget_is_rejected(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https%25253A%25252F%25252Fexample.test%25252Frepo",
            "1.1.0",
        )
        self.assertFalse(value.ok)
        self.assertEqual(value.error.code,
                         NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED)
        self.assertIsNone(value.original_purl)

    def test_double_encoded_url_without_credentials_is_accepted(self):
        value = normalize_purl(
            "pkg:npm/name@1.0.0?repository_url="
            "https%253A%252F%252Fexample.test%252Frepository",
            "1.1.0",
        )
        self.assertTrue(value.ok)
        self.assertEqual(
            dict(value.package.qualifiers)["repository_url"],
            "https%3A%2F%2Fexample.test%2Frepository",
        )

    def test_credential_bearing_purl_is_absent_from_serialized_result(self):
        secret = "serialization-leak-sentinel"
        purl = (
            "pkg:npm/name@1.0.0?repository_url="
            f"https://user:{secret}@example.test/repo"
        )
        runner = FailingRunner()
        service = RemediationDiscoveryService(runner=runner, container_name="victim-X")
        results = service.discover_unified([], [{
            "canonical_cve_id": "CVE-1", "package_name": "name",
            "package_purl": purl, "installed_version": "1.0.0",
            "fixed_versions": ["1.1.0"], "result_class": "lang-pkgs",
            "result_type": "npm",
        }])

        artifact = artifact_to_dict("credential-redaction", results)
        encoded = json.dumps(artifact, sort_keys=True)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("user:", encoded)
        serialized_result = artifact["results"][0]
        self.assertIsNone(serialized_result["request"]["original_purl"])
        self.assertIsNone(serialized_result["request"]["normalized_purl"])
        self.assertNotIn(
            "package_purl", serialized_result["request"]["occurrence_provenance"]
        )
        provider = serialized_result["provider_results"][0]
        self.assertEqual(provider["status"], ProviderStatus.INVALID_REQUEST.value)
        self.assertEqual(
            provider["errors"],
            [{
                "code": NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED.value,
                "safe_message": "package PURL contains credential-bearing qualifiers",
            }],
        )
        self.assertEqual(
            provider["raw_evidence"],
            {
                "stage": "purl_normalization",
                "error_code":
                    NormalizationErrorCode.PURL_CREDENTIALS_NOT_ALLOWED.value,
            },
        )
        restored = artifact_from_dict(artifact)[0]
        self.assertEqual(restored.status, UnifiedDiscoveryStatus.INVALID_REQUEST)
        self.assertEqual(restored.provider_results[0].status,
                         ProviderStatus.INVALID_REQUEST)
        self.assertEqual(runner.calls, [])

    def test_double_encoded_secret_is_absent_from_artifact_and_provider(self):
        secret = "double-serialization-leak-sentinel"
        purl = (
            "pkg:npm/name@1.0.0?repository_url="
            f"https%253A%252F%252Fexample.test%252Frepo%253Fpassword%253D{secret}"
        )
        runner = FailingRunner()
        service = RemediationDiscoveryService(runner=runner, container_name="victim-X")
        results = service.discover_unified([], [{
            "canonical_cve_id": "CVE-1", "package_name": "name",
            "package_purl": purl, "installed_version": "1.0.0",
            "fixed_versions": ["1.1.0"], "result_class": "os-pkgs",
            "result_type": "debian",
        }])

        encoded = json.dumps(
            artifact_to_dict("double-credential-redaction", results),
            sort_keys=True,
        )
        self.assertNotIn(secret, encoded)
        self.assertNotIn(purl, encoded)
        self.assertEqual(results[0].status,
                         UnifiedDiscoveryStatus.INVALID_REQUEST)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
