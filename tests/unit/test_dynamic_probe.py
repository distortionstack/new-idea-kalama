from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import yaml

from kalama.dynamic_probe import (
    APPROVED_TEMPLATE_MANIFEST_SCHEMA, ApprovedTemplate, DynamicEndpoint,
    DynamicEvidence, DynamicEvidenceSet, DynamicProbeStatus, DynamicSignal,
    NucleiTemplatePolicy, TemplatePolicyError, load_approved_template_manifest,
)
from kalama.target.models import ObservationStatus, TargetFacts


class DynamicProbeContractTests(unittest.TestCase):
    def facts(self, *, container_id: str = "container-a") -> TargetFacts:
        return TargetFacts(
            "aB3x9", "before", "victim-aB3x9", container_id, "running", "image:test",
            "sha256:image", "repo@sha256:digest", "kalama-net", "172.18.0.11", (), (), (),
            (), (), ObservationStatus.AVAILABLE, (),
        )

    def test_signal_taxonomy_is_explicit_and_distinct(self):
        self.assertEqual({item.value for item in DynamicSignal}, {
            "CORROBORATED", "NOT_OBSERVED", "NOT_APPLICABLE", "NOT_RUN", "INCONCLUSIVE",
        })
        self.assertNotEqual(DynamicSignal.NOT_OBSERVED, DynamicSignal.NOT_APPLICABLE)
        self.assertNotIn("NOT_VULNERABLE", {item.value for item in DynamicSignal})

    def test_evidence_requires_endpoint_but_never_package_identity(self):
        endpoint = DynamicEndpoint.from_target_facts(self.facts(), port=8080)
        evidence = DynamicEvidence(endpoint.endpoint_key, "cves/example", True,
                                   matcher_name="body", cve_id="CVE-2099-0001")
        evidence_set = DynamicEvidenceSet("aB3x9", "before", endpoint,
                                           DynamicProbeStatus.SUCCEEDED, (evidence,))
        self.assertEqual(evidence_set.evidence[0].cve_id, "CVE-2099-0001")
        self.assertFalse(hasattr(evidence_set.evidence[0], "package_name"))

    def test_endpoint_key_binds_run_and_container_not_just_ip_and_port(self):
        left = DynamicEndpoint.from_target_facts(self.facts(container_id="container-a"), port=8080)
        right = DynamicEndpoint.from_target_facts(self.facts(container_id="container-b"), port=8080)
        self.assertEqual(left.ip_address, right.ip_address)
        self.assertEqual(left.port, right.port)
        self.assertNotEqual(left.endpoint_key, right.endpoint_key)
        self.assertEqual(left.to_dict()["run_id"], "aB3x9")
        self.assertEqual(left.to_dict()["container_id"], "container-a")

    def write_manifest(self, root: Path, entries: list[dict[str, object]]) -> Path:
        manifest = root / "approved.yaml"
        manifest.write_text(yaml.safe_dump({
            "schema": APPROVED_TEMPLATE_MANIFEST_SCHEMA,
            "profile": "safe-cve-http",
            "template_revision": "reviewed-test",
            "approved_templates": entries,
        }, sort_keys=False), encoding="utf-8")
        return manifest

    def test_manifest_rejects_template_path_outside_pinned_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "templates"
            root.mkdir()
            manifest = self.write_manifest(root, [{
                "template_id": "outside", "relative_path": "../outside.yaml",
                "expected_sha256": "0" * 64, "mapped_cves": ["CVE-2099-0001"],
            }])
            with self.assertRaises(TemplatePolicyError) as caught:
                load_approved_template_manifest(manifest, root)
        self.assertEqual(caught.exception.code, "NUCLEI_TEMPLATE_OUTSIDE_ROOT")

    def test_manifest_rejects_duplicate_template_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "templates"
            root.mkdir()
            entries = [{
                "template_id": "same", "relative_path": "a.yaml",
                "expected_sha256": "0" * 64, "mapped_cves": ["CVE-2099-0001"],
            }, {
                "template_id": "same", "relative_path": "b.yaml",
                "expected_sha256": "1" * 64, "mapped_cves": ["CVE-2099-0002"],
            }]
            with self.assertRaises(TemplatePolicyError) as caught:
                load_approved_template_manifest(self.write_manifest(root, entries), root)
        self.assertEqual(caught.exception.code, "NUCLEI_TEMPLATE_DUPLICATE_ID")

    def test_approved_template_rejects_parent_path_without_manifest_loader(self):
        with self.assertRaises(TemplatePolicyError) as caught:
            ApprovedTemplate("id", "../../escape.yaml", "0" * 64, ("CVE-2099-0001",))
        self.assertEqual(caught.exception.code, "NUCLEI_TEMPLATE_OUTSIDE_ROOT")

    def test_policy_rejects_redirects_or_non_http_protocols(self):
        with self.assertRaises(TemplatePolicyError) as redirects:
            NucleiTemplatePolicy("safe-cve-http", redirects_allowed=True)
        with self.assertRaises(TemplatePolicyError) as protocols:
            NucleiTemplatePolicy("safe-cve-http", allowed_protocols=frozenset({"http", "dns"}))
        self.assertEqual(redirects.exception.code, "NUCLEI_POLICY_INVALID")
        self.assertEqual(protocols.exception.code, "NUCLEI_POLICY_INVALID")


if __name__ == "__main__":
    unittest.main()
