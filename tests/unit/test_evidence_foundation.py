import hashlib
import tempfile
import unittest
from pathlib import Path

from kalama.config import load_evidence_config
from kalama.evidence import (
    CandidateContext, EvidenceCache, EvidenceCacheRecord, EvidenceItem, EvidencePack,
    EvidencePurpose, EvidenceResult, EvidenceResultState, EvidenceSourceConfig,
    FieldRequest, SourceKind, SourcePolicy,
)


def context(cve="CVE-2099-0001", component="pkg:x", version="1", run="run-a"):
    return CandidateContext(run, cve, component, "apk", (version,), "sha256:image",
                            "target-a", "container-a", "before")


class EvidenceFoundationTests(unittest.TestCase):
    def request(self, ctx=None, fields=("targeturi",), resolved=None):
        return FieldRequest(ctx or context(), EvidencePurpose.EXPLOIT_CONFIGURATION,
                            fields, resolved or {})

    def item(self, ctx=None, content="facts", digest="a" * 64):
        return EvidenceItem(ctx or context(), SourceKind.MSF_METADATA, "metasploit",
                            "module:exploit/x", {"value": content}, content, digest)

    def test_candidate_context_isolation(self):
        a, package, cve = context(), context(component="pkg:y", version="4"), context(cve="CVE-2099-0002")
        self.assertNotEqual(a, package)
        self.assertNotEqual(a, cve)
        with self.assertRaises(ValueError):
            EvidencePack(self.request(a), (self.item(package),))

    def test_incompatible_version_cannot_bind(self):
        v1, v2 = context(version="1"), context(version="2")
        with self.assertRaises(ValueError):
            EvidencePack(self.request(v2), (self.item(v1),))

    def test_digest_is_deterministic_and_semantic(self):
        ctx = context()
        left = EvidencePack(self.request(ctx, ("payload", "targeturi"), {"module": "x"}),
                            (self.item(ctx, "a", "a" * 64), self.item(ctx, "b", "b" * 64)))
        right = EvidencePack(self.request(ctx, ("targeturi", "payload"), {"module": "x"}),
                             tuple(reversed(left.items)))
        self.assertEqual(left.sha256, right.sha256)
        self.assertNotEqual(left.sha256, EvidencePack(self.request(ctx, ("target",), {"module": "x"}), left.items).sha256)
        self.assertNotEqual(left.sha256, EvidencePack(self.request(context(run="run-b"), ("payload", "targeturi"), {"module": "x"}),
                                                      tuple(self.item(context(run="run-b"), x.facts["value"], x.snapshot_sha256) for x in left.items)).sha256)
        self.assertNotEqual(left.sha256, EvidencePack(self.request(ctx, ("payload", "targeturi"), {"module": "y"}), left.items).sha256)

    def test_policy_is_field_specific_and_respects_switches(self):
        request = self.request(fields=("targeturi", "payload", "fixed_version", "known_exploited", "rport"))
        policy = SourcePolicy(EvidenceSourceConfig(vendor_upstream=True, nvd=True))
        self.assertEqual(policy.ordered_sources(request, "rport"), (SourceKind.RUNTIME,))
        self.assertEqual(policy.ordered_sources(request, "payload")[:3], (SourceKind.MSF_METADATA, SourceKind.MSF_MODULE_DOC, SourceKind.MSF_REFERENCE))
        self.assertEqual(policy.ordered_sources(request, "fixed_version"), (SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM, SourceKind.NVD))
        self.assertEqual(policy.ordered_sources(request, "known_exploited"), (SourceKind.CISA_KEV,))
        disabled = SourcePolicy(EvidenceSourceConfig(msf_metadata=False, vendor_upstream=False, nvd=False))
        self.assertEqual(disabled.ordered_sources(request, "payload"), (SourceKind.MSF_MODULE_DOC, SourceKind.MSF_REFERENCE))
        self.assertEqual(disabled.ordered_sources(request, "fixed_version"), (SourceKind.KNOWLEDGE,))

    def test_result_failure_states_are_explicit_and_non_evidence(self):
        for state in (EvidenceResultState.UNAVAILABLE, EvidenceResultState.NOT_APPLICABLE,
                      EvidenceResultState.NO_AUTHORITATIVE_SOURCE, EvidenceResultState.REJECTED_BY_POLICY):
            result = EvidenceResult(state, SourceKind.NVD, detail="not safe")
            self.assertFalse(result.items)
        stale = EvidenceResult(EvidenceResultState.STALE_CACHE_FALLBACK, SourceKind.NVD,
                               (EvidenceItem(context(), SourceKind.NVD, "nvd", "CVE-2099-0001"),))
        self.assertEqual(stale.state, EvidenceResultState.STALE_CACHE_FALLBACK)

    def test_cache_is_content_addressed_and_history_is_immutable(self):
        with tempfile.TemporaryDirectory() as root:
            cache = EvidenceCache(root)
            old = cache.store_raw(b"old")
            self.assertEqual(old, cache.store_raw(b"old"))
            new = cache.store_raw(b"new")
            self.assertNotEqual(old, new)
            self.assertEqual(cache.read_raw(old), b"old")
            norm = cache.store_normalized({"z": 1, "a": [2]})
            self.assertEqual(cache.read_normalized(norm), b'{"a":[2],"z":1}')
            record = cache.record(EvidenceCacheRecord(SourceKind.NVD, "nvd", "CVE-2099-0001",
                "v1", "2026-01-01T00:00:00Z", hashlib.sha256(b"old").hexdigest(),
                raw_snapshot_sha256=old, normalized_snapshot_sha256=norm, cache_status="MISS",
                freshness={"ttl_seconds": 3600}))
            found = cache.records(SourceKind.NVD, "CVE-2099-0001")
            self.assertEqual(found, (record,))
            self.assertFalse((Path(root) / "knowledge" / "kalama-knowledge.sqlite3").exists())

    def test_evidence_config_defaults_and_external_switches(self):
        default = load_evidence_config(env={})
        self.assertTrue(default.runtime)
        self.assertFalse(default.vendor_upstream)
        self.assertFalse(default.nvd)
        configured = load_evidence_config(env={"KALAMA_EVIDENCE_VENDOR_UPSTREAM_ENABLED": "true",
                                               "KALAMA_EVIDENCE_NVD_ENABLED": "1"})
        self.assertTrue(configured.vendor_upstream)
        self.assertTrue(configured.nvd)
        self.assertFalse(configured.web_search)


if __name__ == "__main__":
    unittest.main()
