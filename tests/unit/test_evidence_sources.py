import tempfile
import unittest
from types import SimpleNamespace

from kalama.evidence import *
from kalama.knowledge import KnowledgeRecord, KnowledgeStore, TrustState


def ctx(cve="CVE-2099-1", component="pkg:x", version="1"):
    return CandidateContext("run", cve, component, "apk", (version,), "img", "target", "cid")


class ExistingEvidenceAdapterTests(unittest.TestCase):
    def request(self, context, fields, purpose=EvidencePurpose.EXPLOIT_CONFIGURATION):
        return FieldRequest(context, purpose, tuple(fields))

    def candidate(self):
        option = SimpleNamespace(name="TARGETURI", default="/", to_dict=lambda: {"name":"TARGETURI","default":"/"})
        target = SimpleNamespace(to_dict=lambda: {"index":0,"name":"auto"})
        payload = SimpleNamespace(to_dict=lambda: {"name":"cmd/unix/reverse"})
        return SimpleNamespace(module_path="exploit/test/x", target_details=(target,), options=(option,),
                               payloads=(payload,), references=("https://vendor.invalid/advisory",),
                               check_supported=True, rank="excellent", default_target_index=0)

    def test_runtime_is_candidate_bound(self):
        occurrences = ({"canonical_cve_id":"CVE-2099-1","package_purl":"pkg:x","installed_version":"1","fixed_versions":["2"]},)
        source = RuntimeEvidenceSource(occurrences, {"reachable_ports":[8080],"target_port":8080}, "artifact:scan")
        available = source.collect(self.request(ctx(), ("rport","fixed_version")))
        self.assertEqual(available.state, EvidenceResultState.AVAILABLE)
        self.assertEqual(available.items[0].facts["rport"], 8080)
        self.assertEqual(source.collect(self.request(ctx(component="pkg:y"), ("rport",))).state, EvidenceResultState.NOT_APPLICABLE)
        self.assertEqual(source.collect(self.request(ctx(version="2"), ("rport",))).state, EvidenceResultState.NOT_APPLICABLE)

    def test_validated_knowledge_is_field_granular_and_compatible(self):
        with tempfile.TemporaryDirectory() as root:
            store = KnowledgeStore(root)
            store.upsert(KnowledgeRecord("CVE-2099-1", "pkg:x", {"package_purl":"pkg:x","installed_version":"1"}, "attack_config", {"targeturi":"/S2-045/"}, TrustState.VALIDATED, "origin", {"sha":"evidence"}))
            source = KnowledgeEvidenceSource(store)
            result = source.collect(self.request(ctx(), ("targeturi","payload")))
            self.assertEqual(result.state, EvidenceResultState.AVAILABLE)
            self.assertEqual(result.items[0].facts["targeturi"], "/S2-045/")
            self.assertNotIn("payload", result.items[0].facts)
            self.assertEqual(source.collect(self.request(ctx(version="2"), ("targeturi",))).state, EvidenceResultState.NOT_APPLICABLE)

    def test_msf_and_reference_remain_distinct(self):
        candidates={"CVE-2099-1":self.candidate()}; request=self.request(ctx(), ("targeturi","payload"))
        msf=MSFMetadataEvidenceSource(candidates, "artifact:resolver").collect(request)
        refs=MSFReferenceEvidenceSource(candidates, "artifact:resolver").collect(request)
        self.assertEqual(msf.items[0].source_kind, SourceKind.MSF_METADATA)
        self.assertEqual(refs.items[0].source_kind, SourceKind.MSF_REFERENCE)
        self.assertEqual(refs.items[0].authority, "metasploit-reference")

    def test_partial_knowledge_does_not_block_target_payload_collection_or_call_kev(self):
        request=self.request(ctx(), ("target","payload"))
        collector=EvidenceCollector(SourcePolicy(), {SourceKind.MSF_METADATA:MSFMetadataEvidenceSource({"CVE-2099-1":self.candidate()}), SourceKind.CISA_KEV:CISAKEVEvidenceSource(None)})
        result=collector.collect(request)
        self.assertEqual(result.pack.request.unresolved_fields, ("payload","target"))
        self.assertTrue(any(x.source_kind == SourceKind.MSF_METADATA and x.state == EvidenceResultState.AVAILABLE for x in result.results))
        self.assertFalse(any(x.source_kind == SourceKind.CISA_KEV for x in result.results))

    def test_failures_are_isolated_and_empty_pack_is_valid(self):
        class Broken:
            def collect(self, request): raise RuntimeError("offline")
        request=self.request(ctx(), ("targeturi",))
        outcome=EvidenceCollector(SourcePolicy(), {SourceKind.MSF_METADATA:Broken()}).collect(request)
        self.assertTrue(any(x.state == EvidenceResultState.UNAVAILABLE for x in outcome.results))
        self.assertEqual(outcome.pack.items, ())

    def test_kev_is_status_only(self):
        kev=CISAKEVEvidenceSource({"cve_ids":["CVE-2099-1"],"sha256":"a"*64})
        self.assertEqual(kev.collect(self.request(ctx(), ("payload",))).state, EvidenceResultState.NOT_APPLICABLE)
        result=kev.collect(self.request(ctx(), ("known_exploited",), EvidencePurpose.EXPLOITATION_STATUS))
        self.assertTrue(result.items[0].facts["known_exploited"])


if __name__ == "__main__": unittest.main()
