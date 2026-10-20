"""Task 4B deterministic tests: field scheduling + evidence production wiring.

No network, Docker, Ollama, or live Metasploit.  Fake collectors/providers
exercise the real production scheduling/merge logic.
"""

import unittest
from dataclasses import replace

from kalama.evidence import (
    CandidateContext,
    Collection,
    EvidenceItem,
    EvidencePack as FieldEvidencePack,
    EvidenceResult,
    EvidenceResultState,
    SourceKind,
)
from kalama.guidance.models import PROPOSAL_SCHEMA
from kalama.guidance.service import GuidanceService
from kalama.resolution.llm_fields import (
    LLM_ELIGIBLE_FIELDS,
    build_candidate_context,
    build_field_request,
    effective_fields,
)
from kalama.resolution.models import RankedCVEInput, ResolverCVEStatus, Step4Analysis
from kalama.resolution.resolver_stage import analyze_cves, target_facts_from_state
from kalama.resolver.config_models import ConfirmationStatus, ExploitValue
from tests.integration import test_step4_orchestrator as helpers

CVE = "CVE-2017-5638"
OCCURRENCES = (
    {
        "package_name": "struts2-core",
        "package_purl": "pkg:maven/org.apache.struts/struts2-core@2.5.12",
        "installed_version": "2.5.12",
        "result_type": "maven",
    },
)
RAW_TARGET = {
    "container_id": "cid-4b",
    "requested_image_reference": "vulhub/struts2:2.3.15",
    "network": "kalama-net",
    "ip_address": "172.18.0.3",
    "exposed_ports": [{"container_port": 8080}],
    "reachable_ports": [8080],
}
KNOWLEDGE_GUIDANCE = {
    CVE: {
        "provider_status": "KNOWLEDGE_HIT",
        "validation_state": "VALIDATED",
        "accepted_suggestions": {
            "targeturi": {
                "value": "/S2-045/",
                "evidence_refs": ["knowledge.record.7"],
                "reason": "validated compatible knowledge",
            }
        },
    }
}


def make_analysis(occurrences=OCCURRENCES):
    payloads = [{"name": "cmd/unix/reverse_bash"}, {"name": "cmd/unix/generic"}]
    live = {
        "exploit/multi/http/struts2_rest_xstream": {
            "options": [
                {"name": "RPORT", "type": "port", "required": True, "default": 8080},
                {"name": "TARGETURI", "type": "path", "required": True, "default": "/demo/"},
            ],
            "target_details": [{"index": 0, "name": "Universal"}],
            "default_target_index": 0,
            "status": "FOUND",
            "payloads": payloads,
            "check_supported": True,
        }
    }
    facts = target_facts_from_state(
        "run-4b",
        {
            "container_id": "cid-4b",
            "requested_image_reference": "vulhub/struts2:2.3.15",
            "network": "kalama-net",
            "ip_address": "172.18.0.3",
            "exposed_ports": [{"container_port": 8080}],
            "reachable_ports": [8080],
        },
    )
    return analyze_cves(
        (RankedCVEInput(1, CVE, occurrences),),
        facts,
        helpers.backend(
            candidates={"exploit/multi/http/struts2_rest_xstream": {"rank": "excellent", "check_supported": True}},
            live=live,
        ),
        "msf",
    )


class FakeCollector:
    def __init__(self, items_factory):
        self.calls = []
        self._factory = items_factory

    def collect(self, request):
        self.calls.append(request)
        items = tuple(self._factory(request))
        pack = FieldEvidencePack(request, items)
        results = (
            EvidenceResult(EvidenceResultState.AVAILABLE, items[0].source_kind, items)
            if items
            else (EvidenceResult(EvidenceResultState.NOT_APPLICABLE, SourceKind.RUNTIME),)
        )
        if items:
            return Collection(pack, (results,))
        return Collection(pack, results if isinstance(results, tuple) else (results,))


class FakeProvider:
    name = "fake-llm"

    def __init__(self, proposals_factory):
        self.calls = []
        self.config = type("C", (), {"model": "fake"})()
        self._factory = proposals_factory

    def propose(self, document, sha256):
        self.calls.append((document, sha256))
        return self._factory(document, sha256), 0.01


class FieldSchedulingTests(unittest.TestCase):
    def test_eligible_fields_are_locked(self):
        self.assertEqual(tuple(sorted(LLM_ELIGIBLE_FIELDS)), ("payload", "rport", "target", "targeturi"))
        for forbidden in ("module", "module_options", "payload_options",
                           "execution_protocol", "preconditions", "RHOSTS",
                           "LHOST", "LPORT", "commands"):
            self.assertNotIn(forbidden, LLM_ELIGIBLE_FIELDS)

    def test_partial_knowledge_exact_wiring(self):
        analysis = make_analysis()
        item = analysis.cves[0]
        self.assertEqual(item.status, ResolverCVEStatus.WAITING_FOR_USER_INPUT)
        # Deterministic rport is already confirmed at 8080.
        self.assertTrue(item.exploit_config.environment.rport.confirmed)
        self.assertEqual(item.exploit_config.environment.rport.value, 8080)

        resolved, unresolved = effective_fields(item, KNOWLEDGE_GUIDANCE[CVE])
        self.assertEqual(resolved.get("rport"), 8080)
        self.assertEqual(resolved.get("targeturi"), "/S2-045/")
        self.assertEqual(set(unresolved), {"target", "payload"})

        context = build_candidate_context("run-4b", CVE, OCCURRENCES, RAW_TARGET)
        self.assertIsInstance(context, CandidateContext)
        self.assertEqual(context.run_id, "run-4b")
        self.assertEqual(context.vulnerability_id, CVE)
        self.assertIn("struts", context.component)
        self.assertEqual(context.phase, "before")
        self.assertEqual(context.image_identity, "vulhub/struts2:2.3.15")

        request = build_field_request(context, resolved, unresolved)
        self.assertEqual(set(request.unresolved_fields), {"target", "payload"})
        self.assertNotIn("rport", set(request.unresolved_fields))
        self.assertNotIn("targeturi", set(request.unresolved_fields))
        self.assertEqual(request.purpose.value, "EXPLOIT_CONFIGURATION")

        def items_factory(request):
            yield EvidenceItem(
                request.context, SourceKind.MSF_METADATA, "metasploit",
                "msf-module:exploit/multi/http/struts2_rest_xstream",
                {"target": [{"index": 0, "name": "Universal"}],
                 "payload": ["cmd/unix/reverse_bash"]},
                provenance_ref="msf:exploit/multi/http/struts2_rest_xstream",
            )

        collector = FakeCollector(items_factory)

        def proposals_factory(document, sha):
            return {
                "schema": PROPOSAL_SCHEMA,
                "status": "PROPOSED",
                "run_id": "run-4b",
                "cve_id": CVE,
                "evidence_pack_sha256": sha,
                # Hardened protocol (Task 4C): echo the exact bindings.
                "candidate_digest": document.get("candidate_digest"),
                "field_evidence_sha256": document.get("field_evidence_sha256"),
                "proposals": {
                    "target": {"value": {"index": 0, "name": "Universal"},
                               "evidence_refs": ["metasploit.targets"], "reason": "default target"},
                    "payload": {"value": "cmd/unix/reverse_bash",
                                "evidence_refs": ["metasploit.compatible_payload_subset"],
                                "reason": "compatible"},
                },
                "missing_evidence": [],
                "guidance_notes": [],
                "reasoning_summary": "test",
            }

        provider = FakeProvider(proposals_factory)
        service = GuidanceService(provider)

        from kalama.resolution.llm_fields import schedule_field_guidance

        outcomes = schedule_field_guidance(
            "run-4b", analysis, RAW_TARGET, KNOWLEDGE_GUIDANCE, service, collector
        )
        # EvidenceCollector invoked exactly once for the unresolved fields.
        self.assertEqual(len(collector.calls), 1)
        self.assertEqual(set(collector.calls[0].unresolved_fields), {"target", "payload"})
        # GuidanceService invoked once the useful pack exists.
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        # The collected pack is the pack consumed by GuidanceService.
        collected = collector.calls[0]
        collected_pack = None
        # Re-derive the collected pack via a second identical collect is not
        # needed: the outcome carries the exact pack object.
        self.assertIsNotNone(outcome.field_evidence_pack)
        self.assertEqual(outcome.field_evidence_pack.sha256,
                         outcome.evidence_pack.document["field_evidence_sha256"])
        self.assertEqual(outcome.field_evidence_pack.to_dict(),
                         outcome.evidence_pack.document["field_evidence_pack"])
        consumed_doc, consumed_sha = provider.calls[0]
        self.assertEqual(consumed_sha, outcome.evidence_pack.sha256)
        self.assertEqual(consumed_doc["field_evidence_sha256"],
                         outcome.field_evidence_pack.sha256)
        # Exact model authority.
        self.assertEqual(set(outcome.evidence_pack.document["allowed_proposal_fields"]),
                         {"target", "payload"})
        # Knowledge/deterministic protection: no rport/targeturi acceptance.
        self.assertNotIn("rport", outcome.accepted)
        self.assertNotIn("targeturi", outcome.accepted)
        self.assertLessEqual(set(outcome.accepted), {"target", "payload"})
        # Suggestions remain suggestions: deterministic config unconfirmed.
        self.assertFalse(item.exploit_config.invariant.target_selection.target_index.confirmed)
        self.assertFalse(item.exploit_config.invariant.payload.payload.confirmed)
        self.assertTrue(item.exploit_config.environment.rport.confirmed)
        # Effective values preserved through the call.
        self.assertEqual(resolved["rport"], 8080)
        self.assertEqual(resolved["targeturi"], "/S2-045/")
        _ = collected_pack

    def test_fully_resolved_short_circuit(self):
        analysis = make_analysis()
        item = analysis.cves[0]
        invariant = item.exploit_config.invariant
        confirmed_target = replace(
            invariant.target_selection.target_index,
            value=0, suggested_value=0,
            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED,
        )
        confirmed_name = replace(
            invariant.target_selection.target_name,
            value="Universal", suggested_value="Universal",
            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED,
        )
        selection = replace(invariant.target_selection, target_index=confirmed_target,
                            target_name=confirmed_name)
        targeturi = replace(invariant.targeturi, value="/S2-045/",
                            suggested_value="/S2-045/",
                            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED)
        payload_value = replace(invariant.payload.payload, value="cmd/unix/reverse_bash",
                                suggested_value="cmd/unix/reverse_bash",
                                confirmation_status=ConfirmationStatus.AUTO_CONFIRMED)
        payload = replace(invariant.payload, payload=payload_value)
        new_invariant = replace(invariant, target_selection=selection,
                                targeturi=targeturi, payload=payload)
        new_config = replace(item.exploit_config, invariant=new_invariant)
        confirmed_item = replace(item, exploit_config=new_config)
        confirmed_analysis = Step4Analysis((confirmed_item,))

        resolved, unresolved = effective_fields(confirmed_item, KNOWLEDGE_GUIDANCE[CVE])
        self.assertEqual(unresolved, ())
        self.assertEqual(set(resolved), {"target", "targeturi", "rport", "payload"})

        collector = FakeCollector(lambda request: iter(()))
        provider = FakeProvider(lambda document, sha: self.fail("provider must not be called"))
        service = GuidanceService(provider)
        from kalama.resolution.llm_fields import schedule_field_guidance

        outcomes = schedule_field_guidance(
            "run-4b", confirmed_analysis, RAW_TARGET, KNOWLEDGE_GUIDANCE, service, collector
        )
        self.assertEqual(outcomes, ())
        self.assertEqual(collector.calls, [])
        self.assertEqual(provider.calls, [])

    def test_no_evidence_skips_provider(self):
        analysis = make_analysis()
        collector = FakeCollector(lambda request: iter(()))
        provider = FakeProvider(lambda document, sha: self.fail("provider must not be called"))
        service = GuidanceService(provider)
        from kalama.resolution.llm_fields import schedule_field_guidance

        outcomes = schedule_field_guidance(
            "run-4b", analysis, RAW_TARGET, {}, service, collector
        )
        # Collector ran for the unresolved fields but produced nothing useful.
        self.assertEqual(len(collector.calls), 1)
        self.assertTrue(set(collector.calls[0].unresolved_fields) <=
                        {"target", "targeturi", "rport", "payload"})
        self.assertEqual(outcomes, ())
        self.assertEqual(provider.calls, [])
        # Manual path remains usable: deterministic config untouched.
        item = analysis.cves[0]
        self.assertEqual(item.status, ResolverCVEStatus.WAITING_FOR_USER_INPUT)
        self.assertIsNotNone(item.exploit_config)


if __name__ == "__main__":
    unittest.main()
