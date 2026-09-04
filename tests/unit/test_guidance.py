import json
import unittest

from kalama.guidance.evidence import build_evidence_pack
from kalama.guidance.models import PROPOSAL_SCHEMA, ProposalValidationState
from kalama.guidance.ollama import OllamaConfig, OllamaProvider
from kalama.guidance.service import GuidanceService
from kalama.guidance.validator import validate_proposal
from kalama.resolution.models import RankedCVEInput
from kalama.resolution.resolver_stage import analyze_cves, target_facts_from_state
from tests.integration import test_step4_orchestrator as helpers


class GuidanceTests(unittest.TestCase):
    def setUp(self):
        payloads = [{"name": "cmd/unix/reverse_bash"}, {"name": "cmd/unix/generic"}]
        live = {"exploit/a": {"options": [
            {"name": "RPORT", "type": "port", "required": True, "default": 8080},
            {"name": "TARGETURI", "type": "path", "required": True, "default": "/demo/"}],
            "target_details": [{"index": 0, "name": "Universal"}],
            "default_target_index": 0, "status": "FOUND", "payloads": payloads,
            "check_supported": True}}
        facts = target_facts_from_state("aB3x9", {
            "container_id": "cid", "requested_image_reference": "victim:test",
            "network": "kalama-net", "ip_address": "172.18.0.3",
            "exposed_ports": [{"container_port": 8080}], "reachable_ports": [8080]})
        self.raw_target = {"container_id": "cid", "requested_image_reference": "victim:test",
            "network": "kalama-net", "ip_address": "172.18.0.3",
            "exposed_ports": [{"container_port": 8080}], "reachable_ports": [8080]}
        self.analysis = analyze_cves((RankedCVEInput(1, "CVE-2099-0001", ({"package": "x"},)),),
            facts, helpers.backend(candidates={"exploit/a": {"rank": "excellent",
            "check_supported": True}}, live=live), "msf")
        self.pack = build_evidence_pack("aB3x9", self.analysis.cves[0], self.raw_target)
        self.assertIsNotNone(self.pack)

    def proposal(self, proposals):
        return {"schema": PROPOSAL_SCHEMA, "status": "PROPOSED", "run_id": "aB3x9",
                "cve_id": "CVE-2099-0001", "evidence_pack_sha256": self.pack.sha256,
                "proposals": proposals, "missing_evidence": [], "guidance_notes": [],
                "reasoning_summary": "short"}

    def test_valid_payload_is_suggestion_only(self):
        state, accepted, issues = validate_proposal(self.pack, self.proposal({"payload": {
            "value": "cmd/unix/reverse_bash",
            "evidence_refs": ["metasploit.compatible_payload_subset"], "reason": "compatible"}}))
        self.assertEqual(state, ProposalValidationState.ACCEPTED_AS_SUGGESTION)
        self.assertEqual(accepted["payload"]["value"], "cmd/unix/reverse_bash")
        self.assertFalse(self.analysis.cves[0].exploit_config.invariant.payload.payload.confirmed)
        self.assertFalse(issues)

    def test_hallucinated_payload_module_port_reference_and_rhosts_are_rejected(self):
        cases = [
            {"payload": {"value": "cmd/not/real", "evidence_refs": ["metasploit.compatible_payload_subset"]}},
            {"module": {"value": "exploit/not/real", "evidence_refs": ["metasploit.candidate_modules"]}},
            {"rport": {"value": 80, "evidence_refs": ["resolver.rport"]}},
            {"payload": {"value": "cmd/unix/generic", "evidence_refs": ["imaginary.path"]}},
            {"rhosts": {"value": "127.0.0.1", "evidence_refs": ["target.ip_address"]}},
            {"oracle": {"value": "VERIFIED", "evidence_refs": ["target.ip_address"]}},
        ]
        for proposals in cases:
            with self.subTest(proposals=proposals):
                state, accepted, _ = validate_proposal(self.pack, self.proposal(proposals))
                self.assertEqual(state, ProposalValidationState.REJECTED)
                self.assertFalse(accepted)

    def test_executable_precondition_is_rejected(self):
        state, _, _ = validate_proposal(self.pack, self.proposal({"preconditions": {
            "value": "curl http://victim/", "evidence_refs": ["resolver.targeturi"]}}))
        self.assertEqual(state, ProposalValidationState.REJECTED)

    def test_invalid_json_timeout_and_unavailable_fall_back(self):
        provider = OllamaProvider(OllamaConfig(), transport=lambda _: b'{bad')
        outcomes = GuidanceService(provider).guide("aB3x9", self.analysis, self.raw_target)
        self.assertEqual(outcomes[0].provider_status, "UNAVAILABLE")
        disabled = GuidanceService(None).guide("aB3x9", self.analysis, self.raw_target)
        self.assertEqual(disabled[0].provider_status, "DISABLED")

    def test_ollama_parses_bounded_json_envelope(self):
        raw = self.proposal({})
        envelope = json.dumps({"message": {"content": json.dumps(raw)}}).encode()
        provider = OllamaProvider(OllamaConfig(model="fake"), transport=lambda _: envelope,
                                  monotonic=iter((1.0, 1.2)).__next__)
        proposal, elapsed = provider.propose(self.pack.document, self.pack.sha256)
        self.assertEqual(proposal["schema"], PROPOSAL_SCHEMA)
        self.assertAlmostEqual(elapsed, .2)

    def test_no_unresolved_fields_skips_provider(self):
        from dataclasses import replace
        from kalama.resolver.config_models import ConfigReadiness, ConfigValidationResult
        from kalama.resolution.models import ResolverCVEResult, Step4Analysis
        item = self.analysis.cves[0]
        ready = replace(item, validation=ConfigValidationResult(True,
                        ConfigReadiness.READY_TO_EXECUTE, ()))
        calls = []
        class Provider:
            name, config = "fake", type("C", (), {"model": "fake"})()
            def propose(self, *_): calls.append(1)
        outcomes = GuidanceService(Provider()).guide(
            "aB3x9", Step4Analysis((ready,)), self.raw_target)
        self.assertEqual(outcomes, ())
        self.assertEqual(calls, [])

    def test_no_module_status_skips_provider(self):
        from dataclasses import replace
        from kalama.resolution.models import ResolverCVEStatus, Step4Analysis
        calls = []
        class Provider:
            name, config = "fake", type("C", (), {"model": "fake"})()
            def propose(self, *_): calls.append(1)
        item = replace(self.analysis.cves[0], status=ResolverCVEStatus.NO_MSF_MODULE)
        self.assertEqual(GuidanceService(Provider()).guide(
            "aB3x9", Step4Analysis((item,)), self.raw_target), ())
        self.assertEqual(calls, [])


if __name__ == "__main__": unittest.main()
