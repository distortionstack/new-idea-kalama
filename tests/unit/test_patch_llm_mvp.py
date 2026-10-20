"""Task 6 deterministic tests: Patch LLM assistance MVP.

No network, Docker, Ollama, or live MSF.  Fake collectors/providers
exercise the real production scheduling/validation/form projection.
"""

import unittest

from kalama.evidence import (
    Collection,
    EvidenceItem,
    EvidencePack as FieldEvidencePack,
    EvidencePurpose,
    EvidenceResult,
    EvidenceResultState,
    SourceKind,
)
from kalama.evidence.policy import EvidenceSourceConfig, SourcePolicy
from kalama.guidance.models import ProposalValidationState
from kalama.guidance.patch_proposal import (
    PATCH_LLM_ELIGIBLE_FIELDS,
    PATCH_PROPOSAL_SCHEMA,
    build_patch_envelope,
    validate_patch_proposal,
)
from kalama.guidance.service import GuidanceService
from kalama.remediation.models import (
    FixType,
    PatchAction,
    PatchPlan,
    PatchStrategy,
    PlanningReason,
    PlanningStatus,
    RemediationCandidate,
)
from kalama.remediation.orchestrator import PatchPlanningOrchestrator
from kalama.remediation.patch_llm import (
    build_patch_candidate_context,
    build_patch_field_request,
    effective_fields,
    project_patch_guidance,
    schedule_patch_guidance,
)

RUN = "run-t6"
CVE = "CVE-2024-0001"
OCC = {
    "canonical_cve_id": CVE,
    "package_name": "libssl",
    "package_purl": "pkg:deb/debian/libssl@1.1.1",
    "installed_version": "1.1.1",
    "fixed_versions": ["1.1.1t"],
    "result_type": "debian",
}
TARGET_FACTS = {
    "container_id": "cid-t6",
    "requested_image_reference": "debian:11",
    "network": "kalama-net",
    "ip_address": "172.18.0.9",
}


def make_action(action_id="patch-001", cve=CVE,
                package_key="pkg:deb/debian/libssl@1.1.1",
                before=("1.1.1",), fixed=("1.1.1t",),
                fix_type=None, strategy=None, candidate=None,
                reasons=(PlanningReason.TARGET_VERSION_UNRESOLVED,)):
    occ = dict(OCC)
    if candidate is None:
        candidate = RemediationCandidate()
    return PatchAction(
        action_id, (cve,), (), package_key, "libssl", "debian",
        (occ,), before, fixed, fix_type, strategy, candidate,
        PlanningStatus.WAITING_FOR_USER_INPUT, reasons)


def full_candidate():
    return RemediationCandidate(
        target_version="1.1.1t", fix_type=FixType.C,
        strategy=PatchStrategy.PACKAGE_MANAGER,
        source_url="https://deb.debian.org/libssl",
        source_identifier="libssl", build_system="maven",
        trusted=False, source_authority="remediation_discovery")


class FakeCollector:
    def __init__(self, items_factory):
        self.calls = []
        self._factory = items_factory

    def collect(self, request):
        self.calls.append(request)
        items = tuple(self._factory(request))
        pack = FieldEvidencePack(request, items)
        if items:
            return Collection(
                pack, (EvidenceResult(
                    EvidenceResultState.AVAILABLE, items[0].source_kind, items),))
        return Collection(
            pack, (EvidenceResult(EvidenceResultState.NOT_APPLICABLE, SourceKind.RUNTIME),))


class FakeProvider:
    name = "fake-patch-llm"

    def __init__(self, proposals_factory):
        self.calls = []
        self.config = type("C", (), {"model": "fake"})()
        self._factory = proposals_factory

    def propose(self, document, sha256):
        self.calls.append((document, sha256))
        return self._factory(document, sha256), 0.01


def valid_proposal(document, sha, proposals):
    return {
        "schema": PATCH_PROPOSAL_SCHEMA,
        "status": "PROPOSED",
        "run_id": document["run_id"],
        "cve_id": document["cve_id"],
        "action_id": document["action_id"],
        "candidate_digest": document["candidate_digest"],
        "field_evidence_sha256": document["field_evidence_sha256"],
        "patch_binding": dict(document["patch_binding"]),
        "proposals": proposals,
        "missing_evidence": [],
        "guidance_notes": [],
        "reasoning_summary": "test",
    }


def evidence_items(request, fields, ref="fake:1", kind=SourceKind.KNOWLEDGE):
    yield EvidenceItem(
        request.context, kind, "kalama-test", "test:resource",
        dict(fields), provenance_ref=ref)


class EligibleFieldsTests(unittest.TestCase):
    def test_eligible_fields_are_locked(self):
        self.assertEqual(tuple(sorted(PATCH_LLM_ELIGIBLE_FIELDS)), (
            "artifact_source", "build_system", "fix_type", "notes",
            "source_identifier", "strategy", "target_version"))
        for forbidden in ("command", "validation_command", "replacement_target",
                          "checksum", "trusted", "source_authority", "source_type",
                          "human_confirmed_fields", "major_version_approved",
                          "execution_target", "disposition", "readiness",
                          "remediation_verified"):
            self.assertNotIn(forbidden, PATCH_LLM_ELIGIBLE_FIELDS)


class SchedulingTests(unittest.TestCase):
    def test_partial_resolution_only_unresolved_requested(self):
        action = make_action(fix_type=FixType.C)
        knowledge = {"patch-001": {"fields": {"target_version": "1.1.1t"}}}
        resolved, unresolved = effective_fields(action, knowledge["patch-001"])
        self.assertEqual(resolved.get("fix_type"), "C")
        self.assertEqual(resolved.get("target_version"), "1.1.1t")
        self.assertEqual(set(unresolved), {
            "strategy", "artifact_source", "source_identifier", "build_system"})

        collector = FakeCollector(
            lambda req: evidence_items(req, {"strategy": "PACKAGE_MANAGER"}))
        provider = FakeProvider(
            lambda doc, sha: valid_proposal(doc, sha, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "vendor doc"},
                "artifact_source": {"value": "https://deb.debian.org/libssl",
                                    "evidence_refs": ["fake:1"], "reason": "repo"},
            }))
        service = GuidanceService(provider)
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            knowledge_by_action=knowledge,
            guidance_service=service, collector_or_factory=collector)
        self.assertEqual(len(collector.calls), 1)
        request = collector.calls[0]
        self.assertEqual(request.purpose, EvidencePurpose.REMEDIATION)
        self.assertEqual(set(request.unresolved_fields), set(unresolved))
        self.assertNotIn("fix_type", set(request.unresolved_fields))
        self.assertNotIn("target_version", set(request.unresolved_fields))
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        self.assertEqual(outcome.validation_state,
                         ProposalValidationState.ACCEPTED_AS_SUGGESTION)
        self.assertLessEqual(set(outcome.accepted),
                             {"strategy", "artifact_source"})
        # Deterministic/Knowledge values untouched by the call.
        self.assertEqual(action.fix_type, FixType.C)
        self.assertIsNone(action.strategy)

    def test_fully_resolved_short_circuit(self):
        action = make_action(fix_type=FixType.C,
                             strategy=PatchStrategy.PACKAGE_MANAGER,
                             candidate=full_candidate(),
                             reasons=())
        resolved, unresolved = effective_fields(action, None)
        self.assertEqual(unresolved, ())
        collector = FakeCollector(lambda req: self.fail("collector must not run"))
        provider = FakeProvider(
            lambda doc, sha: self.fail("provider must not be called"))
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            guidance_service=GuidanceService(provider),
            collector_or_factory=collector)
        self.assertEqual(outcomes, ())
        self.assertEqual(collector.calls, [])
        self.assertEqual(provider.calls, [])

    def test_no_evidence_skips_provider(self):
        action = make_action()
        collector = FakeCollector(lambda req: iter(()))
        provider = FakeProvider(
            lambda doc, sha: self.fail("provider must not be called"))
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            guidance_service=GuidanceService(provider),
            collector_or_factory=collector)
        self.assertEqual(len(collector.calls), 1)
        self.assertEqual(outcomes, ())
        self.assertEqual(provider.calls, [])
        self.assertEqual(action.status, PlanningStatus.WAITING_FOR_USER_INPUT)

    def test_provider_failure_and_malformed_proposal_nonfatal(self):
        action = make_action()

        class Boom:
            name = "boom"
            config = type("C", (), {"model": "boom"})()

            def propose(self, document, sha):
                raise RuntimeError("llm down")

        collector = FakeCollector(
            lambda req: evidence_items(req, {"strategy": "PACKAGE_MANAGER"}))
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            guidance_service=GuidanceService(Boom()),
            collector_or_factory=collector)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].provider_status, "UNAVAILABLE")
        self.assertEqual(outcomes[0].accepted, {})

        malformed = FakeProvider(
            lambda doc, sha: {"schema": PATCH_PROPOSAL_SCHEMA,
                              "status": "PROPOSED"})  # missing bindings/proposals
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            guidance_service=GuidanceService(malformed),
            collector_or_factory=collector)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].validation_state,
                         ProposalValidationState.REJECTED)
        # Deterministic values remain; plan still waiting.
        self.assertIsNone(action.strategy)
        self.assertEqual(action.status, PlanningStatus.WAITING_FOR_USER_INPUT)

    def test_no_knowledge_write(self):
        class CountingStore:
            def __init__(self):
                self.upserts = 0

            def candidates(self, *args, **kwargs):
                return []

            def upsert(self, record):
                self.upserts += 1
                return record

        store = CountingStore()
        action = make_action()
        collector = FakeCollector(
            lambda req: evidence_items(req, {"strategy": "PACKAGE_MANAGER"}))
        provider = FakeProvider(
            lambda doc, sha: valid_proposal(doc, sha, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"}}))
        schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            knowledge_store=store,
            guidance_service=GuidanceService(provider),
            collector_or_factory=collector)
        self.assertEqual(store.upserts, 0)

    def test_isolation_same_cve(self):
        action_a = make_action("patch-001")
        action_b = make_action(
            "patch-002", package_key="pkg:deb/debian/openssl@1.1.1",
            before=("3.0.1",), fixed=("3.0.9",))
        collector = FakeCollector(
            lambda req: evidence_items(req, {"strategy": "PACKAGE_MANAGER"}))
        provider = FakeProvider(
            lambda doc, sha: valid_proposal(doc, sha, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"}}))
        service = GuidanceService(provider)
        outcomes = schedule_patch_guidance(
            RUN, (action_a, action_b), target_facts=TARGET_FACTS,
            guidance_service=service, collector_or_factory=collector)
        self.assertEqual(len(outcomes), 2)
        digests = {o.action_id: o.envelope.document["candidate_digest"]
                   for o in outcomes}
        self.assertNotEqual(digests["patch-001"], digests["patch-002"])
        # A proposal bound to action A must not validate for action B.
        raw = dict(provider.calls[0][0])
        envelope_b = outcomes[1].envelope
        stolen = valid_proposal(
            outcomes[0].envelope.document, outcomes[0].envelope.sha256, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope_b, stolen)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        self.assertEqual(accepted, {})
        _ = raw


class ValidatorTests(unittest.TestCase):
    def _envelope(self, action=None, allowed=("strategy", "target_version",
                                             "fix_type", "artifact_source",
                                             "source_identifier", "build_system",
                                             "notes")):
        action = action or make_action()
        context = build_patch_candidate_context(RUN, action, (), TARGET_FACTS)
        request = build_patch_field_request(context, {}, allowed)
        pack = FieldEvidencePack(
            request, tuple(evidence_items(
                request, {"strategy": "PACKAGE_MANAGER"}, ref="fake:1")))
        return build_patch_envelope(
            run_id=RUN, cve_id=CVE, action_id=action.action_id,
            package_key=action.package_key,
            candidate_digest=context.digest,
            candidate_context=context.provenance_dict(),
            field_pack=pack, allowed_fields=allowed,
            plan_revision=1, base_patch_plan_sha256="b" * 64)

    def test_binding_mismatch_rejected(self):
        envelope = self._envelope()
        doc = envelope.document
        for mutate in ("candidate_digest", "field_evidence_sha256"):
            raw = valid_proposal(doc, envelope.sha256, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"}})
            raw[mutate] = "0" * 64
            state, accepted, _ = validate_patch_proposal(envelope, raw)
            self.assertEqual(state, ProposalValidationState.REJECTED)
            self.assertEqual(accepted, {})
        raw = valid_proposal(doc, envelope.sha256, {
            "strategy": {"value": "PACKAGE_MANAGER",
                         "evidence_refs": ["fake:1"], "reason": "x"}})
        raw["action_id"] = "patch-999"
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        raw = valid_proposal(doc, envelope.sha256, {
            "strategy": {"value": "PACKAGE_MANAGER",
                         "evidence_refs": ["fake:1"], "reason": "x"}})
        raw["patch_binding"] = {**raw["patch_binding"], "plan_revision": 2}
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        self.assertEqual(accepted, {})

    def test_fabricated_refs_rejected(self):
        envelope = self._envelope()
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "strategy": {"value": "PACKAGE_MANAGER",
                         "evidence_refs": ["https://evil.example/x"],
                         "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        self.assertEqual(accepted, {})

    def test_forbidden_fields_rejected(self):
        envelope = self._envelope()
        for forbidden in ("command", "validation_command", "replacement_target",
                          "checksum", "trusted", "readiness",
                          "human_confirmed_fields"):
            raw = valid_proposal(envelope.document, envelope.sha256, {
                forbidden: {"value": "x", "evidence_refs": ["fake:1"],
                            "reason": "x"}})
            state, accepted, _ = validate_patch_proposal(envelope, raw)
            self.assertEqual(state, ProposalValidationState.REJECTED, forbidden)
            self.assertEqual(accepted, {}, forbidden)

    def test_invalid_fix_type_and_strategy_rejected(self):
        envelope = self._envelope()
        for bad in ("D", "X", "", None, 42):
            raw = valid_proposal(envelope.document, envelope.sha256, {
                "fix_type": {"value": bad, "evidence_refs": ["fake:1"],
                             "reason": "x"}})
            state, accepted, _ = validate_patch_proposal(envelope, raw)
            self.assertEqual(state, ProposalValidationState.REJECTED)
            self.assertEqual(accepted, {})
        for bad in ("REBOOT", "", None):
            raw = valid_proposal(envelope.document, envelope.sha256, {
                "strategy": {"value": bad, "evidence_refs": ["fake:1"],
                             "reason": "x"}})
            state, accepted, _ = validate_patch_proposal(envelope, raw)
            self.assertEqual(state, ProposalValidationState.REJECTED)
            self.assertEqual(accepted, {})

    def test_invalid_pairing_rejected_valid_pairing_accepted(self):
        envelope = self._envelope()
        for fix, strat in (("C", "REBUILD"), ("C", "PREBUILT_IMAGE_REPLACEMENT"),
                           ("A", "PACKAGE_MANAGER"), ("B", "REBUILD")):
            raw = valid_proposal(envelope.document, envelope.sha256, {
                "fix_type": {"value": fix, "evidence_refs": ["fake:1"],
                             "reason": "x"},
                "strategy": {"value": strat, "evidence_refs": ["fake:1"],
                             "reason": "x"}})
            state, accepted, _ = validate_patch_proposal(envelope, raw)
            self.assertNotIn("strategy", accepted, f"{fix}+{strat}")
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "fix_type": {"value": "C", "evidence_refs": ["fake:1"],
                         "reason": "x"},
            "strategy": {"value": "PACKAGE_MANAGER",
                         "evidence_refs": ["fake:1"], "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.ACCEPTED_AS_SUGGESTION)
        self.assertEqual(set(accepted), {"fix_type", "strategy"})

    def test_target_version_major_jump_rejected(self):
        envelope = self._envelope()
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "target_version": {"value": "3.0.9", "evidence_refs": ["fake:1"],
                               "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "target_version": {"value": "1.1.1t", "evidence_refs": ["fake:1"],
                               "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertIn("target_version", accepted)

    def test_trust_fields_rejected(self):
        envelope = self._envelope()
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "strategy": {"value": "PACKAGE_MANAGER",
                         "evidence_refs": ["fake:1"], "reason": "x"}})
        raw["trusted"] = True
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertEqual(state, ProposalValidationState.REJECTED)
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "artifact_source": {"value": "https://x.example",
                                "evidence_refs": ["fake:1"], "reason": "x"}})
        state, accepted, issues = validate_patch_proposal(envelope, raw)
        self.assertIn("artifact_source", accepted)
        # Acceptance is suggestion-only: no trust promotion keys exist.
        self.assertNotIn("trusted", accepted["artifact_source"])
        self.assertNotIn("source_authority", accepted["artifact_source"])

    def test_evidence_required_and_notes_adjunct(self):
        envelope = self._envelope()
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "strategy": {"value": "PACKAGE_MANAGER", "evidence_refs": [],
                         "reason": "memory"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertNotIn("strategy", accepted)
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "notes": {"value": "Scanner reports 1.1.1t fixed branch.",
                      "evidence_refs": [], "reason": "summary"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertIn("notes", accepted)

    def test_build_system_vocabulary_bounded(self):
        envelope = self._envelope()
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "build_system": {"value": "maven", "evidence_refs": ["fake:1"],
                             "reason": "pom"}})
        _, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertIn("build_system", accepted)
        raw = valid_proposal(envelope.document, envelope.sha256, {
            "build_system": {"value": "ninja", "evidence_refs": ["fake:1"],
                             "reason": "x"}})
        state, accepted, _ = validate_patch_proposal(envelope, raw)
        self.assertNotIn("build_system", accepted)
        self.assertEqual(state, ProposalValidationState.REJECTED)


class ProjectionTests(unittest.TestCase):
    def test_projection_suggested_only_form_unconfirmed(self):
        action = make_action()
        plan = PatchPlan(RUN, (action,), PlanningStatus.WAITING_FOR_USER_INPUT)
        form = PatchPlanningOrchestrator._form(plan, RUN, "p" * 64)
        collector = FakeCollector(
            lambda req: evidence_items(req, {"strategy": "PACKAGE_MANAGER"}))
        provider = FakeProvider(
            lambda doc, sha: valid_proposal(doc, sha, {
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"},
                "target_version": {"value": "1.1.1t",
                                   "evidence_refs": ["fake:1"], "reason": "x"},
                "notes": {"value": "Same-branch fixed version.",
                          "evidence_refs": [], "reason": "summary"}}))
        outcomes = schedule_patch_guidance(
            RUN, (action,), target_facts=TARGET_FACTS,
            guidance_service=GuidanceService(provider),
            collector_or_factory=collector,
            base_patch_plan_sha256="p" * 64)
        self.assertEqual(len(outcomes), 1)
        updated, guidance = project_patch_guidance(form, outcomes)
        slot = updated["actions"]["patch-001"]
        self.assertEqual(slot["strategy"]["suggested"], "PACKAGE_MANAGER")
        self.assertEqual(slot["target_version"]["suggested"], "1.1.1t")
        # Human gate: nothing confirmed.
        self.assertIsNone(slot["strategy"]["confirmed"])
        self.assertIsNone(slot["target_version"]["confirmed"])
        self.assertIsNone(slot["command"]["confirmed"])
        self.assertIsNone(slot["validation_command"]["confirmed"])
        self.assertIsNone(slot.get("major_version_approved"))
        self.assertNotIn("human_confirmed_fields", slot)
        self.assertNotIn("trusted", slot)
        # Deterministic/manual form untouched: no execution keys invented.
        self.assertNotIn("execution", slot)
        self.assertEqual(slot["execution_target"], "patch-workspace")
        # Original form object unmodified.
        self.assertIsNone(form["actions"]["patch-001"]["strategy"]["suggested"])
        # Sidecar carries audit; source_identifier/build_system/notes have no
        # confirmed slots to abuse.
        self.assertEqual(guidance["schema"], "kalama.patch-llm-guidance/v1")
        self.assertEqual(len(guidance["actions"]), 1)
        entry = guidance["actions"][0]
        self.assertEqual(entry["action_id"], "patch-001")
        self.assertEqual(entry["patch_binding"]["base_patch_plan_sha256"], "p" * 64)
        self.assertIn("strategy", entry["accepted_suggestions"])

    def test_deterministic_suggested_never_overwritten(self):
        action = make_action(fix_type=FixType.C,
                             strategy=PatchStrategy.PACKAGE_MANAGER)
        plan = PatchPlan(RUN, (action,), PlanningStatus.WAITING_FOR_USER_INPUT)
        form = PatchPlanningOrchestrator._form(plan, RUN, "p" * 64)
        self.assertEqual(form["actions"]["patch-001"]["fix_type"]["suggested"], "C")
        context = build_patch_candidate_context(RUN, action, (), TARGET_FACTS)
        request = build_patch_field_request(
            context, {"fix_type": "C"}, ("strategy",))
        pack = FieldEvidencePack(
            request, tuple(evidence_items(
                request, {"strategy": "x"}, ref="fake:1")))
        from kalama.guidance.service import GuidanceService as GS
        service = GS(FakeProvider(
            lambda doc, sha: valid_proposal(doc, sha, {
                "fix_type": {"value": "B", "evidence_refs": ["fake:1"],
                             "reason": "rogue"},
                "strategy": {"value": "PACKAGE_MANAGER",
                             "evidence_refs": ["fake:1"], "reason": "x"}})))
        outcome = service.guide_with_patch_pack(
            RUN, action, TARGET_FACTS, field_pack=pack,
            allowed_fields=frozenset({"strategy"}))
        # fix_type was already resolved: validator must refuse it.
        self.assertNotIn("fix_type", outcome.accepted)
        updated, _ = project_patch_guidance(form, (outcome,))
        self.assertEqual(
            updated["actions"]["patch-001"]["fix_type"]["suggested"], "C")

    def test_no_execution_state(self):
        action = make_action()
        self.assertFalse(action.execution or {})
        self.assertEqual(action.status, PlanningStatus.WAITING_FOR_USER_INPUT)
        # Projection and scheduling never produce execution material.
        plan = PatchPlan(RUN, (action,), PlanningStatus.WAITING_FOR_USER_INPUT)
        form = PatchPlanningOrchestrator._form(plan, RUN, "p" * 64)
        updated, _ = project_patch_guidance(form, ())
        self.assertEqual(updated["actions"]["patch-001"]["command"],
                         {"confirmed": None})


class PolicyTests(unittest.TestCase):
    def test_patch_field_authority(self):
        from kalama.remediation.patch_llm import build_patch_candidate_context as ctx
        action = make_action()
        context = ctx(RUN, action, (), TARGET_FACTS)
        policy = SourcePolicy(EvidenceSourceConfig())
        target_order = policy.ordered_sources(
            build_patch_field_request(context, {}, ("target_version",)),
            "target_version")
        self.assertEqual(target_order[0], SourceKind.KNOWLEDGE)
        build_order = policy.ordered_sources(
            build_patch_field_request(context, {}, ("build_system",)),
            "build_system")
        self.assertEqual(build_order[0], SourceKind.RUNTIME)
        fix_order = policy.ordered_sources(
            build_patch_field_request(context, {}, ("fix_type",)),
            "fix_type")
        self.assertEqual(fix_order[0], SourceKind.RUNTIME)
        # Disabled-by-default sources stay out without network enablement.
        self.assertNotIn(SourceKind.NVD, target_order)
        self.assertNotIn(SourceKind.VENDOR_UPSTREAM, target_order)


if __name__ == "__main__":
    unittest.main()
