from __future__ import annotations

from typing import Any, Mapping, Protocol

from ..resolution.models import ResolverCVEResult, Step4Analysis
from .evidence import build_evidence_pack
from .models import EvidencePack, GuidanceOutcome, ProposalValidationState
from .validator import validate_proposal
from .patch_proposal import (
    PATCH_ELIGIBLE_SET as PATCH_ELIGIBLE_FIELDS,
    PatchGuidanceOutcome,
    build_patch_envelope,
    validate_patch_proposal,
)

# Task 4B locked LLM-eligible Attack fields.  Guidance must never be
# authorized beyond this set.
LLM_ELIGIBLE_FIELDS = frozenset({"target", "targeturi", "rport", "payload"})


class GuidanceProvider(Protocol):
    name: str
    config: Any
    def propose(self, evidence: Mapping[str, Any], evidence_sha256: str): ...


class GuidanceService:
    def __init__(self, provider: GuidanceProvider | None, *, cve_ids: frozenset[str] | None = None):
        self.provider, self.cve_ids = provider, cve_ids

    def guide(self, run_id: str, analysis: Step4Analysis,
              target: Mapping[str, Any]) -> tuple[GuidanceOutcome, ...]:
        outcomes = []
        for item in analysis.cves:
            if self.cve_ids is not None and item.input.cve_id not in self.cve_ids:
                continue
            pack = build_evidence_pack(run_id, item, target)
            if pack is None: continue
            if self.provider is None:
                outcomes.append(GuidanceOutcome(item.input.cve_id, pack, "DISABLED"))
                continue
            try:
                proposal, elapsed = self.provider.propose(pack.document, pack.sha256)
                state, accepted, issues = validate_proposal(pack, proposal)
                outcomes.append(GuidanceOutcome(
                    item.input.cve_id, pack, "AVAILABLE", self.provider.name,
                    getattr(self.provider.config, "model", None), elapsed, proposal,
                    state, accepted, issues))
            except Exception as exc:
                outcomes.append(GuidanceOutcome(
                    item.input.cve_id, pack, "UNAVAILABLE", self.provider.name,
                    getattr(self.provider.config, "model", None), issues=(
                        f"{type(exc).__name__}: {str(exc)[:500]}",)))
        return tuple(outcomes)

    def guide_with_field_pack(
        self,
        run_id: str,
        item: ResolverCVEResult,
        target: Mapping[str, Any],
        *,
        field_pack: Any,
        allowed_fields: frozenset[str] | set[str] | tuple[str, ...] | list[str],
    ) -> GuidanceOutcome | None:
        """Field-level LLM call consuming an already-collected EvidencePack.

        ``field_pack`` is the exact Task 2/3 ``EvidenceCollector`` pack for
        this candidate.  It is embedded into the evidence document handed to
        the provider, and its provenance/snapshot references are merged into
        the validation reference set, so the collected pack is the pack the
        provider path actually consumes.  ``allowed_fields`` becomes the
        exact model authority (a subset of the four eligible fields).

        Compatibility review (Task 4C): the legacy guidance pack built here
        is only the provider/schema envelope.  It supplies the shapes the
        existing validator needs (``allowed_proposal_fields`` slot, the
        Metasploit value allow-lists, target-port support) and carries no
        independent field evidence of its own: ``allowed_proposal_fields``
        is overwritten (never merged) with the exact unresolved set, and the
        Task 1-3 pack is embedded verbatim plus bound by
        ``field_evidence_sha256`` and ``candidate_digest``.  There is no
        conflicting evidence authority: any proposal must echo both digests
        and cite only references from the merged set, otherwise the
        deterministic validator rejects it.  The Task 1-3 EvidencePack is
        authoritative for field evidence.
        """
        if self.cve_ids is not None and item.input.cve_id not in self.cve_ids:
            return None
        legacy = build_evidence_pack(run_id, item, target)
        if legacy is None:
            return None
        allowed = sorted(set(allowed_fields) & LLM_ELIGIBLE_FIELDS)
        if not allowed:
            return None
        try:
            field_dict = field_pack.to_dict()
            field_sha = field_pack.sha256
            candidate_context = field_pack.request.context.provenance_dict()
            candidate_digest = field_pack.request.context.digest
        except Exception:
            return None
        document = dict(legacy.document)
        document["allowed_proposal_fields"] = allowed
        document["field_evidence_pack"] = field_dict
        document["field_evidence_sha256"] = field_sha
        document["candidate_context"] = candidate_context
        document["candidate_digest"] = candidate_digest
        references = set(legacy.references)
        try:
            for ref in getattr(field_pack, "snapshot_refs", ()):
                if isinstance(ref, str) and ref:
                    references.add(ref)
            for evidence_item in getattr(field_pack, "items", ()):
                provenance = getattr(evidence_item, "provenance_ref", None)
                if isinstance(provenance, str) and provenance:
                    references.add(provenance)
                snapshot = getattr(evidence_item, "snapshot_sha256", None)
                if isinstance(snapshot, str) and snapshot:
                    references.add(snapshot)
                kind = getattr(evidence_item, "source_kind", None)
                kind_value = getattr(kind, "value", kind)
                if isinstance(kind_value, str) and kind_value:
                    references.add(f"field_evidence.{kind_value}")
        except Exception:
            pass
        enriched = EvidencePack(
            legacy.run_id,
            legacy.cve_id,
            document,
            frozenset(references),
            legacy.full_compatible_payloads,
            legacy.full_module_options,
            legacy.full_payload_options,
        )
        if self.provider is None:
            return GuidanceOutcome(
                item.input.cve_id, enriched, "DISABLED",
                field_evidence_pack=field_pack,
            )
        try:
            proposal, elapsed = self.provider.propose(enriched.document, enriched.sha256)
            state, accepted, issues = validate_proposal(enriched, proposal)
            return GuidanceOutcome(
                item.input.cve_id, enriched, "AVAILABLE", self.provider.name,
                getattr(self.provider.config, "model", None), elapsed, proposal,
                state, accepted, issues, field_evidence_pack=field_pack)
        except Exception as exc:
            return GuidanceOutcome(
                item.input.cve_id, enriched, "UNAVAILABLE", self.provider.name,
                getattr(self.provider.config, "model", None),
                issues=(f"{type(exc).__name__}: {str(exc)[:500]}",),
                field_evidence_pack=field_pack)

    def guide_with_patch_pack(
        self,
        run_id: str,
        action: Any,
        target: Mapping[str, Any],
        *,
        field_pack: Any,
        allowed_fields: frozenset[str] | set[str] | tuple[str, ...] | list[str],
        plan_revision: int | None = None,
        base_patch_plan_sha256: str | None = None,
    ) -> PatchGuidanceOutcome | None:
        """Patch field-level LLM call consuming a REMEDIATION EvidencePack.

        Task 6 MVP: ``allowed_fields`` must be a subset of the seven locked
        Patch fields.  The Task 1-3 EvidencePack is authoritative for field
        evidence; the proposal must echo the candidate digest, the pack SHA,
        and the exact action/plan binding or the Patch validator rejects it.
        Accepted suggestions are returned for SUGGESTED/display projection
        only -- this method never confirms, submits, or executes anything.
        """
        try:
            target_cves = tuple(getattr(action, "target_cves", ()) or ())
            action_id = str(action.action_id)
            package_key = str(action.package_key)
        except Exception:
            return None
        if self.cve_ids is not None and not (set(target_cves) & set(self.cve_ids)):
            return None
        cve_id = str(target_cves[0]) if target_cves else ""
        if not cve_id:
            return None
        allowed = sorted(set(allowed_fields) & PATCH_ELIGIBLE_FIELDS)
        if not allowed:
            return None
        try:
            candidate_digest = field_pack.request.context.digest
            candidate_context = field_pack.request.context.provenance_dict()
            resolved_fields = dict(getattr(field_pack.request, "resolved_fields", {}) or {})
        except Exception:
            return None
        try:
            envelope = build_patch_envelope(
                run_id=run_id,
                cve_id=cve_id,
                action_id=action_id,
                package_key=package_key,
                candidate_digest=candidate_digest,
                candidate_context=candidate_context,
                field_pack=field_pack,
                allowed_fields=allowed,
                resolved_fields=resolved_fields,
                target_cves=target_cves,
                plan_revision=plan_revision,
                base_patch_plan_sha256=base_patch_plan_sha256,
            )
        except Exception:
            return None
        if self.provider is None:
            return PatchGuidanceOutcome(
                action_id, cve_id, envelope, "DISABLED",
                field_evidence_pack=field_pack)
        try:
            # Prefer a patch-shaped provider call so the model is constrained
            # to the Patch contract; fall back to the generic call for
            # providers that only implement the Attack-shaped protocol.
            propose = getattr(self.provider, "propose_patch", None) or self.provider.propose
            proposal, elapsed = propose(envelope.document, envelope.sha256)
            state, accepted, issues = validate_patch_proposal(envelope, proposal)
            return PatchGuidanceOutcome(
                action_id, cve_id, envelope, "AVAILABLE", self.provider.name,
                getattr(self.provider.config, "model", None), elapsed, proposal,
                state, accepted, issues, field_evidence_pack=field_pack)
        except Exception as exc:
            return PatchGuidanceOutcome(
                action_id, cve_id, envelope, "UNAVAILABLE", self.provider.name,
                getattr(self.provider.config, "model", None),
                issues=(f"{type(exc).__name__}: {str(exc)[:500]}",),
                field_evidence_pack=field_pack)
