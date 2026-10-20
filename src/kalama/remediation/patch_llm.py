"""Task 6 field-level Patch LLM scheduling.

Production path::

    deterministic remediation discovery + compatible VALIDATED Knowledge
    -> resolved eligible fields -> unresolved eligible fields
    -> CandidateContext -> FieldRequest(purpose=REMEDIATION)
    -> EvidenceCollector -> EvidencePack -> Patch Guidance
    -> Patch validator -> Patch Form suggested/guidance
    -> PAUSE for human submission.

Only the seven locked MVP fields are LLM eligible: ``fix_type``,
``strategy``, ``target_version``, ``artifact_source``,
``source_identifier``, ``build_system`` and ``notes``.  Of these, only
the six substantive fields drive evidence collection; ``notes`` is an
inert display-only adjunct that never triggers a provider call on its
own and never affects readiness or execution.  Nothing here confirms a
field, submits a form, writes Knowledge, or executes a patch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from ..evidence import (
    CandidateContext,
    EvidencePurpose,
    FieldRequest,
    SourceKind,
)
from ..evidence.policy import EvidenceSourceConfig
from ..guidance.patch_proposal import (
    PATCH_LLM_ELIGIBLE_FIELDS,
    PATCH_LLM_GUIDANCE_SCHEMA,
    PatchGuidanceOutcome,
)
from ..knowledge import retrieve_compatible
from .models import PatchAction, PlanningStatus


# Re-export for callers/tests.
PATCH_ELIGIBLE_FIELDS = PATCH_LLM_ELIGIBLE_FIELDS
_SUBSTANTIVE_FIELDS = tuple(f for f in PATCH_LLM_ELIGIBLE_FIELDS if f != "notes")
_SUBSTANTIVE_SET = frozenset(_SUBSTANTIVE_FIELDS)
_ELIGIBLE_SET = frozenset(PATCH_LLM_ELIGIBLE_FIELDS)


def deterministic_resolved(action: PatchAction) -> dict[str, Any]:
    """Effective deterministic values for the eligible Patch fields.

    A field counts as resolved only when the existing PatchAction /
    RemediationCandidate already carries it (deterministic discovery or
    compatible VALIDATED Knowledge merged by KnowledgeRemediationProvider).
    Evidence presence alone never counts as resolved.
    """
    resolved: dict[str, Any] = {}
    candidate = action.candidate
    if action.fix_type is not None:
        resolved["fix_type"] = action.fix_type.value
    if action.strategy is not None:
        resolved["strategy"] = action.strategy.value
    if candidate is not None:
        if candidate.target_version:
            resolved["target_version"] = candidate.target_version
        if candidate.source_url:
            resolved["artifact_source"] = candidate.source_url
        if candidate.source_identifier:
            resolved["source_identifier"] = candidate.source_identifier
        if candidate.build_system:
            resolved["build_system"] = candidate.build_system
    return {k: v for k, v in resolved.items() if k in _SUBSTANTIVE_SET}


def knowledge_resolved(knowledge_entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatible VALIDATED Knowledge values for eligible fields only."""
    if not isinstance(knowledge_entry, Mapping):
        return {}
    # Shape 1: Attack-style accepted suggestions (accepted by the shared
    # KnowledgeEvidenceSource path).
    accepted = knowledge_entry.get("accepted_suggestions")
    source: Mapping[str, Any] = accepted if isinstance(accepted, Mapping) else (
        knowledge_entry.get("fields") if isinstance(knowledge_entry.get("fields"), Mapping)
        else knowledge_entry)
    resolved: dict[str, Any] = {}
    get = source.get
    flat = {
        "fix_type": get("fix_type"),
        "strategy": get("strategy"),
        "target_version": get("target_version"),
        "artifact_source": get("artifact_source", get("source_url")),
        "source_identifier": get("source_identifier"),
        "build_system": get("build_system"),
    }
    for field, proposal in flat.items():
        if field not in _SUBSTANTIVE_SET:
            continue
        if isinstance(proposal, Mapping) and "value" in proposal:
            proposal = proposal.get("value")
        if isinstance(proposal, str):
            if not proposal.strip():
                continue
            resolved[field] = proposal
    return resolved


def effective_fields(
    action: PatchAction, knowledge_entry: Mapping[str, Any] | None
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Merge deterministic facts with compatible VALIDATED Knowledge.

    Deterministic values win; Knowledge only fills fields that remain
    unresolved.  Returns ``(resolved, unresolved)`` where ``unresolved``
    is exactly the substantive eligible subset still needing help.
    ``notes`` never drives scheduling.
    """
    resolved = deterministic_resolved(action)
    for field, value in knowledge_resolved(knowledge_entry).items():
        if field not in resolved:
            resolved[field] = value
    unresolved = tuple(sorted(k for k in _SUBSTANTIVE_SET if k not in resolved))
    return resolved, unresolved


def _first_occurrence(action: PatchAction,
                      occurrences: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    pool = list(occurrences) or list(action.occurrences or ())
    for item in pool:
        if isinstance(item, Mapping):
            return item
    return None


def retrieve_patch_knowledge(store: Any, action: PatchAction,
                             occurrence: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """Fetch the first compatible VALIDATED remediation record for an action."""
    if store is None or not action.target_cves:
        return None
    cve = str(action.target_cves[0])
    component = str(action.package_key or "")
    if not cve or not component:
        return None
    occ = occurrence or {}
    context = {"package_purl": occ.get("package_purl"),
               "package_name": occ.get("package_name"),
               "ecosystem": occ.get("result_type") or action.ecosystem,
               "installed_version": occ.get("installed_version")}
    try:
        records = retrieve_compatible(store, cve_id=cve, component=component,
                                      kind="remediation", context=context)
    except Exception:
        return None
    if not records:
        return None
    return {"fields": dict(records[0].fields)}


def build_patch_candidate_context(
    run_id: str,
    action: PatchAction,
    occurrences: Sequence[Mapping[str, Any]],
    target_facts: Mapping[str, Any],
    *,
    phase: str = "patch",
) -> CandidateContext | None:
    """Build the CandidateContext from real production Patch data.

    Returns ``None`` when no stable component identity exists; the caller
    must then skip LLM assistance and keep the manual Patch Form path.
    Missing optional identity fields are left as ``None``, never fabricated.
    """
    occurrence = _first_occurrence(action, occurrences)
    component = action.package_key or None
    if not component and occurrence is not None:
        component = occurrence.get("package_purl") or occurrence.get("package_name")
    if not component or not action.target_cves:
        return None
    ecosystem = action.ecosystem or (occurrence.get("result_type") if occurrence else None)
    facts = dict(target_facts or {})
    image_identity = (facts.get("requested_image_reference")
                      or facts.get("requested_reference")
                      or facts.get("image_id"))
    return CandidateContext(
        run_id=run_id,
        vulnerability_id=str(action.target_cves[0]),
        component=str(component),
        ecosystem=str(ecosystem) if ecosystem else None,
        installed_versions=tuple(sorted(set(
            str(v) for v in (action.before_versions or ()) if v))),
        image_identity=str(image_identity) if image_identity else None,
        target_identity=str(facts.get("ip_address")) if facts.get("ip_address") else None,
        container_id=str(facts.get("container_id")) if facts.get("container_id") else None,
        phase=phase,
    )


def build_patch_field_request(
    context: CandidateContext,
    resolved: Mapping[str, Any],
    unresolved: Sequence[str],
    *,
    enabled_sources: frozenset[SourceKind] | None = None,
    purpose: EvidencePurpose = EvidencePurpose.REMEDIATION,
) -> FieldRequest:
    """Build the FieldRequest for exactly the unresolved substantive fields."""
    wanted = tuple(sorted(set(unresolved) & _SUBSTANTIVE_SET))
    if not wanted:
        raise ValueError("field request requires unresolved eligible fields")
    safe_resolved = {k: resolved[k] for k in sorted(resolved) if k not in wanted}
    sources = enabled_sources if enabled_sources is not None else EvidenceSourceConfig().enabled()
    return FieldRequest(
        context=context,
        purpose=purpose,
        unresolved_fields=wanted,
        resolved_fields=safe_resolved,
        enabled_sources=sources,
    )


def has_useful_evidence(collection: Any) -> bool:
    """True only when the collector produced usable evidence items."""
    try:
        items = getattr(collection.pack, "items", ())
    except Exception:
        return False
    if not items:
        return False
    return any(bool(getattr(item, "facts", None)) for item in items)


def default_enabled_sources(evidence_config: EvidenceSourceConfig | None = None) -> frozenset[SourceKind]:
    config = evidence_config if evidence_config is not None else EvidenceSourceConfig()
    return config.enabled()


def _production_collector(knowledge_store: Any, target_facts: Mapping[str, Any],
                          occurrences: Sequence[Mapping[str, Any]],
                          output_root: Any, evidence_config: EvidenceSourceConfig | None):
    from ..resolution.llm_fields import build_production_collector
    return build_production_collector(
        knowledge_store=knowledge_store,
        target_facts=target_facts,
        occurrences=occurrences,
        candidates_by_cve={},
        output_root=output_root,
        evidence_config=evidence_config,
    )


def schedule_patch_guidance(
    run_id: str,
    actions: Sequence[PatchAction],
    *,
    target_facts: Mapping[str, Any],
    occurrences_by_action: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    knowledge_by_action: Mapping[str, Mapping[str, Any] | None] | None = None,
    knowledge_store: Any = None,
    guidance_service: Any,
    collector_or_factory: Any = None,
    plan_revision: int | None = None,
    base_patch_plan_sha256: str | None = None,
    evidence_config: EvidenceSourceConfig | None = None,
    output_root: Any = None,
) -> tuple[PatchGuidanceOutcome, ...]:
    """Schedule per-action field LLM assistance on the production path.

    Fully resolved actions short-circuit without touching the collector,
    GuidanceService, or the LLM provider.  Actions with unresolved fields
    collect a REMEDIATION EvidencePack first; the provider is invoked only
    when that exact pack carries useful evidence.  Failures are nonfatal:
    the deterministic/Knowledge manual Patch Form path remains usable.
    LLM suggestions are NEVER written to KnowledgeStore here.
    """
    if guidance_service is None:
        return ()
    occurrences_by_action = dict(occurrences_by_action or {})
    knowledge_by_action = dict(knowledge_by_action or {})
    facts = dict(target_facts or {})
    shared: Any = collector_or_factory if not callable(collector_or_factory) else None
    factory: Callable[..., Any] | None = (
        collector_or_factory if callable(collector_or_factory) else None)
    if shared is None and factory is None and knowledge_store is None and output_root is None:
        # No evidence subsystem available; manual path only.
        pass
    outcomes: list[PatchGuidanceOutcome] = []
    for action in actions or ():
        try:
            if action.status != PlanningStatus.WAITING_FOR_USER_INPUT:
                continue
        except Exception:
            continue
        occurrences = list(occurrences_by_action.get(action.action_id, ())
                           or action.occurrences or ())
        knowledge_entry = knowledge_by_action.get(action.action_id)
        if knowledge_entry is None and knowledge_store is not None:
            try:
                knowledge_entry = retrieve_patch_knowledge(
                    knowledge_store, action, _first_occurrence(action, occurrences))
            except Exception:
                knowledge_entry = None
        try:
            resolved, unresolved = effective_fields(action, knowledge_entry)
        except Exception:
            continue
        if not unresolved:
            continue
        try:
            context = build_patch_candidate_context(
                run_id, action, occurrences, facts)
        except Exception:
            continue
        if context is None:
            continue
        try:
            request = build_patch_field_request(
                context, resolved, unresolved,
                enabled_sources=default_enabled_sources(evidence_config))
        except Exception:
            continue
        try:
            active = shared
            if active is None and factory is not None:
                try:
                    active = factory()
                except TypeError:
                    active = factory(
                        knowledge_store=knowledge_store,
                        target_facts=facts,
                        occurrences=occurrences,
                        candidates_by_cve={},
                    )
            if active is None:
                if knowledge_store is None and output_root is None:
                    continue
                active = _production_collector(
                    knowledge_store, facts, occurrences, output_root, evidence_config)
        except Exception:
            continue
        try:
            collection = active.collect(request)
        except Exception:
            continue
        if not has_useful_evidence(collection):
            continue
        guide_with_pack = getattr(guidance_service, "guide_with_patch_pack", None)
        if guide_with_pack is None:
            continue
        try:
            outcome = guide_with_pack(
                run_id, action, facts,
                field_pack=collection.pack,
                allowed_fields=frozenset(unresolved),
                plan_revision=plan_revision,
                base_patch_plan_sha256=base_patch_plan_sha256,
            )
        except Exception:
            continue
        if outcome is not None:
            outcomes.append(outcome)
    return tuple(outcomes)


def project_patch_guidance(
    form: Mapping[str, Any],
    outcomes: Sequence[PatchGuidanceOutcome],
    *,
    created_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project accepted LLM suggestions into SUGGESTED/display values only.

    Only blank ``suggested`` slots are filled (deterministic/Knowledge
    suggestions are never overwritten).  ``confirmed`` values,
    ``human_confirmed_fields``, trust, readiness, and execution state are
    never touched.  Fields without a safe form slot (``source_identifier``,
    ``build_system``, ``notes``) live in the sidecar guidance artifact only.
    Returns ``(updated_form, guidance_artifact)``.
    """
    updated_actions: dict[str, Any] = {}
    for action_id, entry in dict(form.get("actions") or {}).items():
        updated_actions[action_id] = _deep_copy(entry)
    guidance_actions: list[dict[str, Any]] = []
    for outcome in outcomes or ():
        accepted = dict(outcome.accepted or {})
        if not accepted:
            continue
        entry = updated_actions.get(outcome.action_id)
        if not isinstance(entry, dict):
            continue
        suggestion = accepted.get("fix_type")
        slot = entry.get("fix_type")
        if (isinstance(suggestion, Mapping) and isinstance(slot, Mapping)
                and slot.get("suggested") is None and slot.get("confirmed") is None):
            slot["suggested"] = suggestion.get("value")
        suggestion = accepted.get("strategy")
        slot = entry.get("strategy")
        if (isinstance(suggestion, Mapping) and isinstance(slot, Mapping)
                and slot.get("suggested") is None and slot.get("confirmed") is None):
            slot["suggested"] = suggestion.get("value")
        suggestion = accepted.get("target_version")
        slot = entry.get("target_version")
        if (isinstance(suggestion, Mapping) and isinstance(slot, Mapping)
                and slot.get("suggested") is None and slot.get("confirmed") is None):
            slot["suggested"] = suggestion.get("value")
        suggestion = accepted.get("artifact_source")
        slot = entry.get("artifact")
        if (isinstance(suggestion, Mapping) and isinstance(slot, Mapping)
                and slot.get("suggested_source") is None
                and slot.get("confirmed_source") is None):
            slot["suggested_source"] = suggestion.get("value")
        guidance_actions.append(outcome.to_dict())
    updated_form = {**dict(form), "actions": updated_actions}
    stamp = created_at or datetime.now(timezone.utc).isoformat()
    artifact = {"schema": PATCH_LLM_GUIDANCE_SCHEMA,
                "run_id": form.get("run_id"),
                "phase": "patch",
                "created_at": stamp,
                "base_patch_plan_sha256": form.get("base_patch_plan_sha256"),
                "revision": form.get("revision"),
                "actions": guidance_actions}
    return updated_form, artifact


def _deep_copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_deep_copy(v) for v in value)
    return value
