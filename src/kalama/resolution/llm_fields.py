"""Task 4B field-level Resolver LLM scheduling.

Production path::

    deterministic Resolver facts + compatible VALIDATED Knowledge
    -> resolved eligible fields -> unresolved eligible fields
    -> CandidateContext -> FieldRequest -> EvidenceCollector
    -> EvidencePack -> GuidanceService -> validator/merge
    -> Attack Form -> PAUSE for human submission.

Only four Attack fields are LLM eligible: ``target``, ``targeturi``,
``rport`` and ``payload``.  Nothing here expands the Attack Form schema,
auto-submits a form, or executes an exploit.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from ..evidence import (
    CandidateContext,
    EvidenceCollector,
    EvidencePurpose,
    FieldRequest,
    SourceKind,
)
from ..evidence.cache import EvidenceCache
from ..evidence.external import (
    BoundedHTTP,
    ExternalPolicy,
    NVDEvidenceSource,
    VendorEvidenceSource,
)
from ..evidence.policy import EvidenceSourceConfig, SourcePolicy
from ..evidence.sources import (
    CISAKEVEvidenceSource,
    KnowledgeEvidenceSource,
    MSFMetadataEvidenceSource,
    MSFReferenceEvidenceSource,
    RuntimeEvidenceSource,
)

LLM_ELIGIBLE_FIELDS: tuple[str, ...] = ("target", "targeturi", "rport", "payload")
_ELIGIBLE_SET = frozenset(LLM_ELIGIBLE_FIELDS)


def deterministic_resolved(item: Any) -> dict[str, Any]:
    """Effective deterministic values for the four eligible fields.

    A field counts as resolved only when the existing deterministic
    Resolver/runtime facts mark it confirmed.  Suggestions, NVD/KEV text,
    external documents and LLM memory never count as resolved.
    """
    resolved: dict[str, Any] = {}
    config = getattr(item, "exploit_config", None)
    if config is None:
        return resolved
    invariant = getattr(config, "invariant", None)
    if invariant is None:
        return resolved
    try:
        target_selection = invariant.target_selection
        index_value = getattr(target_selection, "target_index", None)
        if index_value is not None and bool(getattr(index_value, "confirmed", False)):
            name_value = getattr(target_selection, "target_name", None)
            resolved["target"] = {
                "index": getattr(index_value, "value", None),
                "name": getattr(name_value, "value", None) if name_value is not None else None,
            }
    except Exception:
        pass
    try:
        targeturi = invariant.targeturi
        if bool(getattr(targeturi, "confirmed", False)):
            resolved["targeturi"] = getattr(targeturi, "value", None)
    except Exception:
        pass
    try:
        rport = config.environment.rport
        if bool(getattr(rport, "confirmed", False)):
            resolved["rport"] = getattr(rport, "value", None)
    except Exception:
        pass
    try:
        payload_value = invariant.payload.payload
        if bool(getattr(payload_value, "confirmed", False)):
            resolved["payload"] = getattr(payload_value, "value", None)
    except Exception:
        pass
    return {key: value for key, value in resolved.items() if key in _ELIGIBLE_SET}


def knowledge_resolved(knowledge_entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compatible VALIDATED Knowledge values for eligible fields only."""
    if not isinstance(knowledge_entry, Mapping):
        return {}
    accepted = knowledge_entry.get("accepted_suggestions")
    if not isinstance(accepted, Mapping):
        return {}
    resolved: dict[str, Any] = {}
    for field, proposal in accepted.items():
        if field not in _ELIGIBLE_SET:
            continue
        if isinstance(proposal, Mapping) and "value" in proposal:
            resolved[field] = proposal.get("value")
    return resolved


def effective_fields(
    item: Any, knowledge_entry: Mapping[str, Any] | None
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Merge deterministic facts with compatible VALIDATED Knowledge.

    Deterministic confirmed values win; Knowledge only fills fields that
    remain unresolved.  Returns ``(resolved, unresolved)`` where
    ``unresolved`` is exactly the eligible subset still needing help.
    """
    resolved = deterministic_resolved(item)
    for field, value in knowledge_resolved(knowledge_entry).items():
        if field not in resolved:
            resolved[field] = value
    unresolved = tuple(sorted(key for key in _ELIGIBLE_SET if key not in resolved))
    return resolved, unresolved


def build_candidate_context(
    run_id: str,
    cve_id: str,
    occurrences: Sequence[Mapping[str, Any]],
    target_facts: Mapping[str, Any],
    *,
    phase: str = "before",
) -> CandidateContext | None:
    """Build the Task 1 CandidateContext from real production data.

    Returns ``None`` when no stable component identity exists; the caller
    must then skip LLM assistance and keep the manual Attack Form path.
    Missing optional identity fields are left as ``None``, never fabricated.
    """
    component: str | None = None
    ecosystem: str | None = None
    versions: list[str] = []
    for occurrence in occurrences or ():
        if not isinstance(occurrence, Mapping):
            continue
        candidate = occurrence.get("package_purl") or occurrence.get("package_name")
        if candidate and component is None:
            component = str(candidate)
            eco = occurrence.get("ecosystem") or occurrence.get("result_type")
            ecosystem = str(eco) if eco else None
        installed = occurrence.get("installed_version")
        if installed:
            versions.append(str(installed))
    if not component:
        return None
    image_identity = target_facts.get("requested_image_reference")
    target_identity = target_facts.get("ip_address") or None
    container_id = target_facts.get("container_id") or None
    return CandidateContext(
        run_id=run_id,
        vulnerability_id=str(cve_id),
        component=component,
        ecosystem=ecosystem,
        installed_versions=tuple(sorted(set(versions))),
        image_identity=str(image_identity) if image_identity else None,
        target_identity=str(target_identity) if target_identity else None,
        container_id=str(container_id) if container_id else None,
        phase=phase,
    )


def build_field_request(
    context: CandidateContext,
    resolved: Mapping[str, Any],
    unresolved: Sequence[str],
    *,
    enabled_sources: frozenset[SourceKind] | None = None,
    purpose: EvidencePurpose = EvidencePurpose.EXPLOIT_CONFIGURATION,
) -> FieldRequest:
    """Build the Task 1 FieldRequest for exactly the unresolved fields."""
    wanted = tuple(sorted(set(unresolved) & _ELIGIBLE_SET))
    if not wanted:
        raise ValueError("field request requires unresolved eligible fields")
    safe_resolved = {key: resolved[key] for key in sorted(resolved) if key not in wanted}
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


def selected_candidate_for_item(item: Any) -> Any | None:
    """Pick the resolved ModuleCandidate backing a Resolver result."""
    try:
        config = item.exploit_config
        discovery = item.discovery
    except Exception:
        return None
    if config is None or discovery is None:
        return None
    try:
        selected = (
            config.invariant.module_selection.module.value
            or config.invariant.module_selection.module.suggested_value
        )
    except Exception:
        selected = None
    candidates = list(getattr(discovery, "candidates", ()) or ())
    if not candidates:
        return None
    if selected:
        for candidate in candidates:
            if getattr(candidate, "module_path", None) == selected:
                return candidate
    return candidates[0]


def build_production_collector(
    *,
    knowledge_store: Any = None,
    target_facts: Mapping[str, Any] | None = None,
    occurrences: Sequence[Mapping[str, Any]] = (),
    candidates_by_cve: Mapping[str, Any] | None = None,
    output_root: Any = None,
    evidence_config: EvidenceSourceConfig | None = None,
) -> EvidenceCollector:
    """Compose the accepted Task 2/3 EvidenceCollector for Resolver use.

    Reuses the existing adapters and default SourcePolicy (NVD/Vendor
    disabled, no web search).  External adapters are instantiated disabled
    so the shared EvidenceCache/policy path is exercised without network.
    """
    config = evidence_config if evidence_config is not None else EvidenceSourceConfig()
    policy = SourcePolicy(config)
    facts = dict(target_facts or {})
    occurrences_list = [dict(x) for x in (occurrences or ()) if isinstance(x, Mapping)]
    candidates = dict(candidates_by_cve or {})
    sources: dict[SourceKind, Any] = {
        SourceKind.RUNTIME: RuntimeEvidenceSource(occurrences_list, facts),
        SourceKind.MSF_METADATA: MSFMetadataEvidenceSource(candidates),
        SourceKind.MSF_REFERENCE: MSFReferenceEvidenceSource(candidates),
        SourceKind.CISA_KEV: CISAKEVEvidenceSource(None),
    }
    if knowledge_store is not None:
        sources[SourceKind.KNOWLEDGE] = KnowledgeEvidenceSource(knowledge_store)
    if output_root is not None:
        try:
            cache = EvidenceCache(output_root)

            def _refused(_url: str, _headers: Mapping[str, str], _timeout: float):  # pragma: no cover
                raise OSError("external evidence transport is unavailable in Resolver")

            http = BoundedHTTP(_refused, ExternalPolicy())
            sources[SourceKind.NVD] = NVDEvidenceSource(http, cache, enabled=False)
            sources[SourceKind.VENDOR_UPSTREAM] = VendorEvidenceSource(
                http, cache, ExternalPolicy(), {}, enabled=False
            )
        except Exception:
            pass
    return EvidenceCollector(policy, sources)


def default_enabled_sources(evidence_config: EvidenceSourceConfig | None = None) -> frozenset[SourceKind]:
    config = evidence_config if evidence_config is not None else EvidenceSourceConfig()
    return config.enabled()


def schedule_field_guidance(
    run_id: str,
    analysis: Any,
    target_facts: Mapping[str, Any],
    knowledge_guidance: Mapping[str, Mapping[str, Any]],
    guidance_service: Any,
    collector_or_factory: Any,
    *,
    evidence_config: EvidenceSourceConfig | None = None,
    knowledge_store: Any = None,
    output_root: Any = None,
) -> tuple[Any, ...]:
    """Schedule per-candidate field LLM assistance on the production path.

    Fully resolved candidates short-circuit without touching the collector,
    GuidanceService, or the LLM provider.  Candidates with unresolved fields
    collect a Task 2/3 EvidencePack first; GuidanceService is invoked only
    when that exact pack carries useful evidence.  Failures are nonfatal:
    the deterministic/Knowledge manual Attack Form path remains usable.
    """
    if guidance_service is None:
        return ()
    cves = list(getattr(analysis, "cves", ()) or ())
    if not cves:
        return ()
    # A shared collector instance, a zero-arg factory, or None (build the
    # production default lazily once analysis candidates are known).
    shared: Any = collector_or_factory if not callable(collector_or_factory) else None
    factory: Callable[..., Any] | None = (
        collector_or_factory if callable(collector_or_factory) else None
    )

    occurrences_all: list[Mapping[str, Any]] = []
    candidates_by_cve: dict[str, Any] = {}
    for item in cves:
        try:
            for occurrence in getattr(item.input, "occurrences", ()):
                if isinstance(occurrence, Mapping):
                    occurrences_all.append(occurrence)
        except Exception:
            continue
        candidate = selected_candidate_for_item(item)
        if candidate is not None:
            try:
                candidates_by_cve[item.input.cve_id] = candidate
            except Exception:
                continue

    outcomes: list[Any] = []
    for item in cves:
        try:
            cve_id = item.input.cve_id
        except Exception:
            continue
        if getattr(guidance_service, "cve_ids", None) is not None:
            try:
                if cve_id not in guidance_service.cve_ids:
                    continue
            except Exception:
                continue
        try:
            from ..resolution.models import ResolverCVEStatus

            if item.status != ResolverCVEStatus.WAITING_FOR_USER_INPUT:
                continue
            if item.exploit_config is None or item.validation is None or item.discovery is None:
                continue
        except Exception:
            continue
        try:
            resolved, unresolved = effective_fields(
                item, (knowledge_guidance or {}).get(cve_id)
            )
        except Exception:
            continue
        if not unresolved:
            continue
        try:
            context = build_candidate_context(
                run_id, cve_id, tuple(getattr(item.input, "occurrences", ()) or ()),
                target_facts,
            )
        except Exception:
            continue
        if context is None:
            continue
        try:
            request = build_field_request(
                context,
                resolved,
                unresolved,
                enabled_sources=default_enabled_sources(evidence_config),
            )
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
                        target_facts=target_facts,
                        occurrences=occurrences_all,
                        candidates_by_cve=candidates_by_cve,
                    )
            if active is None:
                active = build_production_collector(
                    knowledge_store=knowledge_store,
                    target_facts=target_facts,
                    occurrences=occurrences_all,
                    candidates_by_cve=candidates_by_cve,
                    output_root=output_root,
                    evidence_config=evidence_config,
                )
        except Exception:
            continue
        try:
            collection = active.collect(request)
        except Exception:
            continue
        if not has_useful_evidence(collection):
            continue
        guide_with_pack = getattr(guidance_service, "guide_with_field_pack", None)
        if guide_with_pack is None:
            # Never rebuild an unrelated legacy pack alongside the collected
            # one; without the pack-accepting API there is no safe call.
            continue
        try:
            outcome = guide_with_pack(
                run_id,
                item,
                target_facts,
                field_pack=collection.pack,
                allowed_fields=frozenset(unresolved),
            )
        except Exception:
            continue
        if outcome is not None:
            outcomes.append(outcome)
    return tuple(outcomes)
