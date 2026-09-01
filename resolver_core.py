"""Resolver discovery core.

The caller supplies a Metasploit backend explicitly.  This module therefore
does not inspect pipeline directories or read/write a run state file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from resolver_models import (
    CandidateAmbiguityStatus,
    CandidateRankingEvidence,
    CandidateRankingResult,
    DiscoveryResult,
    DiscoveryStatus,
    ModuleCandidate,
    ModuleOption,
    ModuleTarget,
    PayloadDiscoveryStatus,
    PayloadEvidence,
    RankedModuleCandidate,
    TargetFacts,
)


# Candidate-ordering heuristic only.  These values are deliberately compact
# and centralized: they are neither an exploitability metric nor a module
# selection policy.
MSF_RANK_WEIGHTS = {
    "manual": 0,
    "low": 1,
    "average": 2,
    "normal": 3,
    "good": 4,
    "great": 5,
    "excellent": 6,
}
MSF_NUMERIC_RANKS = {
    "0": "manual",
    "100": "low",
    "200": "average",
    "300": "normal",
    "400": "good",
    "500": "great",
    "600": "excellent",
}
CHECK_SUPPORTED_WEIGHT = 2
RPORT_MATCH_WEIGHT = 2
LIVE_INTROSPECTION_WEIGHT = 1
CLEAR_WINNER_MINIMUM_GAP = 2


@dataclass(frozen=True)
class DiscoveryBackend:
    load_cache: Callable[[], dict[str, Any] | None]
    find_from_cache: Callable[[dict[str, Any] | None, str], dict[str, dict[str, Any]]]
    search_live: Callable[[str, str], list[str]]
    query_modules: Callable[[list[str], str], dict[str, dict[str, Any]]]
    cache_description: str
    query_payloads: Callable[[list[str], str], dict[str, dict[str, Any]]] | None = None
    resolve_msf_ip: Callable[[str, str], str | None] | None = None
    introspect_payload: Callable[[str, str, str], PayloadEvidence] | None = None


def _option_from_raw(raw: dict[str, Any]) -> ModuleOption:
    return ModuleOption(
        name=str(raw.get("name", "")),
        type=None if raw.get("type") is None else str(raw["type"]),
        required=bool(raw.get("required", False)),
        default=raw.get("default"),
    )


def discover_cve(cve_id: str, msf_container: str, backend: DiscoveryBackend) -> DiscoveryResult:
    """Discover and introspect every MSF candidate for one CVE.

    Candidate order is discovery order only.  It is not a ranking, selection,
    or confirmation signal.
    """
    try:
        cache = backend.load_cache()
        cache_candidates = backend.find_from_cache(cache, cve_id)

        if cache_candidates:
            fullnames = list(cache_candidates)
            discovery_source = "metadata_cache"
        elif cache is None:
            fullnames = backend.search_live(cve_id, msf_container)
            discovery_source = "msfconsole_search"
        else:
            return DiscoveryResult(cve_id, DiscoveryStatus.NO_MSF_MODULE)

        if not fullnames:
            return DiscoveryResult(cve_id, DiscoveryStatus.NO_MSF_MODULE)

        live_data = backend.query_modules(fullnames, msf_container)
        payload_data = (backend.query_payloads(fullnames, msf_container)
                        if backend.query_payloads is not None else live_data)
    except (OSError, RuntimeError, ValueError) as exc:
        return DiscoveryResult(
            cve_id,
            DiscoveryStatus.ENVIRONMENT_ERROR,
            errors=(str(exc),),
        )

    candidates: list[ModuleCandidate] = []
    errors: list[str] = []
    for fullname in fullnames:
        live_entry = live_data.get(fullname, {})
        base = cache_candidates.get(fullname, {})
        if "error" in live_entry:
            errors.append(f"{fullname}: {live_entry['error']}")
            if not base:
                continue

        metadata_sources = []
        if base:
            metadata_sources.append(backend.cache_description)
        if live_entry and "error" not in live_entry:
            metadata_sources.append("live_msfconsole")

        raw_targets = live_entry.get("target_details") or base.get("target_details") or ()
        target_details = tuple(ModuleTarget(int(item["index"]), str(item["name"]))
                               for item in raw_targets
                               if isinstance(item, dict) and isinstance(item.get("index"), int)
                               and isinstance(item.get("name"), str))
        payload_entry = payload_data.get(fullname, {})
        try:
            payload_status = PayloadDiscoveryStatus(
                payload_entry.get("status", PayloadDiscoveryStatus.UNAVAILABLE.value))
        except ValueError:
            payload_status = PayloadDiscoveryStatus.ERROR
        payloads = []
        seen_payloads = set()
        for raw_payload in payload_entry.get("payloads", ()):
            if not isinstance(raw_payload, dict) or not isinstance(raw_payload.get("name"), str):
                continue
            name = raw_payload["name"].removeprefix("payload/")
            if not name or name in seen_payloads:
                continue
            seen_payloads.add(name)
            # Discovery records the compatible allowlist only.  Payload option
            # schemas are loaded after a human selects an allowlisted payload.
            payloads.append(PayloadEvidence(name))
        raw_default_target = live_entry.get("default_target_index")
        if not isinstance(raw_default_target, int):
            raw_default_target = base.get("default_target_index")
        known_target_indexes = {item.index for item in target_details}
        default_target_index = (raw_default_target
                                if raw_default_target in known_target_indexes else None)
        if default_target_index is None and len(known_target_indexes) == 1:
            default_target_index = next(iter(known_target_indexes))
        candidates.append(ModuleCandidate(
            module_path=fullname,
            rank=str(base.get("rank") or live_entry.get("rank") or "normal"),
            disclosure_date=base.get("disclosure_date", live_entry.get("disclosure_date")),
            platform=tuple(base.get("platform") or live_entry.get("platform") or ()),
            targets=tuple(base.get("targets") or live_entry.get("targets") or ()),
            check_supported=bool(base.get("check_supported", live_entry.get("check_supported", False))),
            references=tuple(base.get("references") or live_entry.get("references") or ()),
            options=tuple(_option_from_raw(option) for option in live_entry.get("options", ())),
            discovery_source=discovery_source,
            metadata_source=tuple(metadata_sources),
            target_details=target_details,
            default_target_index=default_target_index,
            payload_discovery_status=payload_status,
            payloads=tuple(payloads),
        ))

    if not candidates:
        return DiscoveryResult(
            cve_id,
            DiscoveryStatus.ENVIRONMENT_ERROR,
            errors=tuple(errors or ["MSF candidates were found but none could be introspected"]),
        )

    return DiscoveryResult(
        cve_id,
        DiscoveryStatus.FOUND,
        candidates=tuple(candidates),
        errors=tuple(errors),
    )


def _normalize_msf_rank(raw_rank: str | None) -> tuple[str, int, bool]:
    raw = "" if raw_rank is None else str(raw_rank).strip().lower()
    normalized = MSF_NUMERIC_RANKS.get(raw, raw)
    if normalized in MSF_RANK_WEIGHTS:
        return normalized, MSF_RANK_WEIGHTS[normalized], True
    return normalized or "unknown", 0, False


def _normalize_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _candidate_default_rport(candidate: ModuleCandidate) -> int | None:
    for option in candidate.options:
        if option.name.upper() == "RPORT":
            return _normalize_port(option.default)
    return None


def _target_ports(target_facts: TargetFacts) -> dict[int, tuple[str, ...]]:
    sources: dict[int, set[str]] = {}
    for observed in target_facts.observed_ports:
        sources.setdefault(observed.port, set()).add("observed")
    for published in target_facts.published_ports:
        sources.setdefault(published.container_port, set()).add("published_container")
        if published.host_port is not None:
            sources.setdefault(published.host_port, set()).add("published_host")
    for exposed in target_facts.exposed_ports:
        sources.setdefault(exposed.port, set()).add("exposed")
    for reachable in target_facts.reachable_ports:
        sources.setdefault(reachable.port, set()).add("reachable")
    return {port: tuple(sorted(labels)) for port, labels in sources.items()}


def _ranking_evidence(
    candidate: ModuleCandidate,
    target_ports: dict[int, tuple[str, ...]],
) -> tuple[CandidateRankingEvidence, ...]:
    normalized_rank, rank_weight, known_rank = _normalize_msf_rank(candidate.rank)
    evidence = [CandidateRankingEvidence(
        reason="metasploit_rank",
        weight=rank_weight,
        matched=known_rank,
        detail=normalized_rank,
    )]

    evidence.append(CandidateRankingEvidence(
        reason="check_supported",
        weight=CHECK_SUPPORTED_WEIGHT if candidate.check_supported else 0,
        matched=candidate.check_supported,
        detail="module advertises check() support" if candidate.check_supported else "check() support not advertised",
    ))

    default_rport = _candidate_default_rport(candidate)
    if default_rport is None:
        port_match = None
        port_weight = 0
        port_detail = "no usable module-default RPORT"
    elif not target_ports:
        port_match = None
        port_weight = 0
        port_detail = f"module default {default_rport}; no target port evidence"
    elif default_rport in target_ports:
        sources_for_port = set(target_ports[default_rport])
        runtime_sources = sources_for_port & {"observed", "reachable"}
        sources = ",".join(sorted(sources_for_port))
        if runtime_sources:
            port_match = True
            port_weight = RPORT_MATCH_WEIGHT
            port_detail = f"module default {default_rport} matches {sources} target port"
        else:
            has_other_runtime = any(
                port != default_rport and set(labels) & {"observed", "reachable"}
                for port, labels in target_ports.items())
            port_match = False if has_other_runtime else None
            port_weight = 0
            port_detail = (f"module default {default_rport} matches only weak {sources} metadata; "
                           "no listening/reachable runtime evidence")
    else:
        port_match = False
        port_weight = 0
        available = ",".join(str(port) for port in sorted(target_ports))
        port_detail = f"module default {default_rport}; target ports {available}"
    evidence.append(CandidateRankingEvidence(
        reason="rport_target_match",
        weight=port_weight,
        matched=port_match,
        detail=port_detail,
    ))

    live_introspection = "live_msfconsole" in candidate.metadata_source
    evidence.append(CandidateRankingEvidence(
        reason="live_introspection",
        weight=LIVE_INTROSPECTION_WEIGHT if live_introspection else 0,
        matched=live_introspection,
        detail="live module metadata available" if live_introspection else "live module metadata unavailable",
    ))
    return tuple(evidence)


def rank_module_candidates(
    cve_id: str,
    candidates: tuple[ModuleCandidate, ...],
    target_facts: TargetFacts,
) -> CandidateRankingResult:
    """Order candidates deterministically without selecting or mutating one."""
    target_ports = _target_ports(target_facts)
    scored = []
    for candidate in candidates:
        evidence = _ranking_evidence(candidate, target_ports)
        scored.append((candidate, sum(item.weight for item in evidence), evidence))

    # Module path is only a stable presentation tie-break.  Ambiguity below is
    # determined from score gaps and is never changed by this lexical ordering.
    scored.sort(key=lambda item: (-item[1], item[0].module_path.casefold(), item[0].module_path))

    ranked = []
    prior_score = None
    rank_position = 0
    for index, (candidate, score, evidence) in enumerate(scored, start=1):
        if score != prior_score:
            rank_position = index
            prior_score = score
        ranked.append(RankedModuleCandidate(candidate, score, evidence, rank_position))

    if not ranked:
        ambiguity = CandidateAmbiguityStatus.NO_CANDIDATES
        top_gap = None
    elif len(ranked) == 1:
        ambiguity = CandidateAmbiguityStatus.SINGLE_CANDIDATE
        top_gap = None
    else:
        top_gap = ranked[0].score - ranked[1].score
        first_port = _candidate_default_rport(ranked[0].candidate)
        second_port = _candidate_default_rport(ranked[1].candidate)
        different_plausible_services = (
            first_port is not None
            and second_port is not None
            and first_port != second_port
            and first_port in target_ports
            and second_port in target_ports
        )
        if different_plausible_services:
            ambiguity = CandidateAmbiguityStatus.AMBIGUOUS
        else:
            ambiguity = (
                CandidateAmbiguityStatus.CLEAR_WINNER
                if top_gap >= CLEAR_WINNER_MINIMUM_GAP
                else CandidateAmbiguityStatus.AMBIGUOUS
            )

    return CandidateRankingResult(cve_id, tuple(ranked), ambiguity, top_gap)


def rank_discovery_candidates(
    discovery: DiscoveryResult,
    target_facts: TargetFacts,
) -> CandidateRankingResult:
    """Rank candidates already present in a DiscoveryResult."""
    return rank_module_candidates(discovery.cve_id, discovery.candidates, target_facts)
