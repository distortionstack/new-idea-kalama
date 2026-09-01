"""Pure-ish Step 4 processing around the existing Resolver APIs."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Sequence

from resolver_config import build_exploit_config, validate_exploit_config
from resolver_config_models import ConfigReadiness, EnvironmentPhase
from resolver_core import DiscoveryBackend, discover_cve, rank_discovery_candidates
from resolver_models import (
    DiscoveryStatus, ObservedPort, PublishedPort, TargetFacts,
)

from .models import RankedCVEInput, ResolverCVEResult, ResolverCVEStatus, Step4Analysis


def target_facts_from_state(run_id: str, raw: Mapping[str, Any]) -> TargetFacts:
    observed = []
    for item in raw.get("listening_ports", []) or []:
        if isinstance(item, Mapping) and isinstance(item.get("container_port"), int):
            protocol = str(item.get("protocol") or "tcp")
            observed.append(ObservedPort(item["container_port"], protocol,
                                         address=item.get("address")))
    exposed = []
    for item in raw.get("exposed_ports", []) or []:
        if isinstance(item, Mapping) and isinstance(item.get("container_port"), int):
            exposed.append(ObservedPort(item["container_port"],
                                        str(item.get("protocol") or "tcp")))
    reachable = [ObservedPort(port) for port in raw.get("reachable_ports", []) or []
                 if isinstance(port, int) and not isinstance(port, bool)]
    published = []
    for item in raw.get("published_ports", []) or []:
        if isinstance(item, Mapping) and isinstance(item.get("container_port"), int):
            published.append(PublishedPort(
                item["container_port"], item.get("host_port"),
                str(item.get("protocol") or "tcp"), item.get("host_ip")))
    return TargetFacts(
        run_id=run_id, container_name=raw.get("container_name"),
        container_id=raw.get("container_id"),
        image=raw.get("requested_image_reference"), image_id=raw.get("image_id"),
        image_digest=raw.get("image_digest"), network=raw.get("network"),
        ip_address=raw.get("ip_address"),
        observed_ports=tuple(sorted(observed, key=lambda x: (x.port, x.protocol))),
        published_ports=tuple(sorted(published, key=lambda x: (
            x.container_port, x.protocol, x.host_port or 0))),
        exposed_ports=tuple(sorted(exposed, key=lambda x: (x.port, x.protocol))),
        reachable_ports=tuple(sorted(reachable, key=lambda x: (x.port, x.protocol))),
    )


def parse_ranked_inputs(top30: Mapping[str, Any]) -> tuple[RankedCVEInput, ...]:
    raw = top30.get("ranked_cves")
    if not isinstance(raw, list):
        raise ValueError("ranked_cves must be an array")
    output = []
    expected_rank = 1
    seen = set()
    for value in raw:
        if not isinstance(value, Mapping):
            raise ValueError("ranked CVE must be an object")
        rank, cve_id, occurrences = value.get("rank"), value.get("cve_id"), value.get("occurrences")
        if rank != expected_rank or not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            raise ValueError("ranked CVEs must have ordinal ranks and canonical CVE IDs")
        if (cve_id in seen or not isinstance(occurrences, list)
                or any(not isinstance(x, Mapping) for x in occurrences)):
            raise ValueError("ranked CVEs must be unique and preserve occurrence arrays")
        seen.add(cve_id)
        output.append(RankedCVEInput(rank, cve_id, tuple(dict(x) for x in occurrences)))
        expected_rank += 1
    return tuple(output)


def _classify(discovery, validation) -> ResolverCVEStatus:
    if discovery.status == DiscoveryStatus.NO_MSF_MODULE:
        return ResolverCVEStatus.NO_MSF_MODULE
    if discovery.status == DiscoveryStatus.ENVIRONMENT_ERROR:
        return ResolverCVEStatus.ENVIRONMENT_ERROR
    if validation.ready and validation.readiness == ConfigReadiness.READY_TO_EXECUTE:
        return ResolverCVEStatus.READY_TO_EXECUTE
    if validation.readiness == ConfigReadiness.READY_FOR_CONFIRMATION:
        return ResolverCVEStatus.WAITING_FOR_USER_INPUT
    return ResolverCVEStatus.UNRESOLVED_CONFIG


def analyze_cves(inputs: Sequence[RankedCVEInput], target_facts: TargetFacts,
                 backend: DiscoveryBackend, msf_container: str) -> Step4Analysis:
    if backend.resolve_msf_ip is not None and target_facts.network:
        try:
            msf_ip = backend.resolve_msf_ip(msf_container, target_facts.network)
        except (OSError, RuntimeError, ValueError):
            msf_ip = None
        target_facts = replace(target_facts, msf_container=msf_container, msf_ip=msf_ip)
    results = []
    for item in inputs:
        try:
            discovery = discover_cve(item.cve_id, msf_container, backend)
            ranking = rank_discovery_candidates(discovery, target_facts)
            config = build_exploit_config(discovery, ranking, target_facts, EnvironmentPhase.BEFORE)
            validation = validate_exploit_config(config)
            results.append(ResolverCVEResult(item, _classify(discovery, validation),
                                             discovery, ranking, config, validation))
        except Exception as exc:
            results.append(ResolverCVEResult(
                item, ResolverCVEStatus.UNRESOLVED_CONFIG, None, None, None, None,
                (f"{type(exc).__name__}: {exc}",)))
    return Step4Analysis(tuple(results))
