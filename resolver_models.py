"""Structured data contract for the Kalama Resolver core.

These models contain discovery inputs and results only.  They deliberately do
not know how to read pipeline state, select a module, or execute an exploit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class DiscoveryStatus(str, Enum):
    FOUND = "FOUND"
    NO_MSF_MODULE = "NO_MSF_MODULE"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"


class CandidateAmbiguityStatus(str, Enum):
    SINGLE_CANDIDATE = "SINGLE_CANDIDATE"
    CLEAR_WINNER = "CLEAR_WINNER"
    AMBIGUOUS = "AMBIGUOUS"
    NO_CANDIDATES = "NO_CANDIDATES"


class PayloadDiscoveryStatus(str, Enum):
    FOUND = "FOUND"
    NONE = "NONE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ObservedPort:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "address": self.address,
        }


@dataclass(frozen=True)
class PublishedPort:
    container_port: int
    host_port: int | None = None
    protocol: str = "tcp"
    host_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_port": self.container_port,
            "host_port": self.host_port,
            "protocol": self.protocol,
            "host_ip": self.host_ip,
        }


@dataclass(frozen=True)
class ModuleTarget:
    index: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name}


@dataclass(frozen=True)
class PayloadEvidence:
    name: str
    options: tuple["ModuleOption", ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "options": [option.to_dict() for option in self.options]}


@dataclass(frozen=True)
class TargetFacts:
    run_id: str | None = None
    container_name: str | None = None
    container_id: str | None = None
    image: str | None = None
    image_id: str | None = None
    image_digest: str | None = None
    network: str | None = None
    ip_address: str | None = None
    observed_ports: tuple[ObservedPort, ...] = ()
    published_ports: tuple[PublishedPort, ...] = ()
    exposed_ports: tuple[ObservedPort, ...] = ()
    reachable_ports: tuple[ObservedPort, ...] = ()
    msf_container: str | None = None
    msf_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "container_name": self.container_name,
            "container_id": self.container_id,
            "image": self.image,
            "image_id": self.image_id,
            "image_digest": self.image_digest,
            "network": self.network,
            "ip_address": self.ip_address,
            "observed_ports": [port.to_dict() for port in self.observed_ports],
            "published_ports": [port.to_dict() for port in self.published_ports],
            "exposed_ports": [port.to_dict() for port in self.exposed_ports],
            "reachable_ports": [port.to_dict() for port in self.reachable_ports],
            "msf_container": self.msf_container,
            "msf_ip": self.msf_ip,
        }


@dataclass(frozen=True)
class ModuleOption:
    name: str
    type: str | None
    required: bool
    default: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default": self.default,
        }


@dataclass(frozen=True)
class ModuleCandidate:
    module_path: str
    rank: str
    disclosure_date: str | None = None
    platform: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    check_supported: bool = False
    references: tuple[str, ...] = ()
    options: tuple[ModuleOption, ...] = ()
    discovery_source: str | None = None
    metadata_source: tuple[str, ...] = ()
    target_details: tuple[ModuleTarget, ...] = ()
    default_target_index: int | None = None
    payload_discovery_status: PayloadDiscoveryStatus = PayloadDiscoveryStatus.UNAVAILABLE
    payloads: tuple[PayloadEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_path": self.module_path,
            "rank": self.rank,
            "disclosure_date": self.disclosure_date,
            "platform": list(self.platform),
            "targets": list(self.targets),
            "check_supported": self.check_supported,
            "references": list(self.references),
            "options": [option.to_dict() for option in self.options],
            "discovery_source": self.discovery_source,
            "metadata_source": list(self.metadata_source),
            "target_details": [target.to_dict() for target in self.target_details],
            "default_target_index": self.default_target_index,
            "payload_discovery_status": self.payload_discovery_status.value,
            "payloads": [payload.to_dict() for payload in self.payloads],
        }


@dataclass(frozen=True)
class DiscoveryResult:
    cve_id: str
    status: DiscoveryStatus
    candidates: tuple[ModuleCandidate, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "status": self.status.value,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class CandidateRankingEvidence:
    reason: str
    weight: int
    matched: bool | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "weight": self.weight,
            "matched": self.matched,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RankedModuleCandidate:
    candidate: ModuleCandidate
    score: int
    evidence: tuple[CandidateRankingEvidence, ...]
    rank_position: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank_position": self.rank_position,
            "score": self.score,
            "candidate": self.candidate.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class CandidateRankingResult:
    cve_id: str
    ranked_candidates: tuple[RankedModuleCandidate, ...]
    ambiguity_status: CandidateAmbiguityStatus
    top_candidate_gap: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "ambiguity_status": self.ambiguity_status.value,
            "top_candidate_gap": self.top_candidate_gap,
            "ranked_candidates": [item.to_dict() for item in self.ranked_candidates],
        }
