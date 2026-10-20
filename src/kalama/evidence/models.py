"""Immutable evidence models; external content is data, never instructions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Mapping


EVIDENCE_PACK_SCHEMA = "kalama.evidence-pack/v1"


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (tuple, list, frozenset, set)):
        normalized = [_canonical(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True,
                                                               separators=(",", ":"),
                                                               ensure_ascii=False))
    if isinstance(value, Enum):
        return value.value
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class EvidencePurpose(str, Enum):
    EXPLOIT_CONFIGURATION = "EXPLOIT_CONFIGURATION"
    REMEDIATION = "REMEDIATION"
    EXPLOITATION_STATUS = "EXPLOITATION_STATUS"


class SourceKind(str, Enum):
    RUNTIME = "RUNTIME"
    KNOWLEDGE = "KNOWLEDGE"
    MSF_METADATA = "MSF_METADATA"
    MSF_MODULE_DOC = "MSF_MODULE_DOC"
    MSF_REFERENCE = "MSF_REFERENCE"
    VENDOR_UPSTREAM = "VENDOR_UPSTREAM"
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"


class EvidenceResultState(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    NO_AUTHORITATIVE_SOURCE = "NO_AUTHORITATIVE_SOURCE"
    REJECTED_BY_POLICY = "REJECTED_BY_POLICY"
    STALE_CACHE_FALLBACK = "STALE_CACHE_FALLBACK"


@dataclass(frozen=True)
class CandidateContext:
    """Isolation identity.

    ``run_id``, CVE, component, ecosystem, installed versions, image, target and
    phase and container participate in per-run pack isolation.  ``container_id``
    is not a cross-run reuse key: later compatibility adapters must compare the
    stable identity fields rather than equating an ephemeral container ID.
    """
    run_id: str
    vulnerability_id: str
    component: str
    ecosystem: str | None = None
    installed_versions: tuple[str, ...] = ()
    image_identity: str | None = None
    target_identity: str | None = None
    container_id: str | None = None
    phase: str = "before"

    def __post_init__(self) -> None:
        if not self.run_id or not self.vulnerability_id or not self.component or not self.phase:
            raise ValueError("candidate context requires run, vulnerability, component, and phase")
        object.__setattr__(self, "vulnerability_id", self.vulnerability_id.upper())
        object.__setattr__(self, "installed_versions", tuple(sorted(set(self.installed_versions))))

    def identity_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "vulnerability_id": self.vulnerability_id,
                "component": self.component, "ecosystem": self.ecosystem,
                "installed_versions": list(self.installed_versions),
                "image_identity": self.image_identity, "target_identity": self.target_identity,
                "phase": self.phase}

    def provenance_dict(self) -> dict[str, Any]:
        return {**self.identity_dict(), "container_id": self.container_id}

    @property
    def digest(self) -> str:
        """Canonical candidate binding digest.

        Covers the full provenance identity (run, CVE, component, ecosystem,
        installed versions, image/target identity, phase, container), so two
        candidates sharing a CVE but differing in component or version never
        share a binding.  Optional fields participate as explicit nulls;
        nothing is fabricated.
        """
        return hashlib.sha256(canonical_bytes(self.provenance_dict())).hexdigest()


@dataclass(frozen=True)
class FieldRequest:
    context: CandidateContext
    purpose: EvidencePurpose
    unresolved_fields: tuple[str, ...]
    resolved_fields: Mapping[str, Any] = field(default_factory=dict)
    enabled_sources: frozenset[SourceKind] = frozenset(SourceKind)

    def __post_init__(self) -> None:
        unresolved = tuple(sorted(set(self.unresolved_fields)))
        if not unresolved:
            raise ValueError("field request requires unresolved fields")
        if set(unresolved) & set(self.resolved_fields):
            raise ValueError("a field cannot be resolved and unresolved")
        object.__setattr__(self, "unresolved_fields", unresolved)
        object.__setattr__(self, "enabled_sources", frozenset(self.enabled_sources))


@dataclass(frozen=True)
class EvidenceItem:
    context: CandidateContext
    source_kind: SourceKind
    authority: str
    resource_identity: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    normalized_content: str | None = None
    snapshot_sha256: str | None = None
    retrieved_at: str | None = None
    source_modified_at: str | None = None
    provenance_ref: str | None = None
    cache_status: str | None = None

    def __post_init__(self) -> None:
        if not self.authority or not self.resource_identity:
            raise ValueError("evidence item requires authority and resource identity")
        if self.snapshot_sha256 is not None and len(self.snapshot_sha256) != 64:
            raise ValueError("snapshot SHA-256 must be a 64 character digest")

    def to_dict(self) -> dict[str, Any]:
        return {"context": self.context.provenance_dict(), "source_kind": self.source_kind.value,
                "authority": self.authority, "resource_identity": self.resource_identity,
                "facts": _canonical(self.facts), "normalized_content": self.normalized_content,
                "snapshot_sha256": self.snapshot_sha256, "retrieved_at": self.retrieved_at,
                "source_modified_at": self.source_modified_at,
                "provenance_ref": self.provenance_ref, "cache_status": self.cache_status}


@dataclass(frozen=True)
class EvidenceResult:
    state: EvidenceResultState
    source_kind: SourceKind
    items: tuple[EvidenceItem, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.state in {EvidenceResultState.AVAILABLE, EvidenceResultState.STALE_CACHE_FALLBACK} and not self.items:
            raise ValueError("available evidence result requires evidence items")
        if self.state not in {EvidenceResultState.AVAILABLE, EvidenceResultState.STALE_CACHE_FALLBACK} and self.items:
            raise ValueError("non-available evidence result cannot contain items")
        if any(item.source_kind != self.source_kind for item in self.items):
            raise ValueError("result items must match result source kind")


@dataclass(frozen=True)
class EvidencePack:
    request: FieldRequest
    items: tuple[EvidenceItem, ...]
    snapshot_refs: tuple[str, ...] = ()
    schema: str = EVIDENCE_PACK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != EVIDENCE_PACK_SCHEMA:
            raise ValueError("unsupported evidence pack schema")
        if any(item.context != self.request.context for item in self.items):
            raise ValueError("evidence item context does not match evidence pack context")
        refs = set(self.snapshot_refs)
        refs.update(item.snapshot_sha256 for item in self.items if item.snapshot_sha256)
        object.__setattr__(self, "snapshot_refs", tuple(sorted(refs)))

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "context": self.request.context.provenance_dict(),
                "purpose": self.request.purpose.value,
                "resolved_fields": _canonical(self.request.resolved_fields),
                "unresolved_fields": list(self.request.unresolved_fields),
                "enabled_sources": sorted(source.value for source in self.request.enabled_sources),
                "items": [item.to_dict() for item in self.items],
                "snapshot_refs": list(self.snapshot_refs)}

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()
