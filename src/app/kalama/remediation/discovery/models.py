"""Deterministic remediation discovery contracts.

These models capture the distinction between classification, version resolution,
candidate resolution, and execution readiness that the feasibility experiment
established as independent concepts. Nothing here performs mutation; every derived
fact carries provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ProvenanceCategory(str, Enum):
    SCANNER_EVIDENCE = "SCANNER_EVIDENCE"
    LOCAL_IMAGE_METADATA = "LOCAL_IMAGE_METADATA"
    LOCAL_SOURCE_METADATA = "LOCAL_SOURCE_METADATA"
    PACKAGE_MANAGER_METADATA = "PACKAGE_MANAGER_METADATA"
    CONTAINER_REGISTRY_METADATA = "CONTAINER_REGISTRY_METADATA"
    UPSTREAM_MACHINE_READABLE_METADATA = "UPSTREAM_MACHINE_READABLE_METADATA"
    HUMAN = "HUMAN"


class DiscoveryClassification(str, Enum):
    """The conceptual shape of a remediation target."""

    OS_PACKAGE = "OS_PACKAGE"
    SOURCE_BUILD = "SOURCE_BUILD"
    PREBUILT_IMAGE = "PREBUILT_IMAGE"
    UNSUPPORTED = "UNSUPPORTED"
    UNCLASSIFIED = "UNCLASSIFIED"


class ClassificationStatus(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIAL = "PARTIAL"
    UNRESOLVED = "UNRESOLVED"
    KNOWLEDGE_REQUIRED = "KNOWLEDGE_REQUIRED"
    UNSUPPORTED = "UNSUPPORTED"


class VersionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIAL = "PARTIAL"
    UNRESOLVED = "UNRESOLVED"
    NONE = "NONE"


class CandidateStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    PARTIAL = "PARTIAL"
    KNOWLEDGE_REQUIRED = "KNOWLEDGE_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    NONE = "NONE"


class ExecutionReadiness(str, Enum):
    READY = "READY"
    NOT_READY = "NOT_READY"
    HUMAN_CONFIRMATION_REQUIRED = "HUMAN_CONFIRMATION_REQUIRED"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"


class AvailabilityStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    EOL_REPOSITORY = "EOL_REPOSITORY"
    PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES = "PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES"
    QUERY_TIMEOUT = "QUERY_TIMEOUT"
    QUERY_ERROR = "QUERY_ERROR"
    NOT_CHECKED = "NOT_CHECKED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class DiscoveryEvidence:
    """One derivable fact with the provenance category that produced it."""

    fact: str
    provenance: ProvenanceCategory
    value: Any = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"fact": self.fact, "provenance": self.provenance.value,
                "value": self.value, "detail": self.detail}


@dataclass(frozen=True)
class AvailabilityResult:
    """Result of a non-mutating package-manager availability probe."""

    candidate_version: str | None
    status: AvailabilityStatus
    query: str | None = None
    repository_context: str | None = None
    evidence_or_error: str | None = None
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"candidate_version": self.candidate_version,
                "status": self.status.value, "query": self.query,
                "repository_context": self.repository_context,
                "evidence_or_error": self.evidence_or_error,
                "elapsed_seconds": self.elapsed_seconds}


@dataclass(frozen=True)
class DiscoveredCandidate:
    """A candidate that deterministic discovery produced (AUTO / SUGGESTED, never HUMAN)."""

    cve_id: str
    classification: DiscoveryClassification
    fix_type: str | None
    strategy: str | None
    package_or_product: str | None
    current_version: str | None
    fixed_version: str | None
    classification_status: ClassificationStatus
    version_status: VersionStatus
    candidate_status: CandidateStatus
    execution_readiness: ExecutionReadiness
    availability: AvailabilityResult | None
    packages: tuple[str, ...] = ()
    installed_versions: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    package_manager: str | None = None
    build_system: str | None = None
    target: str | None = None
    source_identifier: str | None = None
    same_branch: bool | None = None
    branch_reason: str | None = None
    eol: bool = False
    evidence: tuple[DiscoveryEvidence, ...] = ()
    issue: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"cve_id": self.cve_id, "classification": self.classification.value,
                "fix_type": self.fix_type, "strategy": self.strategy,
                "package_or_product": self.package_or_product,
                "current_version": self.current_version, "fixed_version": self.fixed_version,
                "classification_status": self.classification_status.value,
                "version_status": self.version_status.value,
                "candidate_status": self.candidate_status.value,
                "execution_readiness": self.execution_readiness.value,
                "packages": list(self.packages),
                "installed_versions": list(self.installed_versions),
                "fixed_versions": list(self.fixed_versions),
                "package_manager": self.package_manager,
                "build_system": self.build_system, "target": self.target,
                "source_identifier": self.source_identifier,
                "same_branch": self.same_branch, "branch_reason": self.branch_reason,
                "eol": self.eol, "issue": self.issue,
                "availability": self.availability.to_dict() if self.availability else None,
                "evidence": [e.to_dict() for e in self.evidence]}
