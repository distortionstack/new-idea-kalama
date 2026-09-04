"""Immutable data contracts for Kalama Pipeline Step 3."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any


class EvidenceState(str, Enum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    LOOKUP_FAILED = "LOOKUP_FAILED"
    INVALID = "INVALID"


class KEVState(str, Enum):
    LISTED = "LISTED"
    NOT_LISTED = "NOT_LISTED"
    LOOKUP_FAILED = "LOOKUP_FAILED"


class ExposureState(str, Enum):
    OBSERVED = "OBSERVED"
    PARTIAL = "PARTIAL"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"


class FailureCode(str, Enum):
    INVALID_TRIVY_ARTIFACT = "INVALID_TRIVY_ARTIFACT"
    UNSUPPORTED_TRIVY_SCHEMA = "UNSUPPORTED_TRIVY_SCHEMA"
    TRIVY_FINDING_INVALID = "TRIVY_FINDING_INVALID"
    CVSS_UNAVAILABLE = "CVSS_UNAVAILABLE"
    CVSS_LOOKUP_FAILED = "CVSS_LOOKUP_FAILED"
    EPSS_MISSING = "EPSS_MISSING"
    EPSS_LOOKUP_FAILED = "EPSS_LOOKUP_FAILED"
    KEV_CATALOG_FAILED = "KEV_CATALOG_FAILED"
    KEV_CATALOG_INVALID = "KEV_CATALOG_INVALID"
    ENRICHMENT_INCOMPLETE = "ENRICHMENT_INCOMPLETE"
    EXPOSURE_INPUT_INVALID = "EXPOSURE_INPUT_INVALID"
    SCORING_INPUT_INVALID = "SCORING_INPUT_INVALID"
    OUTPUT_VALIDATION_FAILED = "OUTPUT_VALIDATION_FAILED"
    OUTPUT_WRITE_FAILED = "OUTPUT_WRITE_FAILED"


def decimal_text(value: Decimal) -> str:
    return format(value, "f")


@dataclass(frozen=True)
class StageIssue:
    code: FailureCode
    stage: str
    message: str
    cve_id: str | None = None
    retryable: bool = False
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value, "stage": self.stage, "message": self.message,
            "cve_id": self.cve_id, "retryable": self.retryable, "provider": self.provider,
        }


@dataclass(frozen=True)
class CVSSCandidate:
    authority: str
    version: str
    score: Decimal
    vector: str | None = None
    transport_source: str = "trivy_embedded"
    source_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority": self.authority, "version": self.version,
            "score": decimal_text(self.score), "vector": self.vector,
            "transport_source": self.transport_source, "source_url": self.source_url,
        }


@dataclass(frozen=True)
class VulnerabilityOccurrence:
    vulnerability_id_raw: str
    canonical_cve_id: str
    aliases: tuple[str, ...]
    package_name: str | None
    installed_version: str | None
    fixed_versions: tuple[str, ...]
    package_purl: str | None
    package_uid: str | None
    target: str | None
    result_class: str | None
    result_type: str | None
    scanner_severity: str | None
    scanner_severity_source: str | None
    scanner_cvss_candidates: tuple[CVSSCandidate, ...]
    primary_url: str | None
    data_source: dict[str, Any] | None
    references: tuple[str, ...]
    published_at: str | None
    modified_at: str | None
    duplicate_count: int = 1

    @property
    def identity(self) -> tuple[Any, ...]:
        return (
            self.canonical_cve_id, self.target or "", self.result_class or "",
            self.result_type or "", self.package_purl or self.package_name or "",
            self.installed_version or "", self.fixed_versions,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_id_raw": self.vulnerability_id_raw,
            "canonical_cve_id": self.canonical_cve_id, "aliases": list(self.aliases),
            "package_name": self.package_name, "installed_version": self.installed_version,
            "fixed_versions": list(self.fixed_versions), "package_purl": self.package_purl,
            "package_uid": self.package_uid, "target": self.target,
            "result_class": self.result_class, "result_type": self.result_type,
            "scanner_severity": self.scanner_severity,
            "scanner_severity_source": self.scanner_severity_source,
            "scanner_cvss_candidates": [x.to_dict() for x in self.scanner_cvss_candidates],
            "primary_url": self.primary_url, "data_source": self.data_source,
            "references": list(self.references), "published_at": self.published_at,
            "modified_at": self.modified_at, "duplicate_count": self.duplicate_count,
        }


@dataclass(frozen=True)
class ExcludedFinding:
    vulnerability_id_raw: str | None
    reason: str
    target: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"vulnerability_id_raw": self.vulnerability_id_raw, "reason": self.reason,
                "target": self.target, "message": self.message}


@dataclass(frozen=True)
class AggregatedCVE:
    cve_id: str
    occurrences: tuple[VulnerabilityOccurrence, ...]


@dataclass(frozen=True)
class CVSSRecord:
    state: EvidenceState
    score: Decimal | None = None
    version: str | None = None
    authority: str | None = None
    vector: str | None = None
    transport_source: str | None = None
    source_url: str | None = None
    selected_by_policy: str = "nvd-source-first-v1"

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value,
                "score": decimal_text(self.score) if self.score is not None else None,
                "version": self.version, "authority": self.authority, "vector": self.vector,
                "transport_source": self.transport_source, "source_url": self.source_url,
                "selected_by_policy": self.selected_by_policy}


@dataclass(frozen=True)
class EPSSRecord:
    state: EvidenceState
    score: Decimal | None = None
    percentile: Decimal | None = None
    data_date: str | None = None
    retrieved_at: str | None = None
    source: str = "FIRST"
    as_of_date: str | None = None
    date_resolution: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value,
                "score": decimal_text(self.score) if self.score is not None else None,
                "percentile": decimal_text(self.percentile) if self.percentile is not None else None,
                "data_date": self.data_date, "effective_date": self.data_date,
                "as_of_date": self.as_of_date,
                "date_resolution": self.date_resolution,
                "retrieved_at": self.retrieved_at, "source": self.source}


@dataclass(frozen=True)
class KEVCatalogSnapshot:
    state: EvidenceState
    cve_ids: frozenset[str] = frozenset()
    catalog_version: str | None = None
    date_released: str | None = None
    retrieved_at: str | None = None
    source: str = "CISA"
    sha256: str | None = None
    count: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    cache_status: str | None = None

    def provenance_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "catalog_version": self.catalog_version,
                "date_released": self.date_released, "retrieved_at": self.retrieved_at,
                "source": self.source, "sha256": self.sha256, "count": self.count,
                "etag": self.etag, "last_modified": self.last_modified,
                "cache_status": self.cache_status}


@dataclass(frozen=True)
class KEVRecord:
    state: KEVState
    listed: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "listed": self.listed}


@dataclass(frozen=True)
class ExposureContext:
    state: ExposureState = ExposureState.UNKNOWN
    evidence: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "score": None,
                "classification": "TARGET_CONTEXT_ONLY", "evidence": list(self.evidence)}


@dataclass(frozen=True)
class ScoreBreakdown:
    cvss: Decimal
    epss_raw: Decimal
    epss_contribution: Decimal
    kev_listed: bool
    kev_contribution: Decimal
    total_raw: Decimal
    total_display: Decimal
    model: str = "kalama-priority-v1"

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model, "components": {
            "cvss": decimal_text(self.cvss),
            "epss": {"raw": decimal_text(self.epss_raw), "weight": "3",
                     "contribution": decimal_text(self.epss_contribution)},
            "kev": {"listed": self.kev_listed,
                    "contribution": decimal_text(self.kev_contribution)}},
            "total_raw": decimal_text(self.total_raw),
            "total_display": decimal_text(self.total_display)}


@dataclass(frozen=True)
class EnrichedCVE:
    aggregate: AggregatedCVE
    cvss: CVSSRecord
    epss: EPSSRecord
    kev: KEVRecord
    exposure: ExposureContext = ExposureContext()


@dataclass(frozen=True)
class PrioritizedCVE:
    rank: int
    enriched: EnrichedCVE
    score: ScoreBreakdown

    def to_dict(self) -> dict[str, Any]:
        scanner_context = sorted({
            (o.scanner_severity or "", o.scanner_severity_source or "")
            for o in self.enriched.aggregate.occurrences
        })
        return {"rank": self.rank, "cve_id": self.enriched.aggregate.cve_id,
                "occurrences": [x.to_dict() for x in self.enriched.aggregate.occurrences],
                "scanner_context": [{"severity": x, "source": y} for x, y in scanner_context],
                "cvss": self.enriched.cvss.to_dict(), "epss": self.enriched.epss.to_dict(),
                "kev": self.enriched.kev.to_dict(), "exposure": self.enriched.exposure.to_dict(),
                "score": self.score.to_dict()}


@dataclass(frozen=True)
class ParseResult:
    schema_version: int
    trivy_version: str | None
    artifact_name: str | None
    artifact_id: str | None
    report_id: str | None
    created_at: str | None
    occurrences: tuple[VulnerabilityOccurrence, ...]
    excluded_findings: tuple[ExcludedFinding, ...]
    warnings: tuple[StageIssue, ...] = ()


@dataclass(frozen=True)
class PrioritizationResult:
    success: bool
    ranked_cves: tuple[PrioritizedCVE, ...] = ()
    issues: tuple[StageIssue, ...] = ()
    artifact: dict[str, Any] | None = None
