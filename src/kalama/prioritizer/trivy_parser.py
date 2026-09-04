"""Semantic parsing and unique-CVE aggregation for validated Trivy JSON."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal, InvalidOperation
import re
from typing import Any, Iterable

from .models import (
    AggregatedCVE, CVSSCandidate, ExcludedFinding, FailureCode, ParseResult,
    StageIssue, VulnerabilityOccurrence,
)


CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


class TrivyArtifactError(ValueError):
    def __init__(self, issue: StageIssue):
        super().__init__(issue.message)
        self.issue = issue


def canonicalize_cve(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if CVE_RE.fullmatch(candidate) else None


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(sorted({str(item) for item in value if isinstance(item, str) and item}))


def _aliases(finding: dict[str, Any]) -> tuple[str, ...]:
    raw: list[Any] = []
    for key in ("Aliases", "aliases", "VendorIDs"):
        value = finding.get(key)
        if isinstance(value, list):
            raw.extend(value)
    return tuple(sorted({cve for item in raw if (cve := canonicalize_cve(item))}))


def _decimal_score(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return score if score.is_finite() and Decimal("0") <= score <= Decimal("10") else None


def _version_for(key: str, vector: Any) -> str | None:
    if key == "V40Score":
        return "4.0" if not vector or str(vector).startswith("CVSS:4.0/") else None
    if key == "V3Score":
        if not vector:
            return None
        text = str(vector)
        if text.startswith("CVSS:3.1/"):
            return "3.1"
        if text.startswith("CVSS:3.0/"):
            return "3.0"
        return None
    if key == "V2Score":
        return "2.0" if not vector or not str(vector).startswith("CVSS:") else None
    return None


def parse_cvss_candidates(raw: Any, source_url: str | None = None) -> tuple[CVSSCandidate, ...]:
    if not isinstance(raw, dict):
        return ()
    candidates = []
    for authority in sorted(raw, key=lambda x: str(x).casefold()):
        values = raw[authority]
        if not isinstance(values, dict):
            continue
        for score_key, vector_key in (("V40Score", "V40Vector"),
                                      ("V3Score", "V3Vector"),
                                      ("V2Score", "V2Vector")):
            if score_key not in values:
                continue
            vector = values.get(vector_key)
            score = _decimal_score(values.get(score_key))
            version = _version_for(score_key, vector)
            if score is not None and version is not None:
                candidates.append(CVSSCandidate(
                    authority=str(authority).lower(), version=version, score=score,
                    vector=str(vector) if vector is not None else None,
                    source_url=source_url,
                ))
    return tuple(candidates)


def _finding_cve(finding: dict[str, Any]) -> tuple[str | None, tuple[str, ...]]:
    raw_id = finding.get("VulnerabilityID")
    canonical = canonicalize_cve(raw_id)
    aliases = _aliases(finding)
    if canonical:
        return canonical, aliases
    return (aliases[0], aliases) if aliases else (None, ())


def parse_trivy_report(data: Any) -> ParseResult:
    if not isinstance(data, dict):
        raise TrivyArtifactError(StageIssue(
            FailureCode.INVALID_TRIVY_ARTIFACT, "trivy_parse", "Trivy artifact must be a JSON object"))
    results = data.get("Results")
    if not isinstance(results, list):
        raise TrivyArtifactError(StageIssue(
            FailureCode.INVALID_TRIVY_ARTIFACT, "trivy_parse", "Trivy artifact Results must be an array"))
    schema = data.get("SchemaVersion")
    if schema != 2:
        raise TrivyArtifactError(StageIssue(
            FailureCode.UNSUPPORTED_TRIVY_SCHEMA, "trivy_parse",
            f"supported Trivy SchemaVersion is 2, got {schema!r}"))

    occurrences: list[VulnerabilityOccurrence] = []
    excluded: list[ExcludedFinding] = []
    warnings: list[StageIssue] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            warnings.append(StageIssue(FailureCode.TRIVY_FINDING_INVALID, "trivy_parse",
                                       f"Results[{result_index}] is not an object"))
            continue
        target = result.get("Target")
        raw_findings = result.get("Vulnerabilities")
        if raw_findings is None:
            continue
        if not isinstance(raw_findings, list):
            warnings.append(StageIssue(FailureCode.TRIVY_FINDING_INVALID, "trivy_parse",
                                       f"Vulnerabilities in Results[{result_index}] is not an array"))
            continue
        for finding_index, finding in enumerate(raw_findings):
            if not isinstance(finding, dict):
                excluded.append(ExcludedFinding(None, "INVALID_FINDING", target,
                                f"finding {finding_index} is not an object"))
                continue
            raw_id = finding.get("VulnerabilityID")
            cve_id, aliases = _finding_cve(finding)
            if cve_id is None:
                raw_text = str(raw_id) if raw_id is not None else None
                reason = "MALFORMED_CVE_IDENTIFIER" if raw_text and raw_text.upper().startswith("CVE-") else "NON_CVE_IDENTIFIER"
                excluded.append(ExcludedFinding(raw_text, reason, target))
                continue
            package_identifier = finding.get("PkgIdentifier")
            package_identifier = package_identifier if isinstance(package_identifier, dict) else {}
            fixed_raw = finding.get("FixedVersion")
            fixed = tuple(x.strip() for x in str(fixed_raw or "").split(",") if x.strip())
            source = finding.get("DataSource")
            source = dict(source) if isinstance(source, dict) else None
            primary_url = finding.get("PrimaryURL")
            occurrences.append(VulnerabilityOccurrence(
                vulnerability_id_raw=str(raw_id), canonical_cve_id=cve_id, aliases=aliases,
                package_name=_optional_string(finding.get("PkgName")),
                installed_version=_optional_string(finding.get("InstalledVersion")),
                fixed_versions=fixed, package_purl=_optional_string(package_identifier.get("PURL")),
                package_uid=_optional_string(package_identifier.get("UID")),
                target=_optional_string(target), result_class=_optional_string(result.get("Class")),
                result_type=_optional_string(result.get("Type")),
                scanner_severity=_optional_string(finding.get("Severity")),
                scanner_severity_source=_optional_string(finding.get("SeveritySource")),
                scanner_cvss_candidates=parse_cvss_candidates(finding.get("CVSS"), _optional_string(primary_url)),
                primary_url=_optional_string(primary_url), data_source=source,
                references=_strings(finding.get("References")),
                published_at=_optional_string(finding.get("PublishedDate")),
                modified_at=_optional_string(finding.get("LastModifiedDate")),
            ))
    trivy = data.get("Trivy") if isinstance(data.get("Trivy"), dict) else {}
    return ParseResult(
        schema_version=schema, trivy_version=_optional_string(trivy.get("Version")),
        artifact_name=_optional_string(data.get("ArtifactName")),
        artifact_id=_optional_string(data.get("ArtifactID")),
        report_id=_optional_string(data.get("ReportID")), created_at=_optional_string(data.get("CreatedAt")),
        occurrences=tuple(occurrences), excluded_findings=tuple(sorted(
            excluded, key=lambda x: (x.target or "", x.vulnerability_id_raw or "", x.reason))),
        warnings=tuple(warnings),
    )


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _occurrence_sort_key(item: VulnerabilityOccurrence) -> tuple[Any, ...]:
    return item.identity + (item.vulnerability_id_raw,)


def aggregate_unique_cves(occurrences: Iterable[VulnerabilityOccurrence]) -> tuple[AggregatedCVE, ...]:
    deduplicated: dict[tuple[Any, ...], VulnerabilityOccurrence] = {}
    for occurrence in occurrences:
        existing = deduplicated.get(occurrence.identity)
        if existing is None:
            deduplicated[occurrence.identity] = occurrence
            continue
        candidates = {repr(x.to_dict()): x for x in existing.scanner_cvss_candidates + occurrence.scanner_cvss_candidates}
        deduplicated[occurrence.identity] = replace(
            existing, duplicate_count=existing.duplicate_count + occurrence.duplicate_count,
            aliases=tuple(sorted(set(existing.aliases + occurrence.aliases))),
            references=tuple(sorted(set(existing.references + occurrence.references))),
            scanner_cvss_candidates=tuple(candidates[k] for k in sorted(candidates)),
        )
    grouped: dict[str, list[VulnerabilityOccurrence]] = {}
    for occurrence in deduplicated.values():
        grouped.setdefault(occurrence.canonical_cve_id, []).append(occurrence)
    return tuple(AggregatedCVE(cve, tuple(sorted(grouped[cve], key=_occurrence_sort_key)))
                 for cve in sorted(grouped))
