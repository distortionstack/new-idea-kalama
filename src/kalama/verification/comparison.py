"""Pure scanner-level comparison; no execution, enrichment, or filesystem access."""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from ..prioritizer.models import ParseResult, VulnerabilityOccurrence
from ..prioritizer.trivy_parser import canonicalize_cve


class AfterScanStatus(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


def _group(occurrences: Iterable[VulnerabilityOccurrence]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for occurrence in occurrences:
        grouped.setdefault(occurrence.canonical_cve_id, []).append(occurrence.to_dict())
    for values in grouped.values():
        values.sort(key=lambda item: (
            item.get("target") or "", item.get("result_type") or "",
            item.get("package_purl") or item.get("package_name") or "",
            item.get("installed_version") or ""))
    return grouped


def _package_key(occurrence: Mapping[str, Any]) -> str | None:
    value = occurrence.get("package_purl") or occurrence.get("package_name")
    return str(value) if value else None


def _material_ambiguity(parsed: ParseResult) -> bool:
    if parsed.warnings:
        return True
    return any(item.reason in {"MALFORMED_CVE_IDENTIFIER", "INVALID_FINDING"}
               for item in parsed.excluded_findings)


def compare_remediation_targets(
        intended_targets: Iterable[str], incidental_targets: Iterable[str],
        before: ParseResult, after: ParseResult,
        *, action_results: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Compare canonical CVEs independently; versions are evidence, never the oracle."""
    before_by_cve, after_by_cve = _group(before.occurrences), _group(after.occurrences)
    after_packages = {_package_key(item) for values in after_by_cve.values() for item in values}
    ambiguous = _material_ambiguity(after)
    action_results = action_results or {}

    def one(cve_id: str, intent: str) -> dict[str, Any]:
        canonical = canonicalize_cve(cve_id)
        before_occurrences = before_by_cve.get(canonical or "", [])
        after_occurrences = after_by_cve.get(canonical or "", [])
        if canonical is None:
            status = AfterScanStatus.UNKNOWN
        elif after_occurrences:
            status = AfterScanStatus.FOUND
        elif ambiguous:
            status = AfterScanStatus.UNKNOWN
        else:
            status = AfterScanStatus.NOT_FOUND
        package_presence = []
        for occurrence in before_occurrences:
            key = _package_key(occurrence)
            package_presence.append({"package": key,
                                     "package_presence_after": (
                                         "FOUND" if key and key in after_packages else "NOT_FOUND")})
        return {"cve_id": canonical or str(cve_id), "intent": intent,
                "scanner_status": status.value,
                "patch_action_status": action_results.get(canonical or str(cve_id)),
                "before_occurrences": before_occurrences,
                "after_occurrences": after_occurrences,
                "package_comparison": package_presence,
                "scanner_remediation_verified": status == AfterScanStatus.NOT_FOUND,
                "empirical_remediation_verified": False}

    intended = [one(cve, "INTENDED") for cve in sorted(set(intended_targets))]
    incidental = [one(cve, "INCIDENTAL") for cve in
                  sorted(set(incidental_targets) - set(intended_targets))]
    summary = {"intended_total": len(intended)}
    for status in AfterScanStatus:
        summary[status.value.casefold()] = sum(
            item["scanner_status"] == status.value for item in intended)
    if sum(summary[key] for key in ("found", "not_found", "unknown")) != len(intended):
        raise ValueError("inconsistent scanner summary")
    return {"intended_targets": intended, "incidental_effects": incidental,
            "summary": summary}
