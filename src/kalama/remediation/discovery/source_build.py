"""Deterministic source/dependency build discovery.

This provider is proposal-only. It may derive a REBUILD candidate (with target
version, manifest evidence, build system) when a local manifest provides all
coordinates, but it never executes a build and never emits an executable candidate.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .models import (
    CandidateStatus, ClassificationStatus, DiscoveredCandidate, DiscoveryClassification,
    DiscoveryEvidence, ExecutionReadiness, ProvenanceCategory, VersionStatus,
)

MAVEN_TYPES = {"jar", "javapkg", "pom", "maven"}


def _is_lang_pkg(occurrence: Mapping[str, Any]) -> bool:
    result_class = str(occurrence.get("result_class") or "").casefold()
    result_type = str(occurrence.get("result_type") or "").casefold()
    return result_class == "lang-pkgs" or result_type in MAVEN_TYPES


def _maven_coordinates(purl: str | None) -> tuple[str | None, str | None]:
    """Extract (groupId, artifactId) from a Maven PURL: pkg:maven/<group>/<artifact>@<ver>."""
    if not purl:
        return None, None
    try:
        rest = purl.split(":", 1)[1]
        body = rest.split("@", 1)[0]
        parts = body.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None, parts[0] if parts else None
    except Exception:
        return None, None


def _select_target(purl: str | None, installed: str | None,
                   fixed_versions: Sequence[str]) -> tuple[str | None, bool | None, str | None]:
    """Same-(major,preferably minor)-branch selection, never a silent major jump."""
    if not fixed_versions:
        return None, None, "no fixed version in scanner evidence"
    if not installed:
        return None, None, "installed version unknown; branch ambiguous"
    installed_major = installed.split(".", 1)[0]
    matches = [v for v in fixed_versions if v.split(".", 1)[0] == installed_major]
    if not matches:
        return None, False, "no fixed version on installed major branch"

    def key(v):
        return tuple(int(x) for x in re.findall(r"\d+", v) or [0])

    installed_parts = installed.split(".")
    installed_minor = installed_parts[1] if len(installed_parts) > 1 else None
    minor_matches = [v for v in matches
                     if installed_minor is not None
                     and (v.split(".")[1] if v.count(".") >= 1 else None) == installed_minor]
    if minor_matches:
        return min(minor_matches, key=key), True, "same major AND minor release branch match"
    return min(matches, key=key), True, "same major release branch; no minor match, chose lowest fixed"


class SourceBuildProvider:
    """Proposal-only source build discovery (Maven first). Never executes a build."""

    def __init__(self, *, source_root: str | None = None):
        self.source_root = source_root

    def supports(self, occurrence: Mapping[str, Any]) -> bool:
        return _is_lang_pkg(occurrence)

    def discover(self, cve_id: str, occurrences: Sequence[Mapping[str, Any]],
                 local_manifests: Sequence[Mapping[str, Any]] | None = None) -> DiscoveredCandidate:
        lang_occurrences = [x for x in occurrences if _is_lang_pkg(x)]
        if not lang_occurrences:
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.UNCLASSIFIED, None, "REBUILD", None, None, None,
                ClassificationStatus.UNRESOLVED, VersionStatus.NONE, CandidateStatus.NONE,
                ExecutionReadiness.NOT_READY, None, issue="no language package evidence")

        manifests = tuple(local_manifests or ())
        pom_evidence = tuple(DiscoveryEvidence(
            "local_manifest", ProvenanceCategory.LOCAL_SOURCE_METADATA, m.get("name"),
            m.get("detail")) for m in manifests if m.get("name"))
        evidence = list(pom_evidence)

        # We report per-occurrence discovery; combine into a single proposal.
        proposals = []
        for occurrence in lang_occurrences:
            proposals.append(self._discover_one(cve_id, occurrence, evidence))
        first = proposals[0]
        if any(p.classification == DiscoveryClassification.UNSUPPORTED for p in proposals):
            return proposals[0]
        all_prebuilt = all(p.classification == DiscoveryClassification.PREBUILT_IMAGE
                           for p in proposals)
        if all_prebuilt:
            combined = first
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.PREBUILT_IMAGE, "B",
                "PREBUILT_IMAGE_REPLACEMENT", first.package_or_product,
                first.current_version, first.fixed_version,
                first.classification_status, first.version_status,
                first.candidate_status, ExecutionReadiness.NOT_READY, None,
                packages=tuple(sorted({p.package_or_product for p in proposals
                                       if p.package_or_product})),
                installed_versions=tuple(sorted({p.current_version for p in proposals
                                                 if p.current_version})),
                fixed_versions=tuple(sorted({p.fixed_version for p in proposals
                                             if p.fixed_version})),
                build_system=None, same_branch=first.same_branch,
                branch_reason=first.branch_reason, source_identifier=None,
                evidence=tuple(evidence), issue=first.issue)
        all_available = all(p.candidate_status == CandidateStatus.DISCOVERED for p in proposals)
        return DiscoveredCandidate(
            cve_id, DiscoveryClassification.SOURCE_BUILD, "A", "REBUILD",
            first.package_or_product, first.current_version, first.fixed_version,
            ClassificationStatus.RESOLVED if all_available else ClassificationStatus.PARTIAL,
            first.version_status,
            CandidateStatus.DISCOVERED if all_available else CandidateStatus.KNOWLEDGE_REQUIRED,
            ExecutionReadiness.NOT_READY, None,
            packages=tuple(sorted({p.package_or_product for p in proposals
                                   if p.package_or_product})),
            installed_versions=tuple(sorted({p.current_version for p in proposals
                                             if p.current_version})),
            fixed_versions=tuple(sorted({p.fixed_version for p in proposals if p.fixed_version})),
            build_system="maven", same_branch=first.same_branch,
            branch_reason=first.branch_reason,
            source_identifier=first.source_identifier,
            evidence=tuple(evidence))

    def _discover_one(self, cve_id: str, occurrence: Mapping[str, Any],
                      evidence: list[DiscoveryEvidence]) -> DiscoveredCandidate:
        package = str(occurrence.get("package_name") or "")
        purl = occurrence.get("package_purl")
        installed = occurrence.get("installed_version")
        fixed_versions = tuple(x for x in (occurrence.get("fixed_versions") or ())
                               if isinstance(x, str))
        coordinate = _maven_coordinates(purl)
        evidence.append(DiscoveryEvidence(
            "package", ProvenanceCategory.SCANNER_EVIDENCE, package))
        evidence.append(DiscoveryEvidence(
            "maven_purl", ProvenanceCategory.SCANNER_EVIDENCE, purl))
        evidence.append(DiscoveryEvidence(
            "installed_version", ProvenanceCategory.SCANNER_EVIDENCE, installed))
        evidence.append(DiscoveryEvidence(
            "fixed_versions", ProvenanceCategory.SCANNER_EVIDENCE, list(fixed_versions)))

        target, same_branch, reason = _select_target(purl, installed, fixed_versions)
        if target:
            evidence.append(DiscoveryEvidence(
                "fixed_version", ProvenanceCategory.SCANNER_EVIDENCE, target))
            evidence.append(DiscoveryEvidence(
                "branch_policy", ProvenanceCategory.SCANNER_EVIDENCE, reason))
        if not evidence or not any(e.fact == "local_manifest" for e in evidence):
            # No local source/build manifest: a rebuild cannot be reconstructed and no
            # trusted replacement image mapping exists. This is the CVE-2017-9805
            # boundary: classification PREBUILT_IMAGE, knowledge required, no candidate.
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.PREBUILT_IMAGE, "B", "PREBUILT_IMAGE_REPLACEMENT",
                package, installed, target,
                ClassificationStatus.RESOLVED if target else ClassificationStatus.PARTIAL,
                VersionStatus.RESOLVED if target else VersionStatus.UNRESOLVED,
                CandidateStatus.KNOWLEDGE_REQUIRED, ExecutionReadiness.NOT_READY, None,
                packages=(package,), installed_versions=(installed,) if installed else (),
                fixed_versions=tuple(fixed_versions), build_system=None,
                source_identifier=None, same_branch=same_branch, branch_reason=reason,
                evidence=tuple(evidence),
                issue=("dependency coordinates present but no local source/build manifest "
                       "and no trusted replacement-image mapping"))
        return DiscoveredCandidate(
            cve_id, DiscoveryClassification.SOURCE_BUILD, "A", "REBUILD",
            package, installed, target, ClassificationStatus.RESOLVED,
            VersionStatus.RESOLVED if target else VersionStatus.PARTIAL,
            CandidateStatus.DISCOVERED, ExecutionReadiness.HUMAN_CONFIRMATION_REQUIRED, None,
            packages=(package,), installed_versions=(installed,) if installed else (),
            fixed_versions=tuple(fixed_versions), build_system="maven",
            source_identifier=coordinate and f"{coordinate[0]}:{coordinate[1]}",
            same_branch=same_branch, branch_reason=reason,
            evidence=tuple(evidence))
