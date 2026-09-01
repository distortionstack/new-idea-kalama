"""Deterministic OS-package remediation discovery.

Only OS-package candidates whose exact fixed version is proven available through a
non-mutating package-manager query become executable. A scanner-reported FixedVersion
is evidence of a fixed version, not proof of current installability.
"""

from __future__ import annotations

import re
import time
from typing import Any, Mapping, Sequence

from .models import (
    AvailabilityResult, AvailabilityStatus, CandidateStatus, ClassificationStatus,
    DiscoveredCandidate, DiscoveryClassification, DiscoveryEvidence, ExecutionReadiness,
    ProvenanceCategory, VersionStatus,
)

DEFAULT_QUERY_TIMEOUT = 20.0

_OS_TYPES = {"debian", "ubuntu", "alpine", "rpm", "rhel", "centos", "fedora", "redhat", "deb", "apk"}


def _is_os_package(occurrence: Mapping[str, Any]) -> bool:
    result_class = str(occurrence.get("result_class") or "").casefold()
    result_type = str(occurrence.get("result_type") or "").casefold()
    return result_class == "os-pkgs" or result_type in _OS_TYPES


def _package_manager(result_type: str | None) -> str | None:
    normalized = (result_type or "").casefold()
    if normalized in {"debian", "ubuntu", "deb"}:
        return "apt"
    if normalized in {"alpine", "apk"}:
        return "apk"
    if normalized in {"rpm", "rhel", "centos", "fedora", "redhat"}:
        return "dnf"
    return None


def _distro_label(target_facts: Mapping[str, Any] | None) -> str | None:
    if not target_facts:
        return None
    return (target_facts.get("distro") or target_facts.get("image_distro")
            or target_facts.get("os") or None)


def _major_minor(version: str) -> tuple[str, str]:
    parts = version.split(".")
    return (parts[0] if parts else "", parts[1] if len(parts) > 1 else "")


def select_same_branch_fixed(installed: str | None, fixed_versions: Sequence[str]) -> tuple[str | None, bool | None, str | None]:
    """Pick the fixed version consistent with the installed release branch.

    Trivy's FixedVersion list is not ordered; do not silently jump major versions.
    If no same-branch match exists among the fixed versions, candidate resolution is
    ambiguous and must remain PARTIAL.
    """
    if not fixed_versions:
        return None, None, "no fixed version in scanner evidence"
    if not installed:
        return None, None, "installed version unknown; branch cannot be determined"
    installed_major, installed_minor = _major_minor(installed)
    matches = [v for v in fixed_versions if _major_minor(v)[0] == installed_major]
    if matches:
        # Same major branch. Prefer the matching minor branch when resolvable to
        # avoid upgrading beyond the installed minor release without evidence.
        minor_matches = [v for v in matches if _major_minor(v)[1] == installed_minor]
        pool = sorted(minor_matches, key=lambda v: tuple(map(int, re.findall(r"\d+", v) or [0])))
        if minor_matches:
            return pool[-1], True, "same major AND minor release branch match"
        return min(matches, key=lambda v: tuple(map(int, re.findall(r"\d+", v) or [0]))), True, \
            "same major release branch; no minor match, chose lowest fixed"
    return None, False, "no fixed version on the installed major branch"


def build_availability_query(package_manager: str | None, package: str,
                             fixed_version: str) -> str | None:
    if package_manager == "apt":
        return f"apt-cache policy {package}"
    if package_manager == "apk":
        return f"apk policy {package}"
    if package_manager == "dnf":
        return f"(command -v repoquery >/dev/null && repoquery --queryformat=%{{VERSION}} {package}) || yum --showduplicates list {package}"
    return None


def parse_availability(manager: str | None, fixed_version: str,
                       stdout: str, stderr: str, exit_code: int) -> AvailabilityStatus:
    text = f"{stdout}\n{stderr}"
    lowered = text.casefold()
    if exit_code != 0 and any(marker in lowered for marker in
                              ("404", "not found", "unable to locate", "no such",
                               "unknown package", "doesn't exist")):
        return AvailabilityStatus.UNAVAILABLE
    if exit_code != 0:
        # Non-zero without an obvious not-found marker is treated as an EOL/broken
        # repository when the candidate version could not be seen at all.
        return AvailabilityStatus.PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES
    # Non-zero/empty handled above. For a successful query, search for the exact
    # fixed version token that identifies the candidate package artifact.
    token = re.escape(fixed_version)
    if re.search(token, text):
        return AvailabilityStatus.AVAILABLE
    return AvailabilityStatus.PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES


class OsPackageProvider:
    """Discovers executable OS-package candidates only after availability is proven."""

    def __init__(self, runner, *, container_name: str | None = None,
                 query_timeout: float = DEFAULT_QUERY_TIMEOUT):
        self.runner = runner
        self.container_name = container_name
        self.query_timeout = query_timeout
        self.query_count = 0
        self.query_elapsed = 0.0

    def supports(self, occurrence: Mapping[str, Any]) -> bool:
        return _is_os_package(occurrence)

    def discover(self, cve_id: str, occurrences: Sequence[Mapping[str, Any]],
                 target_facts: Mapping[str, Any] | None = None) -> DiscoveredCandidate:
        os_occurrences = [x for x in occurrences if _is_os_package(x)]
        packages = tuple(sorted({str(x.get("package_name")) for x in os_occurrences
                                 if x.get("package_name")}))
        if not packages:
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.UNCLASSIFIED, None, None, None, None, None,
                ClassificationStatus.UNRESOLVED, VersionStatus.NONE, CandidateStatus.NONE,
                ExecutionReadiness.NOT_READY, None, issue="no OS package evidence")

        # A single CVE may map to multiple packages; record and validate per package.
        candidate_per_package = []
        all_evidence = []
        for occurrence in os_occurrences:
            package = str(occurrence.get("package_name"))
            if not package:
                continue
            installed = occurrence.get("installed_version")
            fixed_versions = tuple(x for x in (occurrence.get("fixed_versions") or ())
                                   if isinstance(x, str))
            result_type = str(occurrence.get("result_type") or "").casefold()
            if _package_manager(result_type) is None:
                return self._unsupported(cve_id, packages, all_evidence,
                                         reason=f"unrecognized OS package manager for {result_type!r}")
            fixed_list = sorted(fixed_versions)
            segmented = self._discover_one(cve_id, package, installed, fixed_list,
                                           result_type, target_facts)
            all_evidence.extend(segmented.evidence)
            candidate_per_package.append(segmented)

        first = candidate_per_package[0]
        combined = DiscoveredCandidate(
            cve_id, first.classification, first.fix_type, first.strategy,
            " / ".join(packages), first.current_version, first.fixed_version,
            self._combine_status(candidate_per_package, "classification_status"),
            self._combine_status(candidate_per_package, "version_status"),
            self._combine_status(candidate_per_package, "candidate_status"),
            first.execution_readiness if all(x.execution_readiness == first.execution_readiness
                                             for x in candidate_per_package)
            else ExecutionReadiness.NOT_READY,
            self._combine_availability(candidate_per_package),
            packages=packages,
            installed_versions=tuple(sorted({x.current_version for x in candidate_per_package
                                             if x.current_version})),
            fixed_versions=tuple(sorted({x.fixed_version for x in candidate_per_package
                                         if x.fixed_version})),
            package_manager=first.package_manager, target=first.target,
            source_identifier=first.source_identifier,
            same_branch=all(x.same_branch is True for x in candidate_per_package),
            branch_reason=first.branch_reason,
            evidence=tuple(all_evidence))
        return combined

    def _unsupported(self, cve_id, packages, evidence, reason) -> DiscoveredCandidate:
        return DiscoveredCandidate(
            cve_id, DiscoveryClassification.UNSUPPORTED, None, None, None, None, None,
            ClassificationStatus.UNSUPPORTED, VersionStatus.NONE, CandidateStatus.UNSUPPORTED,
            ExecutionReadiness.NOT_EXECUTABLE, None, packages=tuple(packages),
            evidence=tuple(evidence), issue=reason)

    @staticmethod
    def _combine_availability(candidates: Sequence[DiscoveredCandidate]) -> AvailabilityResult | None:
        if not candidates:
            return None
        if any(x.availability is None for x in candidates):
            return AvailabilityResult(None, AvailabilityStatus.NOT_CHECKED)
        statuses = [x.availability.status for x in candidates
                    if x.availability is not None]
        if any(s == AvailabilityStatus.AVAILABLE for s in statuses):
            # At least one package is installable at the fixed version.
            return candidates[0].availability
        if all(s == AvailabilityStatus.AVAILABLE for s in statuses):
            return candidates[0].availability
        # Not all packages available -> not executable overall.
        return candidates[0].availability

    @staticmethod
    def _combine_status(candidates: Sequence[DiscoveredCandidate], field: str):
        resolved = all(getattr(c, field) in (ClassificationStatus.RESOLVED, VersionStatus.RESOLVED)
                       for c in candidates)
        if resolved:
            return getattr(candidates[0], field)
        if any(getattr(c, field) == ClassificationStatus.UNSUPPORTED for c in candidates):
            return ClassificationStatus.UNSUPPORTED
        return getattr(candidates[0], field)

    def _query_argv(self, command: str) -> tuple[str, ...]:
        if self.container_name:
            return ("docker", "exec", self.container_name, "sh", "-lc", command)
        return tuple(command.split())

    def _probe_availability(self, package: str, fixed_version: str,
                            manager: str) -> tuple[AvailabilityResult, DiscoveryEvidence]:
        query = build_availability_query(manager, package, fixed_version)
        evidence = DiscoveryEvidence(
            "availability_query_attempted", ProvenanceCategory.PACKAGE_MANAGER_METADATA,
            query)
        if not query:
            return AvailabilityResult(fixed_version, AvailabilityStatus.UNSUPPORTED,
                                      None, manager, "no deterministic query for manager",
                                      0.0), evidence
        argv = self._query_argv(query)
        started = time.monotonic()
        try:
            result = self.runner.run(argv, timeout=self.query_timeout)
        except Exception as exc:  # timeout / command-runtime failure
            elapsed = time.monotonic() - started
            self.query_count += 1
            self.query_elapsed += elapsed
            return AvailabilityResult(
                fixed_version, AvailabilityStatus.QUERY_TIMEOUT, query, manager,
                f"query raised error: {exc}", elapsed), evidence
        elapsed = time.monotonic() - started
        self.query_count += 1
        self.query_elapsed += elapsed
        status = parse_availability(manager, fixed_version, result.stdout, result.stderr,
                                    result.exit_code)
        detail = (f"exit_code={result.exit_code} stdout={ (result.stdout or '')[:120]!r} "
                  f"stderr={ (result.stderr or '')[:120]!r}")
        if status == AvailabilityStatus.UNAVAILABLE:
            status = AvailabilityStatus.PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES
        availability = AvailabilityResult(fixed_version, status, query, manager, detail, elapsed)
        return availability, evidence

    def _discover_one(self, cve_id: str, package: str, installed: str | None,
                      fixed_versions: Sequence[str], result_type: str,
                      target_facts: Mapping[str, Any] | None) -> DiscoveredCandidate:
        manager = _package_manager(result_type)
        fixed_version, same_branch, branch_reason = select_same_branch_fixed(
            installed, fixed_versions)
        evidence = [
            DiscoveryEvidence("package_name", ProvenanceCategory.SCANNER_EVIDENCE, package),
            DiscoveryEvidence("installed_version", ProvenanceCategory.SCANNER_EVIDENCE, installed),
            DiscoveryEvidence("fixed_versions", ProvenanceCategory.SCANNER_EVIDENCE,
                              list(fixed_versions)),
            DiscoveryEvidence("package_type", ProvenanceCategory.SCANNER_EVIDENCE, result_type),
        ]
        distro = _distro_label(target_facts)
        if distro:
            evidence.append(DiscoveryEvidence("runtime_distro",
                                              ProvenanceCategory.LOCAL_IMAGE_METADATA, distro))
        evidence.append(DiscoveryEvidence("package_manager",
                                          ProvenanceCategory.LOCAL_IMAGE_METADATA, manager))
        if fixed_version is None:
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.OS_PACKAGE, "C", "PACKAGE_MANAGER",
                package, installed, None, ClassificationStatus.RESOLVED,
                VersionStatus.UNRESOLVED, CandidateStatus.NONE,
                ExecutionReadiness.NOT_READY, None, packages=(package,),
                installed_versions=(installed,) if installed else (),
                fixed_versions=tuple(fixed_versions), package_manager=manager,
                target=_distro_label(target_facts), evidence=tuple(evidence), issue=branch_reason)
        evidence.append(DiscoveryEvidence(
            "fixed_version", ProvenanceCategory.SCANNER_EVIDENCE, fixed_version))
        evidence.append(DiscoveryEvidence(
            "branch_policy", ProvenanceCategory.SCANNER_EVIDENCE, branch_reason))
        evidence.append(DiscoveryEvidence(
            "selected_target_version", ProvenanceCategory.SCANNER_EVIDENCE, fixed_version))

        availability, avail_evidence = self._probe_availability(package, fixed_version, manager)
        combined_evidence = tuple(evidence) + (avail_evidence,)
        if availability.status == AvailabilityStatus.AVAILABLE:
            return DiscoveredCandidate(
                cve_id, DiscoveryClassification.OS_PACKAGE, "C", "PACKAGE_MANAGER",
                package, installed, fixed_version, ClassificationStatus.RESOLVED,
                VersionStatus.RESOLVED, CandidateStatus.DISCOVERED,
                ExecutionReadiness.HUMAN_CONFIRMATION_REQUIRED, availability,
                packages=(package,), installed_versions=(installed,) if installed else (),
                fixed_versions=tuple(fixed_versions), package_manager=manager,
                target=_distro_label(target_facts), source_identifier=package,
                same_branch=same_branch, branch_reason=branch_reason,
                evidence=combined_evidence)
        eol = availability.status in (AvailabilityStatus.UNAVAILABLE,
                                      AvailabilityStatus.PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES)
        return DiscoveredCandidate(
            cve_id, DiscoveryClassification.OS_PACKAGE, "C", "PACKAGE_MANAGER",
            package, installed, fixed_version, ClassificationStatus.RESOLVED,
            VersionStatus.RESOLVED, CandidateStatus.UNAVAILABLE,
            ExecutionReadiness.NOT_READY, availability,
            packages=(package,), installed_versions=(installed,) if installed else (),
            fixed_versions=tuple(fixed_versions), package_manager=manager,
            target=_distro_label(target_facts), source_identifier=package,
            same_branch=same_branch, branch_reason=branch_reason, eol=eol,
            evidence=combined_evidence)
