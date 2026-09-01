"""RemediationDiscoveryService: deterministic routing + candidate building.

Routes each remediation target (occurrence set) through the appropriate provider
(OS package, source build) based on deterministic scanner evidence, joins it to
runtime/source facts, and produces an AUTO / SUGGESTED candidate. It never infers
facts absent from evidence and never produces a Human-confirmed or verified verdict.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..models import FixType, PatchStrategy, RemediationCandidate
from .models import (
    CandidateStatus, ClassificationStatus, DiscoveredCandidate, DiscoveryClassification,
    ExecutionReadiness, VersionStatus,
)
from .os_package import OsPackageProvider
from .source_build import SourceBuildProvider

AUTO_SOURCE_AUTHORITY = "remediation_discovery"
AUTO_SOURCE_TYPE = "auto_discovered"
DISCOVERY_SCHEMA = "kalama.remediation-discovery/v1"


def collect_local_manifests(source_root: str | None) -> list[Mapping[str, Any]]:
    """Detect a local build manifest for source-build coordination. Maven first."""
    if not source_root:
        return []
    try:
        from pathlib import Path
        root = Path(source_root)
        if (root / "pom.xml").is_file():
            return [{"name": "pom.xml", "detail": str(root / "pom.xml")}]
        if (root / "Dockerfile").is_file():
            return [{"name": "Dockerfile", "detail": str(root / "Dockerfile")}]
        return []
    except OSError:
        return []


def _provider_for(occurrence: Mapping[str, Any]) -> str | None:
    from .os_package import _is_os_package
    from .source_build import _is_lang_pkg
    if _is_os_package(occurrence):
        return "os_package"
    if _is_lang_pkg(occurrence):
        return "source_build"
    return None


def _bridge(d: DiscoveredCandidate) -> RemediationCandidate | None:
    """Convert a DiscoveredCandidate into the production RemediationCandidate."""
    return RemediationCandidate(
        target_version=d.fixed_version,
        fix_type=FixType(d.fix_type) if d.fix_type else None,
        strategy=PatchStrategy(d.strategy) if d.strategy else None,
        source_type=AUTO_SOURCE_TYPE,
        source_authority=AUTO_SOURCE_AUTHORITY,
        source_identifier=d.source_identifier,
        source_url=None,
        checksum=None,
        trusted=False,
        same_branch=d.same_branch,
        fallback_used=False,
        build_system=d.build_system,
        eol=d.eol,
        replacement_target=None,
        artifact_name=d.package_or_product,
        classification=d.classification.value,
        classification_status=d.classification_status.value,
        version_status=d.version_status.value,
        candidate_status=d.candidate_status.value,
        execution_readiness=d.execution_readiness.value,
        availability=d.availability.status.value if d.availability else None,
        discovery_issue=d.issue,
        evidence=tuple(e.to_dict() for e in d.evidence),
    )


class RemediationDiscoveryService:
    """Coordinates deterministic discovery and produces SUGGESTED candidates."""

    def __init__(self, *, runner=None, container_name: str | None = None,
                 source_root: str | None = None, query_timeout: float = 20.0):
        self.os_package = OsPackageProvider(runner, container_name=container_name,
                                            query_timeout=query_timeout)
        self.source_build = SourceBuildProvider(source_root=source_root)
        self.source_root = source_root

    @property
    def provider_stats(self) -> dict[str, Any]:
        return {
            "os_package": {"query_count": self.os_package.query_count,
                           "query_elapsed": self.os_package.query_elapsed},
        }

    def discover_occurrences(self, cve_ids: Sequence[str],
                             occurrences: Sequence[Mapping[str, Any]],
                             target_facts: Mapping[str, Any] | None = None
                             ) -> dict[str, DiscoveredCandidate]:
        """Discover per-CVE candidates from canonical occurrence evidence."""
        canonical_cve = next((str(x.get("canonical_cve_id")) for x in occurrences
                              if x.get("canonical_cve_id")), None)
        cve_id = canonical_cve or (cve_ids[0] if cve_ids else "UNKNOWN")
        by_cve: dict[str, list[Mapping[str, Any]]] = {}
        for occurrence in occurrences:
            key = str(occurrence.get("canonical_cve_id") or cve_id)
            by_cve.setdefault(key, []).append(occurrence)
        results: dict[str, DiscoveredCandidate] = {}
        for key, occs in by_cve.items():
            routed = None
            for occurrence in occs:
                route = _provider_for(occurrence)
                if route == "os_package":
                    routed = "os_package"
                    break
                if route == "source_build" and routed is None:
                    routed = "source_build"
            if routed == "os_package":
                results[key] = self.os_package.discover(key, occs, target_facts)
            elif routed == "source_build":
                manifests = collect_local_manifests(self.source_root)
                results[key] = self.source_build.discover(key, occs, manifests)
            else:
                results[key] = DiscoveredCandidate(
                    key, DiscoveryClassification.UNCLASSIFIED, None, None, None, None, None,
                    ClassificationStatus.UNRESOLVED, VersionStatus.NONE, CandidateStatus.NONE,
                    ExecutionReadiness.NOT_READY, None,
                    issue="no deterministic discovery provider matched")
        return results

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]],
                  target_facts: Mapping[str, Any] | None = None) -> RemediationCandidate | None:
        """Adapter for the existing RemediationProvider protocol."""
        if not occurrences:
            return None
        results = self.discover_occurrences([], occurrences, target_facts)
        if not results:
            return None
        ordered = sorted(results.values(), key=lambda d: (
            0 if d.candidate_status == CandidateStatus.DISCOVERED else 1, d.cve_id))
        primary = ordered[0]
        return _bridge(primary)


class AutomaticRemediationProvider:
    """Production RemediationProvider surface backed by deterministic discovery.

    Records every per-CVE discovery result (with provenance evidence) so the
    orchestrator can persist a REMEDIATION_DISCOVERY artifact. Discovery never
    marks a candidate Human-confirmed or verified.
    """

    def __init__(self, service: RemediationDiscoveryService, *, output_root=None,
                 container_name: str | None = None, source_root: str | None = None):
        self.service = service or RemediationDiscoveryService(
            runner=None, container_name=container_name, source_root=source_root)
        self.output_root = output_root
        self.results_by_cve: dict[str, DiscoveredCandidate] = {}

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]],
                  target_facts: Mapping[str, Any] | None = None) -> RemediationCandidate | None:
        results = self.service.discover_occurrences([], occurrences, target_facts)
        self.results_by_cve.update(results)
        if not results:
            return None
        ordered = sorted(results.values(), key=lambda d: (
            0 if d.candidate_status == CandidateStatus.DISCOVERED else 1, d.cve_id))
        return _bridge(ordered[0])

    def discovery_artifact(self, run_id: str) -> dict[str, Any]:
        return {
            "schema": DISCOVERY_SCHEMA,
            "run_id": run_id,
            "phase": "patch",
            "provider_stats": self.service.provider_stats,
            "targets": [d.to_dict() for d in
                        sorted(self.results_by_cve.values(), key=lambda x: x.cve_id)],
        }

    def write_discovery_artifact(self, run_id: str) -> tuple[str, str] | None:
        if self.output_root is None or not self.results_by_cve:
            return None
        import json
        from datetime import datetime, timezone
        from pathlib import Path
        from ...resolution.artifacts import _atomic_write
        artifact = self.discovery_artifact(run_id)
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = Path(self.output_root) / "patch" / "discovery" / f"discovery_{created}_{run_id}.json"
        payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        sha = _atomic_write(path, payload)
        return str(path.resolve()), sha
