"""RemediationDiscoveryService: deterministic routing + candidate building.

Routes each remediation target (occurrence set) through the appropriate provider
(OS package, source build) based on deterministic scanner evidence, joins it to
runtime/source facts, and produces an AUTO / SUGGESTED candidate. It never infers
facts absent from evidence and never produces a Human-confirmed or verified verdict.
"""

from __future__ import annotations

import hashlib
from importlib.metadata import version as distribution_version
import json
from typing import Any, Mapping, Sequence

from ..models import FixType, PatchStrategy, RemediationCandidate
from .models import (
    CandidateStatus, ClassificationStatus, DiscoveredCandidate, DiscoveryClassification,
    ExecutionReadiness, VersionStatus,
)
from .contracts import (
    DISCOVERY_SCHEMA_V2, DiscoveryRequest, PackageIdentity, ProviderError, ProviderResult,
    ProviderStatus, RepositoryContext, RepositoryContextStatus, UnifiedDiscoveryResult,
    UnifiedDiscoveryStatus,
)
from .codec import artifact_to_dict, legacy_candidate_to_v2
from .purl import NormalizationError, PurlNormalizationResult, normalize_purl
from .repository_context import RepositoryContextResolver
from .target_filesystem import TargetFilesystemReader
from .os_package import OsPackageProvider
from .source_build import SourceBuildProvider

AUTO_SOURCE_AUTHORITY = "remediation_discovery"
AUTO_SOURCE_TYPE = "auto_discovered"
DISCOVERY_SCHEMA = DISCOVERY_SCHEMA_V2
PURL_NORMALIZER_VERSION = distribution_version("packageurl-python")


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()}"


def _image_identity(target_facts: Mapping[str, Any] | None) -> str | None:
    if not target_facts:
        return None
    for key in ("canonical_image_identity", "image_digest", "image_id",
                "requested_image_reference", "requested_reference"):
        value = target_facts.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _repository_context(target_facts: Mapping[str, Any] | None,
                        result_type: str | None) -> RepositoryContext:
    facts = target_facts or {}
    distro = facts.get("distro") or facts.get("image_distro") or facts.get("os")
    release = facts.get("distro_version") or facts.get("os_version") or facts.get("release")
    codename = facts.get("codename")
    architecture = facts.get("architecture") or facts.get("arch")
    normalized_type = (result_type or "").casefold()
    manager = ("apt" if normalized_type in {"debian", "ubuntu", "deb"}
               else "apk" if normalized_type in {"alpine", "apk"}
               else "dnf" if normalized_type in {"rpm", "rhel", "centos", "fedora", "redhat"}
               else None)
    values = {"distro": distro, "release": release, "codename": codename,
              "architecture": architecture, "package_manager": manager}
    missing = tuple(sorted(key for key, value in values.items() if not value))
    status = (RepositoryContextStatus.COMPLETE if not missing
              else RepositoryContextStatus.PARTIAL if any(values.values())
              else RepositoryContextStatus.UNKNOWN)
    return RepositoryContext(
        str(distro) if distro else None, str(release) if release else None,
        str(codename) if codename else None, str(architecture) if architecture else None,
        manager, (), (), missing, status,
    )


def _request_from_occurrence(occurrence: Mapping[str, Any], requested_version: str | None,
                             target_facts: Mapping[str, Any] | None,
                             repository_context: RepositoryContext | None = None,
                             ) -> tuple[DiscoveryRequest, NormalizationError | None]:
    provenance_keys = (
        "canonical_cve_id", "package_uid", "package_name", "package_purl",
        "installed_version", "result_class", "result_type", "scanner",
    )
    provenance = {key: occurrence.get(key) for key in provenance_keys
                  if occurrence.get(key) is not None}
    occurrence_id = (str(occurrence.get("package_uid"))
                     if occurrence.get("package_uid") else _stable_id("occurrence", provenance))
    cve_id = str(occurrence.get("canonical_cve_id") or "UNKNOWN")
    original_purl = occurrence.get("package_purl")
    package_name = occurrence.get("package_name")
    package_type = occurrence.get("result_type")
    normalization: PurlNormalizationResult | None = None
    if original_purl is not None:
        normalization = normalize_purl(
            str(original_purl) if isinstance(original_purl, str) else None,
            requested_version,
        )
    package = (normalization.package if normalization and normalization.package else
               PackageIdentity(
                   str(package_type).casefold() if package_type else None,
                   None, str(package_name) if package_name else None,
               ))
    normalized_purl = (normalization.fixed_version_purl
                       if normalization and normalization.ok else None)
    image_identity = _image_identity(target_facts)
    request_seed = {
        "canonical_image_identity": image_identity,
        "cve_id": cve_id,
        "occurrence_id": occurrence_id,
        "package": package.to_dict(),
        "requested_fixed_version": requested_version,
        "normalized_purl": normalized_purl,
    }
    missing = []
    if image_identity is None:
        missing.append("canonical_image_identity")
    if original_purl is None:
        missing.extend(("original_purl", "normalized_purl"))
    else:
        if normalized_purl is None:
            missing.append("normalized_purl")
    if requested_version is None:
        missing.append("requested_fixed_version")
    safe_provenance = dict(provenance)
    if normalization and not normalization.ok:
        safe_provenance.pop("package_purl", None)
        missing.append("valid_original_purl")
    request = DiscoveryRequest(
        _stable_id("request", request_seed), cve_id, occurrence_id,
        tuple(sorted(safe_provenance.items())), image_identity,
        (str(original_purl) if isinstance(original_purl, str)
         and normalization and normalization.ok else None),
        normalized_purl, package,
        str(occurrence.get("installed_version"))
        if occurrence.get("installed_version") else None,
        requested_version, repository_context or _repository_context(
            target_facts, str(package_type) if package_type else None),
        tuple(sorted(missing)),
    )
    return request, normalization.error if normalization else None


def _normalization_failure(request: DiscoveryRequest,
                           error: NormalizationError) -> UnifiedDiscoveryResult:
    provider = ProviderResult(
        request.request_id, "packageurl-python", PURL_NORMALIZER_VERSION,
        ProviderStatus.INVALID_REQUEST, (),
        (ProviderError(error.code.value, error.safe_message),),
        {"stage": "purl_normalization", "error_code": error.code.value},
    )
    return UnifiedDiscoveryResult(
        request, (provider,), (), ("normalized package identity",),
        UnifiedDiscoveryStatus.INVALID_REQUEST,
    )


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
        self.repository_context = (RepositoryContextResolver(
            TargetFilesystemReader(runner, container_name))
            if container_name else None)

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

    def unified_from_legacy(self, occurrences: Sequence[Mapping[str, Any]],
                            target_facts: Mapping[str, Any] | None,
                            legacy: Mapping[str, DiscoveredCandidate]
                            ) -> tuple[UnifiedDiscoveryResult, ...]:
        """Project current providers into occurrence/fixed-version v2 granularity."""
        unified = []
        for occurrence in occurrences:
            cve_id = str(occurrence.get("canonical_cve_id") or "UNKNOWN")
            candidate = legacy.get(cve_id)
            versions = tuple(dict.fromkeys(
                value for value in (occurrence.get("fixed_versions") or ())
                if isinstance(value, str) and value)) or (None,)
            for version in versions:
                request, error = _request_from_occurrence(occurrence, version, target_facts)
                if error is not None:
                    unified.append(_normalization_failure(request, error))
                    continue
                if candidate is None:
                    candidate = DiscoveredCandidate(
                        cve_id, DiscoveryClassification.UNCLASSIFIED, None, None,
                        str(occurrence.get("package_name") or "") or None,
                        str(occurrence.get("installed_version") or "") or None, None,
                        ClassificationStatus.UNRESOLVED, VersionStatus.NONE,
                        CandidateStatus.NONE, ExecutionReadiness.NOT_READY, None,
                        issue="no deterministic discovery provider matched")
                unified.append(legacy_candidate_to_v2(candidate, request))
        return tuple(sorted(unified, key=lambda item: item.request.request_id))

    def discover_bundle(self, cve_ids: Sequence[str],
                        occurrences: Sequence[Mapping[str, Any]],
                        target_facts: Mapping[str, Any] | None = None
                        ) -> tuple[dict[str, DiscoveredCandidate],
                                   tuple[UnifiedDiscoveryResult, ...]]:
        """Normalize first so malformed PURLs never reach a resource provider."""
        legacy: dict[str, DiscoveredCandidate] = {}
        unified = []
        failures = []
        pending = []
        for occurrence in occurrences:
            versions = tuple(dict.fromkeys(
                value for value in (occurrence.get("fixed_versions") or ())
                if isinstance(value, str) and value)) or (None,)
            for requested_version in versions:
                request, error = _request_from_occurrence(
                    occurrence, requested_version, target_facts)
                if error is not None:
                    failures.append(_normalization_failure(request, error))
                    continue
                pending.append((occurrence, requested_version))
        resolved_context = (self.repository_context.resolve(target_facts)
                            if pending and self.repository_context else None)
        for occurrence, requested_version in pending:
            request, _ = _request_from_occurrence(
                occurrence, requested_version, target_facts, resolved_context)
            projected = dict(occurrence)
            projected["fixed_versions"] = ([requested_version]
                                             if requested_version is not None else [])
            result = self.discover_occurrences(cve_ids, [projected], target_facts)
            cve_id = request.cve_id
            candidate = result.get(cve_id)
            if candidate is not None:
                current = legacy.get(cve_id)
                if (current is None
                        or (current.candidate_status != CandidateStatus.DISCOVERED
                            and candidate.candidate_status == CandidateStatus.DISCOVERED)):
                    legacy[cve_id] = candidate
                unified.append(legacy_candidate_to_v2(candidate, request))
        unified.extend(failures)
        return legacy, tuple(sorted(unified, key=lambda item: item.request.request_id))

    def discover_unified(self, cve_ids: Sequence[str],
                         occurrences: Sequence[Mapping[str, Any]],
                         target_facts: Mapping[str, Any] | None = None
                         ) -> tuple[UnifiedDiscoveryResult, ...]:
        return self.discover_bundle(cve_ids, occurrences, target_facts)[1]

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]],
                  target_facts: Mapping[str, Any] | None = None) -> RemediationCandidate | None:
        """Adapter for the existing RemediationProvider protocol."""
        if not occurrences:
            return None
        results, _ = self.discover_bundle([], occurrences, target_facts)
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
        self.results_by_request: dict[str, UnifiedDiscoveryResult] = {}

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]],
                  target_facts: Mapping[str, Any] | None = None) -> RemediationCandidate | None:
        results, unified = self.service.discover_bundle([], occurrences, target_facts)
        self.results_by_cve.update(results)
        for result in unified:
            self.results_by_request[result.request.request_id] = result
        if not results:
            return None
        ordered = sorted(results.values(), key=lambda d: (
            0 if d.candidate_status == CandidateStatus.DISCOVERED else 1, d.cve_id))
        return _bridge(ordered[0])

    def discovery_artifact(self, run_id: str) -> dict[str, Any]:
        return artifact_to_dict(run_id, tuple(self.results_by_request.values()),
                                provider_stats=self.service.provider_stats)

    def write_discovery_artifact(self, run_id: str) -> tuple[str, str] | None:
        if self.output_root is None or not self.results_by_request:
            return None
        import json
        from datetime import datetime, timezone
        from pathlib import Path
        from ...resolution.artifacts import _atomic_write
        artifact = self.discovery_artifact(run_id)
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = (Path(self.output_root) / "patch" / "discovery" /
                f"discovery_v2_{created}_{run_id}.json")
        payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        sha = _atomic_write(path, payload)
        return str(path.resolve()), sha
