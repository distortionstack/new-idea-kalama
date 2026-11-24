"""Strict codecs and compatibility adapters for discovery artifacts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from ..models import FixType, PatchStrategy, RemediationCandidate
from .contracts import (
    DISCOVERY_SCHEMA_V1, DISCOVERY_SCHEMA_V2, DiscoveryRequest, InstalledSourceMapping,
    PackageIdentity, ProviderError, ProviderResult, ProviderStatus, RepositoryContext,
    RepositoryContextStatus, RepositoryReference, ResourceChecksum, ResourceKind,
    ResourceLocationStatus, ResourceRecord, SignatureMetadata, UnifiedDiscoveryResult,
    UnifiedDiscoveryStatus, VerificationDimension, VerificationLevel, VerificationResult,
    VerificationStatus,
)
from .models import (
    AvailabilityStatus, CandidateStatus, ClassificationStatus, DiscoveredCandidate,
    DiscoveryClassification, ExecutionReadiness, VersionStatus,
)


MAX_RAW_EVIDENCE_BYTES = 16 * 1024
MAX_SAFE_MESSAGE_CHARS = 1000
_SECRET_KEYS = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|token|access_token|"
    r"api[_-]?key|password|passwd|secret|client_secret)$", re.IGNORECASE)


def _is_secret_key(value: str) -> bool:
    for _ in range(3):
        if _SECRET_KEYS.match(value):
            return True
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return False


def _safe_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parts.port is not None:
            netloc += f":{parts.port}"
        query = urlencode([
            (key, "REDACTED" if _is_secret_key(key) else item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
        ])
        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    except (TypeError, ValueError):
        return "REDACTED_INVALID_URL"


def sanitize_url(value: str | None) -> str | None:
    return _safe_url(value) if value is not None else None


def sanitize_safe_message(value: str) -> str:
    sanitized = value
    # Remove common credential-bearing URL forms before bounding the message.
    sanitized = re.sub(
        r"https?://[^\s/@:]+:[^\s/@]+@",
        lambda match: match.group(0).split("://", 1)[0] + "://",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(authorization|cookie|token|api[_-]?key|password|secret)\s*[:=]\s*[^\s,;]+",
        lambda match: match.group(1) + "=REDACTED",
        sanitized,
    )
    return sanitized[:MAX_SAFE_MESSAGE_CHARS]


def _sanitize(value: Any, *, key: str | None = None) -> Any:
    if key and _SECRET_KEYS.match(key):
        return "REDACTED"
    if isinstance(value, Mapping):
        return {str(k): _sanitize(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(x) for x in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return _safe_url(value)
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def sanitize_raw_evidence(value: Any, *, max_bytes: int = MAX_RAW_EVIDENCE_BYTES
                          ) -> tuple[Any, bool]:
    sanitized = _sanitize(value)
    encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return sanitized, False
    marker = "...[TRUNCATED]"
    prefix = encoded[:max(0, max_bytes - len(marker.encode("utf-8")))]
    text = prefix.decode("utf-8", errors="ignore") + marker
    return text, True


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _text(value: Any, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{name} must be an array of strings")
    return tuple(value)


def package_identity_from_dict(raw: Any) -> PackageIdentity:
    value = _mapping(raw, "package identity")
    qualifiers = value.get("qualifiers") or {}
    if not isinstance(qualifiers, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in qualifiers.items()):
        raise ValueError("package qualifiers must be a string map")
    return PackageIdentity(
        _text(value.get("type"), "package.type", optional=True),
        _text(value.get("namespace"), "package.namespace", optional=True),
        _text(value.get("name"), "package.name", optional=True),
        tuple(sorted(qualifiers.items())),
        _text(value.get("subpath"), "package.subpath", optional=True),
    )


def repository_context_from_dict(raw: Any) -> RepositoryContext:
    value = _mapping(raw, "repository_context")
    repositories = []
    for item in value.get("configured_repositories") or ():
        ref = _mapping(item, "configured repository")
        repositories.append(RepositoryReference(
            _text(ref.get("url"), "repository.url"),
            _text(ref.get("provenance"), "repository.provenance"),
            _text(ref.get("suite"), "repository.suite", optional=True),
            _text(ref.get("component"), "repository.component", optional=True),
        ))
    mappings = []
    for item in value.get("installed_source_mappings") or ():
        entry = _mapping(item, "installed source mapping")
        mappings.append(InstalledSourceMapping(
            _text(entry.get("binary_name"), "mapping.binary_name"),
            _text(entry.get("binary_version"), "mapping.binary_version", optional=True),
            _text(entry.get("source_name"), "mapping.source_name"),
            _text(entry.get("source_version"), "mapping.source_version", optional=True),
            _text(entry.get("provenance"), "mapping.provenance"),
        ))
    try:
        status = RepositoryContextStatus(value.get("status"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid repository context status") from exc
    return RepositoryContext(
        _text(value.get("distro"), "repository_context.distro", optional=True),
        _text(value.get("release"), "repository_context.release", optional=True),
        _text(value.get("codename"), "repository_context.codename", optional=True),
        _text(value.get("architecture"), "repository_context.architecture", optional=True),
        _text(value.get("package_manager"), "repository_context.package_manager", optional=True),
        tuple(repositories), tuple(mappings),
        _string_tuple(value.get("missing_fields"), "repository_context.missing_fields"), status,
        _text(value.get("architecture_provenance"),
              "repository_context.architecture_provenance", optional=True),
    )


def request_from_dict(raw: Any) -> DiscoveryRequest:
    value = _mapping(raw, "request")
    provenance = value.get("occurrence_provenance") or {}
    if not isinstance(provenance, Mapping):
        raise ValueError("occurrence_provenance must be an object")
    return DiscoveryRequest(
        _text(value.get("request_id"), "request_id"),
        _text(value.get("cve_id"), "cve_id"),
        _text(value.get("occurrence_id"), "occurrence_id"),
        tuple(sorted((str(k), v) for k, v in provenance.items())),
        _text(value.get("canonical_image_identity"), "canonical_image_identity", optional=True),
        _text(value.get("original_purl"), "original_purl", optional=True),
        _text(value.get("normalized_purl"), "normalized_purl", optional=True),
        package_identity_from_dict(value.get("package")),
        _text(value.get("installed_version"), "installed_version", optional=True),
        _text(value.get("requested_fixed_version"), "requested_fixed_version", optional=True),
        repository_context_from_dict(value.get("repository_context")),
        _string_tuple(value.get("missing_fields"), "request.missing_fields"),
    )


def resource_from_dict(raw: Any) -> ResourceRecord:
    value = _mapping(raw, "resource")
    checksums = []
    for item in value.get("checksums") or ():
        checksum = _mapping(item, "checksum")
        checksums.append(ResourceChecksum(
            _text(checksum.get("algorithm"), "checksum.algorithm"),
            _text(checksum.get("value"), "checksum.value"),
            _text(checksum.get("provenance"), "checksum.provenance"),
        ))
    raw_signature = value.get("signature")
    signature = None
    if raw_signature is not None:
        item = _mapping(raw_signature, "signature")
        signature = SignatureMetadata(
            _text(item.get("signature_url"), "signature.signature_url", optional=True),
            _text(item.get("key_fingerprint"), "signature.key_fingerprint", optional=True),
            _text(item.get("provenance"), "signature.provenance", optional=True),
        )
    size = value.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise ValueError("resource.size must be a non-negative integer")
    try:
        kind = ResourceKind(value.get("kind"))
        location_status = ResourceLocationStatus(value.get("location_status"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid resource enum") from exc
    return ResourceRecord(
        _text(value.get("resource_id"), "resource_id"),
        package_identity_from_dict(value.get("identity")),
        _text(value.get("requested_version"), "requested_version", optional=True),
        _text(value.get("provider_resolved_version"), "provider_resolved_version", optional=True),
        _text(value.get("architecture"), "resource.architecture", optional=True),
        _text(value.get("distro"), "resource.distro", optional=True),
        _text(value.get("provider"), "resource.provider"),
        _text(value.get("provider_version"), "resource.provider_version"),
        kind,
        _text(value.get("url"), "resource.url", optional=True), location_status,
        _text(value.get("filename"), "resource.filename", optional=True), size,
        tuple(checksums), signature,
    )


def provider_result_from_dict(raw: Any) -> ProviderResult:
    value = _mapping(raw, "provider result")
    try:
        status = ProviderStatus(value.get("status"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid provider status") from exc
    errors = []
    for item in value.get("errors") or ():
        error = _mapping(item, "provider error")
        message = _text(error.get("safe_message"), "provider error safe_message")
        errors.append(ProviderError(
            _text(error.get("code"), "provider error code"),
            message[:MAX_SAFE_MESSAGE_CHARS],
        ))
    elapsed = value.get("elapsed_seconds", 0.0)
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or elapsed < 0:
        raise ValueError("elapsed_seconds must be non-negative")
    return ProviderResult(
        _text(value.get("request_id"), "provider request_id"),
        _text(value.get("provider"), "provider"),
        _text(value.get("provider_version"), "provider_version"), status,
        tuple(resource_from_dict(x) for x in value.get("resources") or ()),
        tuple(errors), value.get("raw_evidence"),
        bool(value.get("raw_evidence_truncated", False)), float(elapsed),
    )


def verification_dimension_from_dict(raw: Any) -> VerificationDimension:
    value = _mapping(raw, "verification dimension")
    try:
        status = VerificationStatus(value.get("status"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid verification status") from exc
    return VerificationDimension(
        status,
        _text(value.get("evidence"), "verification.evidence", optional=True),
        _text(value.get("source"), "verification.source", optional=True),
        _text(value.get("error_code"), "verification.error_code", optional=True),
    )


def verification_result_from_dict(raw: Any) -> VerificationResult:
    value = _mapping(raw, "verification result")
    try:
        levels = tuple(VerificationLevel(x) for x in value.get("levels") or ())
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid verification level") from exc
    return VerificationResult(
        _text(value.get("request_id"), "verification request_id"),
        _text(value.get("resource_id"), "verification resource_id"),
        verification_dimension_from_dict(value.get("identity")),
        verification_dimension_from_dict(value.get("version")),
        verification_dimension_from_dict(value.get("architecture")),
        verification_dimension_from_dict(value.get("distribution")),
        verification_dimension_from_dict(value.get("availability")),
        verification_dimension_from_dict(value.get("integrity")),
        verification_dimension_from_dict(value.get("authenticity")), levels,
        _string_tuple(value.get("missing_evidence"), "verification.missing_evidence"),
    )


def unified_result_from_dict(raw: Any) -> UnifiedDiscoveryResult:
    value = _mapping(raw, "unified discovery result")
    try:
        status = UnifiedDiscoveryStatus(value.get("status"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid unified discovery status") from exc
    result = UnifiedDiscoveryResult(
        request_from_dict(value.get("request")),
        tuple(provider_result_from_dict(x) for x in value.get("provider_results") or ()),
        tuple(verification_result_from_dict(x)
              for x in value.get("verification_results") or ()),
        _string_tuple(value.get("missing_evidence"), "result.missing_evidence"), status,
    )
    request_id = result.request.request_id
    if any(x.request_id != request_id for x in result.provider_results):
        raise ValueError("provider result request_id mismatch")
    resource_ids = {r.resource_id for p in result.provider_results for r in p.resources}
    if any(x.request_id != request_id or x.resource_id not in resource_ids
           for x in result.verification_results):
        raise ValueError("verification result is not linked to this request/resource")
    return result


def artifact_to_dict(run_id: str, results: Sequence[UnifiedDiscoveryResult], *,
                     provider_stats: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": DISCOVERY_SCHEMA_V2,
        "run_id": run_id,
        "phase": "patch",
        "provider_stats": _sanitize(dict(provider_stats or {})),
        "results": [x.to_dict() for x in sorted(results, key=lambda x: x.request.request_id)],
    }


def artifact_from_dict(raw: Any) -> tuple[UnifiedDiscoveryResult, ...]:
    artifact = _mapping(raw, "discovery artifact")
    schema = artifact.get("schema")
    if schema == DISCOVERY_SCHEMA_V2:
        results = artifact.get("results")
        if not isinstance(results, list):
            raise ValueError("v2 discovery results must be an array")
        decoded = tuple(unified_result_from_dict(x) for x in results)
        ids = [x.request.request_id for x in decoded]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate discovery request_id")
        return decoded
    if schema == DISCOVERY_SCHEMA_V1:
        targets = artifact.get("targets")
        if not isinstance(targets, list):
            raise ValueError("v1 discovery targets must be an array")
        return tuple(legacy_dict_to_v2(x, index=index) for index, x in enumerate(targets))
    raise ValueError(f"unsupported discovery schema: {schema!r}")


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()}"


def _legacy_status(candidate_status: str | None) -> tuple[ProviderStatus, UnifiedDiscoveryStatus]:
    if candidate_status == "DISCOVERED":
        return ProviderStatus.RESOLVED, UnifiedDiscoveryStatus.UNVERIFIED
    if candidate_status in {"PARTIAL", "KNOWLEDGE_REQUIRED"}:
        return ProviderStatus.PARTIAL, UnifiedDiscoveryStatus.PARTIAL
    if candidate_status == "UNSUPPORTED":
        return ProviderStatus.UNSUPPORTED, UnifiedDiscoveryStatus.UNSUPPORTED
    if candidate_status == "UNAVAILABLE":
        return ProviderStatus.UNAVAILABLE, UnifiedDiscoveryStatus.NOT_FOUND
    return ProviderStatus.NOT_FOUND, UnifiedDiscoveryStatus.NOT_FOUND


def _legacy_kind(classification: str | None) -> ResourceKind:
    if classification == "SOURCE_BUILD":
        return ResourceKind.BUILDABLE_SOURCE_TREE
    if classification == "PREBUILT_IMAGE":
        return ResourceKind.BINARY_PACKAGE
    return ResourceKind.BINARY_PACKAGE


def legacy_dict_to_v2(raw: Any, *, index: int = 0,
                      request: DiscoveryRequest | None = None) -> UnifiedDiscoveryResult:
    value = _mapping(raw, "legacy discovery target")
    legacy_enums = (
        ("classification", DiscoveryClassification),
        ("classification_status", ClassificationStatus),
        ("version_status", VersionStatus),
        ("candidate_status", CandidateStatus),
        ("execution_readiness", ExecutionReadiness),
    )
    try:
        for field, enum_type in legacy_enums:
            if value.get(field) is not None:
                enum_type(value[field])
        availability = value.get("availability")
        if isinstance(availability, Mapping) and availability.get("status") is not None:
            AvailabilityStatus(availability["status"])
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid legacy discovery enum") from exc
    cve_id = str(value.get("cve_id") or "UNKNOWN")
    name = value.get("package_or_product")
    fixed = value.get("fixed_version")
    if request is None:
        seed = {"index": index, "cve_id": cve_id, "package": name, "fixed_version": fixed}
        request_id = _stable_id("legacy", seed)
        occurrence_id = _stable_id("unknown-occurrence", seed)
        request = DiscoveryRequest(
            request_id, cve_id, occurrence_id, (), None, None, None,
            PackageIdentity(None, None, str(name) if name else None),
            str(value.get("current_version")) if value.get("current_version") else None,
            str(fixed) if fixed else None, RepositoryContext(),
            ("canonical_image_identity", "occurrence_provenance", "original_purl",
             "normalized_purl", "repository_context"),
        )
    provider_status, final_status = _legacy_status(
        str(value.get("candidate_status")) if value.get("candidate_status") else None)
    resources = ()
    verifications = ()
    if (provider_status in {ProviderStatus.RESOLVED, ProviderStatus.PARTIAL}
            and name and fixed
            and request.requested_fixed_version in (None, str(fixed))):
        resource_id = _stable_id("resource", {
            "request_id": request.request_id, "provider": "legacy-v1-replay",
            "name": str(name), "version": str(fixed),
        })
        resource = ResourceRecord(
            resource_id, replace(request.package, name=request.package.name or str(name)),
            request.requested_fixed_version, str(fixed), None,
            request.repository_context.distro, "legacy-v1-replay", "v1",
            _legacy_kind(str(value.get("classification") or "")),
        )
        resources = (resource,)
        unknown = VerificationDimension(VerificationStatus.UNVERIFIED,
                                        error_code="LEGACY_EVIDENCE_INSUFFICIENT")
        not_applicable = VerificationDimension(VerificationStatus.NOT_APPLICABLE)
        verifications = (VerificationResult(
            request.request_id, resource_id, unknown, unknown, unknown, unknown,
            unknown, unknown, not_applicable, (),
            ("provider metadata", "content checksum", "authenticity chain"),
        ),)
    evidence = value.get("evidence") if isinstance(value.get("evidence"), list) else []
    provider = ProviderResult(
        request.request_id, "legacy-v1-replay", "v1", provider_status, resources,
        (), {"legacy_evidence": evidence, "legacy_issue": value.get("issue")},
    )
    missing = tuple(sorted(set(request.missing_fields) | {
        "resource verification provenance", "provider evidence linkage"}))
    return UnifiedDiscoveryResult(request, (provider,), verifications, missing, final_status)


def legacy_candidate_to_v2(candidate: DiscoveredCandidate, request: DiscoveryRequest
                           ) -> UnifiedDiscoveryResult:
    """Adapt a live v1 candidate without inventing facts absent from the request."""
    return legacy_dict_to_v2(candidate.to_dict(), request=request)


def v2_to_legacy_candidate(result: UnifiedDiscoveryResult, *,
                           fix_type: FixType | None = None,
                           strategy: PatchStrategy | None = None,
                           resource_verified: bool = False) -> RemediationCandidate:
    """Temporary Planner-boundary projection; it never derives a strategy itself."""
    resources = [resource for provider in result.provider_results
                 for resource in provider.resources]
    resource = resources[0] if resources else None
    return RemediationCandidate(
        target_version=(resource.provider_resolved_version if resource
                        else result.request.requested_fixed_version),
        fix_type=fix_type,
        strategy=strategy,
        source_type="unified_discovery_v2",
        source_authority=resource.provider if resource else None,
        source_identifier=(resource.url or resource.identity.name) if resource else None,
        source_url=resource.url if resource else None,
        checksum=(resource.checksums[0].value
                  if resource and resource.checksums else None),
        trusted=resource_verified,
        artifact_name=resource.filename if resource else result.request.package.name,
        candidate_status=result.status.value,
        evidence=tuple({"request_id": result.request.request_id,
                        "resource_id": item.resource_id,
                        "verification": "FACTS_ONLY"}
                       for item in resources),
    )
