"""Unified Resource Discovery v2 contracts.

The contracts contain facts only.  They deliberately have no patch strategy,
execution-readiness, or human-confirmation fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


DISCOVERY_SCHEMA_V2 = "kalama.remediation-discovery/v2"
DISCOVERY_SCHEMA_V1 = "kalama.remediation-discovery/v1"


class RepositoryContextStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class ResourceKind(str, Enum):
    BINARY_PACKAGE = "BINARY_PACKAGE"
    PACKAGE_SOURCE_ARCHIVE = "PACKAGE_SOURCE_ARCHIVE"
    BUILDABLE_SOURCE_TREE = "BUILDABLE_SOURCE_TREE"
    REPOSITORY = "REPOSITORY"
    DOCUMENTATION = "DOCUMENTATION"


class ResourceLocationStatus(str, Enum):
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    CANDIDATE_ONLY = "CANDIDATE_ONLY"
    UNKNOWN = "UNKNOWN"


class ProviderStatus(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIAL = "PARTIAL"
    NOT_FOUND = "NOT_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_REQUEST = "INVALID_REQUEST"
    PROVIDER_ERROR = "PROVIDER_ERROR"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VerificationLevel(str, Enum):
    METADATA_VERIFIED = "METADATA_VERIFIED"
    CONTENT_VERIFIED = "CONTENT_VERIFIED"
    AUTHENTICITY_VERIFIED = "AUTHENTICITY_VERIFIED"
    LOCAL_HASH_ONLY = "LOCAL_HASH_ONLY"


class UnifiedDiscoveryStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    PARTIAL = "PARTIAL"
    NOT_FOUND = "NOT_FOUND"
    UNSUPPORTED = "UNSUPPORTED"
    INVALID_REQUEST = "INVALID_REQUEST"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class PackageIdentity:
    package_type: str | None
    namespace: str | None
    name: str | None
    qualifiers: tuple[tuple[str, str], ...] = ()
    subpath: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.package_type,
            "namespace": self.namespace,
            "name": self.name,
            "qualifiers": {key: value for key, value in self.qualifiers},
            "subpath": self.subpath,
        }


@dataclass(frozen=True)
class RepositoryReference:
    url: str
    provenance: str
    suite: str | None = None
    component: str | None = None

    def to_dict(self) -> dict[str, Any]:
        from .codec import sanitize_url
        return {
            "url": sanitize_url(self.url),
            "provenance": self.provenance,
            "suite": self.suite,
            "component": self.component,
        }


@dataclass(frozen=True)
class InstalledSourceMapping:
    binary_name: str
    binary_version: str | None
    source_name: str
    source_version: str | None
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_name": self.binary_name,
            "binary_version": self.binary_version,
            "source_name": self.source_name,
            "source_version": self.source_version,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class RepositoryContext:
    distro: str | None = None
    release: str | None = None
    codename: str | None = None
    architecture: str | None = None
    package_manager: str | None = None
    configured_repositories: tuple[RepositoryReference, ...] = ()
    installed_source_mappings: tuple[InstalledSourceMapping, ...] = ()
    missing_fields: tuple[str, ...] = ()
    status: RepositoryContextStatus = RepositoryContextStatus.UNKNOWN
    architecture_provenance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "distro": self.distro,
            "release": self.release,
            "codename": self.codename,
            "architecture": self.architecture,
            "package_manager": self.package_manager,
            "configured_repositories": [x.to_dict() for x in self.configured_repositories],
            "installed_source_mappings": [x.to_dict() for x in self.installed_source_mappings],
            "missing_fields": list(self.missing_fields),
            "status": self.status.value,
            "architecture_provenance": self.architecture_provenance,
        }


@dataclass(frozen=True)
class DiscoveryRequest:
    request_id: str
    cve_id: str
    occurrence_id: str
    occurrence_provenance: tuple[tuple[str, Any], ...]
    canonical_image_identity: str | None
    original_purl: str | None
    normalized_purl: str | None
    package: PackageIdentity
    installed_version: str | None
    requested_fixed_version: str | None
    repository_context: RepositoryContext
    missing_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        from .codec import _sanitize, sanitize_url
        return {
            "request_id": self.request_id,
            "cve_id": self.cve_id,
            "occurrence_id": self.occurrence_id,
            "occurrence_provenance": _sanitize(
                {key: value for key, value in self.occurrence_provenance}),
            "canonical_image_identity": self.canonical_image_identity,
            "original_purl": sanitize_url(self.original_purl),
            "normalized_purl": sanitize_url(self.normalized_purl),
            "package": self.package.to_dict(),
            "installed_version": self.installed_version,
            "requested_fixed_version": self.requested_fixed_version,
            "repository_context": self.repository_context.to_dict(),
            "missing_fields": list(self.missing_fields),
        }


@dataclass(frozen=True)
class ResourceChecksum:
    algorithm: str
    value: str
    provenance: str

    def to_dict(self) -> dict[str, str]:
        return {"algorithm": self.algorithm, "value": self.value,
                "provenance": self.provenance}


@dataclass(frozen=True)
class SignatureMetadata:
    signature_url: str | None = None
    key_fingerprint: str | None = None
    provenance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_url": self.signature_url,
            "key_fingerprint": self.key_fingerprint,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    identity: PackageIdentity
    requested_version: str | None
    provider_resolved_version: str | None
    architecture: str | None
    distro: str | None
    provider: str
    provider_version: str
    kind: ResourceKind
    url: str | None = None
    location_status: ResourceLocationStatus = ResourceLocationStatus.UNKNOWN
    filename: str | None = None
    size: int | None = None
    checksums: tuple[ResourceChecksum, ...] = ()
    signature: SignatureMetadata | None = None

    def to_dict(self) -> dict[str, Any]:
        from .codec import sanitize_url
        return {
            "resource_id": self.resource_id,
            "identity": self.identity.to_dict(),
            "requested_version": self.requested_version,
            "provider_resolved_version": self.provider_resolved_version,
            "architecture": self.architecture,
            "distro": self.distro,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "kind": self.kind.value,
            "url": sanitize_url(self.url),
            "location_status": self.location_status.value,
            "filename": self.filename,
            "size": self.size,
            "checksums": [x.to_dict() for x in self.checksums],
            "signature": ({**self.signature.to_dict(),
                           "signature_url": sanitize_url(self.signature.signature_url)}
                          if self.signature else None),
        }


@dataclass(frozen=True)
class ProviderError:
    code: str
    safe_message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "safe_message": self.safe_message}


@dataclass(frozen=True)
class ProviderResult:
    request_id: str
    provider: str
    provider_version: str
    status: ProviderStatus
    resources: tuple[ResourceRecord, ...] = ()
    errors: tuple[ProviderError, ...] = ()
    raw_evidence: Any = None
    raw_evidence_truncated: bool = False
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        # Import lazily to keep contracts independent from serialization policy.
        from .codec import sanitize_raw_evidence, sanitize_safe_message
        evidence, truncated = sanitize_raw_evidence(self.raw_evidence)
        return {
            "request_id": self.request_id,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "status": self.status.value,
            "resources": [x.to_dict() for x in self.resources],
            "errors": [{"code": x.code,
                        "safe_message": sanitize_safe_message(x.safe_message)}
                       for x in self.errors],
            "raw_evidence": evidence,
            "raw_evidence_truncated": self.raw_evidence_truncated or truncated,
            "elapsed_seconds": self.elapsed_seconds,
        }


@dataclass(frozen=True)
class VerificationDimension:
    status: VerificationStatus
    evidence: str | None = None
    source: str | None = None
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "evidence": self.evidence,
            "source": self.source,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class VerificationResult:
    request_id: str
    resource_id: str
    identity: VerificationDimension
    version: VerificationDimension
    architecture: VerificationDimension
    distribution: VerificationDimension
    availability: VerificationDimension
    integrity: VerificationDimension
    authenticity: VerificationDimension
    levels: tuple[VerificationLevel, ...] = ()
    missing_evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "resource_id": self.resource_id,
            "identity": self.identity.to_dict(),
            "version": self.version.to_dict(),
            "architecture": self.architecture.to_dict(),
            "distribution": self.distribution.to_dict(),
            "availability": self.availability.to_dict(),
            "integrity": self.integrity.to_dict(),
            "authenticity": self.authenticity.to_dict(),
            "levels": [x.value for x in self.levels],
            "missing_evidence": list(self.missing_evidence),
        }


@dataclass(frozen=True)
class UnifiedDiscoveryResult:
    request: DiscoveryRequest
    provider_results: tuple[ProviderResult, ...]
    verification_results: tuple[VerificationResult, ...]
    missing_evidence: tuple[str, ...]
    status: UnifiedDiscoveryStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "provider_results": [x.to_dict() for x in self.provider_results],
            "verification_results": [x.to_dict() for x in self.verification_results],
            "missing_evidence": list(self.missing_evidence),
            "status": self.status.value,
        }
