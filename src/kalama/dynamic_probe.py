"""Contracts for opt-in observations against a running Kalama target.

This module deliberately does not share the image-scanner contract.  Image
scanners report package/image observations; a dynamic probe observes a live,
run-bound endpoint.  No runner or pipeline wiring is provided in Wave 1.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol

import yaml

from .target.models import TargetFacts


APPROVED_TEMPLATE_MANIFEST_SCHEMA = "kalama.nuclei-template-policy/v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class DynamicProbeStatus(str, Enum):
    """Execution coverage, not vulnerability truth, for a future probe."""

    NOT_RUN = "NOT_RUN"
    SUCCEEDED = "SUCCEEDED"
    TIMED_OUT = "TIMED_OUT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    PARTIAL_OUTPUT = "PARTIAL_OUTPUT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    POLICY_REJECTED = "POLICY_REJECTED"
    TARGET_IDENTITY_DRIFT = "TARGET_IDENTITY_DRIFT"


class DynamicSignal(str, Enum):
    """Per-CVE dynamic-observation semantics.

    NOT_OBSERVED is not a claim that the target is not vulnerable.  It only
    describes complete, applicable probe coverage without a match.
    """

    CORROBORATED = "CORROBORATED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_RUN = "NOT_RUN"
    INCONCLUSIVE = "INCONCLUSIVE"


class TemplatePolicyError(ValueError):
    """A stable policy-validation failure suitable for Doctor diagnostics."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class NucleiTemplatePolicy:
    """Non-negotiable constraints for the first reviewed Nuclei profile.

    The eventual runner must translate these controls into Nuclei arguments and
    validate the resolved templates again.  This contract rejects a weaker
    policy now, instead of treating tags as the primary boundary.
    """

    profile: str
    allowed_protocols: frozenset[str] = frozenset({"http"})
    redirects_allowed: bool = False
    oast_allowed: bool = False
    remote_template_sources_allowed: bool = False
    runtime_template_updates_allowed: bool = False
    excluded_tags: frozenset[str] = frozenset({
        "intrusive", "dos", "fuzz", "bruteforce", "local",
    })
    excluded_protocols: frozenset[str] = frozenset({
        "code", "javascript", "headless", "dns", "tcp", "network", "workflow",
    })
    require_run_bound_endpoint: bool = True

    def __post_init__(self) -> None:
        if not self.profile.strip():
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID", "profile is required")
        if self.allowed_protocols != frozenset({"http"}):
            raise TemplatePolicyError("NUCLEI_POLICY_INVALID",
                                      "Wave 1 reviewed policy permits HTTP templates only")
        if any((self.redirects_allowed, self.oast_allowed,
                self.remote_template_sources_allowed, self.runtime_template_updates_allowed)):
            raise TemplatePolicyError("NUCLEI_POLICY_INVALID",
                                      "Wave 1 policy forbids redirects, OAST, remote templates, and updates")
        required_tags = {"intrusive", "dos", "fuzz", "bruteforce", "local"}
        required_protocols = {"code", "javascript", "headless", "dns", "tcp", "network", "workflow"}
        if not required_tags.issubset(self.excluded_tags):
            raise TemplatePolicyError("NUCLEI_POLICY_INVALID",
                                      "Wave 1 policy must exclude unsafe template tags")
        if not required_protocols.issubset(self.excluded_protocols):
            raise TemplatePolicyError("NUCLEI_POLICY_INVALID",
                                      "Wave 1 policy must exclude non-HTTP protocols")
        if not self.require_run_bound_endpoint:
            raise TemplatePolicyError("NUCLEI_POLICY_INVALID",
                                      "Wave 1 policy requires a current run-bound endpoint")


def _require_sha256(value: str, *, field: str) -> str:
    normalized = value.lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                  f"{field} must be a 64-character SHA-256 hex digest")
    return normalized


@dataclass(frozen=True)
class DynamicEndpoint:
    """An endpoint whose identity is bound to one Kalama victim container."""

    run_id: str
    container_id: str
    container_name: str
    network: str
    ip_address: str
    port: int
    scheme: str
    readiness_state: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (
                self.run_id, self.container_id, self.container_name, self.network,
                self.ip_address, self.scheme, self.readiness_state)):
            raise ValueError("dynamic endpoint identity fields must be non-empty strings")
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError("dynamic endpoint IP address must be valid") from exc
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("dynamic endpoint port must be in 1..65535")
        if self.scheme not in {"http", "https"}:
            raise ValueError("Wave 1 dynamic endpoints support only http or https")

    @property
    def endpoint_key(self) -> str:
        """Stable identity including container identity, never only a URL."""
        identity = {
            "container_id": self.container_id,
            "ip_address": self.ip_address,
            "network": self.network,
            "port": self.port,
            "run_id": self.run_id,
            "scheme": self.scheme,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"dynamic-endpoint/v1:{hashlib.sha256(encoded).hexdigest()}"

    def to_dict(self) -> dict[str, object]:
        return {"run_id": self.run_id, "container_id": self.container_id,
                "container_name": self.container_name, "network": self.network,
                "ip_address": self.ip_address, "port": self.port, "scheme": self.scheme,
                "readiness_state": self.readiness_state, "endpoint_key": self.endpoint_key}

    @classmethod
    def from_target_facts(cls, facts: TargetFacts, *, port: int,
                          scheme: str = "http", readiness_state: str = "READY") -> "DynamicEndpoint":
        if not facts.ip_address:
            raise ValueError("target facts have no run-bound IP address")
        return cls(facts.run_id, facts.container_id, facts.container_name, facts.network,
                   facts.ip_address, port, scheme, readiness_state)


_BASE_PATH_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_BASE_PATH_ENCODED_TRAVERSAL_RE = re.compile(r"%2[ef]", re.IGNORECASE)


def normalize_http_base_path(value: str) -> str:
    """Validate and deterministically normalize an HTTP application base path.

    Base paths are directory-scoped and always trailing-slash normalized
    (``/`` stays ``/``; ``/S2-045`` becomes ``/S2-045/``) so that Nuclei
    target binding never depends on caller slash syntax. Traversal, query
    strings, fragments, scheme/host injection, percent-encoded traversal,
    and protocol-relative ``//host`` forms are rejected fail-closed.
    """
    if not isinstance(value, str):
        raise ValueError("HTTP application base path must be text")
    text = value.strip()
    if not text.startswith("/") or text.startswith("//"):
        raise ValueError("HTTP application base path must start with a single /")
    if "\\" in text or "?" in text or "#" in text:
        raise ValueError("HTTP application base path must not contain queries, "
                         "fragments, or backslashes")
    if _BASE_PATH_ENCODED_TRAVERSAL_RE.search(text):
        raise ValueError("HTTP application base path must not contain "
                         "percent-encoded traversal")
    if _BASE_PATH_SCHEME_RE.match(text):
        raise ValueError("HTTP application base path must not carry a scheme")
    segments = [segment for segment in text.split("/") if segment not in ("", ".")]
    if any(segment == ".." for segment in segments):
        raise ValueError("HTTP application base path must not traverse")
    normalized = "/" + "/".join(segments)
    return normalized + "/" if normalized != "/" else "/"


@dataclass(frozen=True)
class HttpApplicationEndpoint:
    """One reviewed application scope bound to a run-bound network endpoint.

    Composition, not replacement: the underlying :class:`DynamicEndpoint`
    keeps the container/IP/port/scheme identity while ``base_path`` selects
    the HTTP application root Nuclei is bound to. Same container/IP/port
    with different base paths yields distinct ``application_endpoint_key``
    values so executions never merge across paths.
    """

    network_endpoint: DynamicEndpoint
    base_path: str
    base_path_source: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_path", normalize_http_base_path(self.base_path))
        if (not isinstance(self.base_path_source, str)
                or not self.base_path_source.strip()):
            raise ValueError("application endpoint requires a base_path_source label")

    @property
    def application_endpoint_key(self) -> str:
        """Stable identity including the normalized base path."""
        identity = {
            "endpoint_key": self.network_endpoint.endpoint_key,
            "base_path": self.base_path,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"dynamic-app-endpoint/v1:{hashlib.sha256(encoded).hexdigest()}"

    def to_dict(self) -> dict[str, object]:
        return {"network_endpoint": self.network_endpoint.to_dict(),
                "base_path": self.base_path,
                "base_path_source": self.base_path_source,
                "application_endpoint_key": self.application_endpoint_key}

    @property
    def effective_target_url(self) -> str:
        endpoint = self.network_endpoint
        return f"{endpoint.scheme}://{endpoint.ip_address}:{endpoint.port}{self.base_path}"


@dataclass(frozen=True)
class DynamicEvidence:
    """One probe observation; package identity is intentionally absent."""

    endpoint_key: str
    template_id: str
    matched: bool
    matcher_name: str | None = None
    cve_id: str | None = None
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class DynamicEvidenceSet:
    """Future runner output, isolated from normalized image-scanner findings."""

    run_id: str
    phase: str
    endpoint: DynamicEndpoint
    status: DynamicProbeStatus
    evidence: tuple[DynamicEvidence, ...] = ()

    def __post_init__(self) -> None:
        if self.run_id != self.endpoint.run_id:
            raise ValueError("dynamic evidence run_id must match endpoint run_id")
        if any(item.endpoint_key != self.endpoint.endpoint_key for item in self.evidence):
            raise ValueError("dynamic evidence must belong to the declared endpoint")


class DynamicProbeAdapter(Protocol):
    """Future adapter boundary. Wave 1 intentionally supplies no implementation."""

    def probe(self, endpoint: DynamicEndpoint,
              policy: "ApprovedTemplateManifest") -> DynamicEvidenceSet: ...


@dataclass(frozen=True)
class ApprovedTemplate:
    template_id: str
    relative_path: str
    expected_sha256: str
    mapped_cves: tuple[str, ...]
    expected_signature_status: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.template_id, str) or not self.template_id.strip():
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID", "template_id is required")
        candidate = Path(self.relative_path)
        if (not isinstance(self.relative_path, str) or not self.relative_path
                or candidate.is_absolute() or ".." in candidate.parts):
            raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                      "template path must be a relative path inside the template root")
        object.__setattr__(self, "expected_sha256",
                           _require_sha256(self.expected_sha256, field="expected_sha256"))
        if not self.mapped_cves or any(not isinstance(cve, str) or not cve.strip()
                                       for cve in self.mapped_cves):
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                      "approved template must map to at least one CVE")
        if len(set(self.mapped_cves)) != len(self.mapped_cves):
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                      "approved template must not repeat a CVE mapping")


@dataclass(frozen=True)
class ApprovedTemplateManifest:
    profile: str
    template_root: Path
    manifest_path: Path
    templates: tuple[ApprovedTemplate, ...]
    policy: NucleiTemplatePolicy
    template_revision: str | None = None

    def __post_init__(self) -> None:
        if not self.profile.strip():
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID", "profile is required")
        ids = [item.template_id for item in self.templates]
        if len(set(ids)) != len(ids):
            raise TemplatePolicyError("NUCLEI_TEMPLATE_DUPLICATE_ID",
                                      "approved manifest contains duplicate template IDs")
        for template in self.templates:
            resolve_approved_template_path(self.template_root, template.relative_path)


@dataclass(frozen=True)
class NucleiDoctorConfig:
    """Explicit opt-in configuration for read-only Nuclei preflight checks."""

    binary_path: Path
    template_root: Path
    manifest_path: Path
    expected_version: str | None = None
    expected_binary_sha256: str | None = None
    expected_template_tree_sha256: str | None = None
    expected_manifest_sha256: str | None = None
    template_revision: str | None = None

    def __post_init__(self) -> None:
        if self.expected_binary_sha256 is not None:
            object.__setattr__(self, "expected_binary_sha256",
                               _require_sha256(self.expected_binary_sha256,
                                               field="expected_binary_sha256"))
        if self.expected_template_tree_sha256 is not None:
            object.__setattr__(self, "expected_template_tree_sha256",
                               _require_sha256(self.expected_template_tree_sha256,
                                               field="expected_template_tree_sha256"))
        if self.expected_manifest_sha256 is not None:
            object.__setattr__(self, "expected_manifest_sha256",
                               _require_sha256(self.expected_manifest_sha256,
                                               field="expected_manifest_sha256"))


def resolve_approved_template_path(template_root: Path, relative_path: str) -> Path:
    """Resolve an approved path and reject traversal and symlink escape."""
    root = template_root.resolve(strict=False)
    candidate = (root / relative_path).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                  f"template path escapes pinned root: {relative_path}") from exc
    return candidate


def load_approved_template_manifest(manifest_path: Path,
                                    template_root: Path) -> ApprovedTemplateManifest:
    """Load the exact reviewed manifest; it never discovers templates dynamically."""
    try:
        raw = yaml.safe_load(manifest_path.read_bytes())
    except (OSError, yaml.YAMLError) as exc:
        raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                  f"cannot read approved template manifest: {exc}") from exc
    if not isinstance(raw, Mapping) or raw.get("schema") != APPROVED_TEMPLATE_MANIFEST_SCHEMA:
        raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                  f"manifest schema must be {APPROVED_TEMPLATE_MANIFEST_SCHEMA}")
    entries = raw.get("approved_templates")
    if not isinstance(entries, list):
        raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                  "approved_templates must be a list")
    templates: list[ApprovedTemplate] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                      f"approved_templates[{index}] must be an object")
        try:
            templates.append(ApprovedTemplate(
                str(entry["template_id"]), str(entry["relative_path"]),
                str(entry["expected_sha256"]), tuple(str(x) for x in entry["mapped_cves"]),
                str(entry["expected_signature_status"])
                if entry.get("expected_signature_status") is not None else None,
            ))
        except KeyError as exc:
            raise TemplatePolicyError("NUCLEI_MANIFEST_INVALID",
                                      f"approved_templates[{index}] is missing {exc.args[0]}") from exc
    profile = str(raw.get("profile") or "")
    return ApprovedTemplateManifest(profile, template_root, manifest_path, tuple(templates),
                                    NucleiTemplatePolicy(profile),
                                    str(raw["template_revision"])
                                    if raw.get("template_revision") is not None else None)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def template_tree_sha256(template_root: Path) -> str:
    """Deterministic identity for the pinned local tree; no network access."""
    root = template_root.resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.resolve(strict=True).relative_to(root).as_posix().encode("utf-8")
        digest.update(relative + b"\0" + sha256_file(path).encode("ascii") + b"\n")
    return digest.hexdigest()
