"""Wave 2 execution foundation for Nuclei dynamic probes.

Covers ONLY: candidate-to-template resolution, runtime template preflight,
run-scoped Docker network sandbox, constrained one-template-per-process
Nuclei execution, JSONL parsing at execution-result level, and scoped
reachability recording.

Explicitly NOT covered: DynamicEvidence publication, final dynamic_signal
correlation, pipeline/state integration, CLI enablement, scoring changes.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlparse

import yaml

from .dynamic_probe import (
    ApprovedTemplate,
    ApprovedTemplateManifest,
    DynamicEndpoint,
    HttpApplicationEndpoint,
    TemplatePolicyError,
    resolve_approved_template_path,
    sha256_file,
)


# ---------------------------------------------------------------------------
# Shared error codes (Wave 2 additions; Wave 1 codes are reused, not changed)
# ---------------------------------------------------------------------------

DYNAMIC_TEMPLATE_NOT_APPROVED = "DYNAMIC_TEMPLATE_NOT_APPROVED"
DYNAMIC_TEMPLATE_POLICY_REJECTED = "DYNAMIC_TEMPLATE_POLICY_REJECTED"
DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL = "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL"
DYNAMIC_TEMPLATE_OAST_FORBIDDEN = "DYNAMIC_TEMPLATE_OAST_FORBIDDEN"
DYNAMIC_SANDBOX_CREATE_FAILED = "DYNAMIC_SANDBOX_CREATE_FAILED"
DYNAMIC_SANDBOX_MEMBERSHIP_INVALID = "DYNAMIC_SANDBOX_MEMBERSHIP_INVALID"
DYNAMIC_TARGET_IDENTITY_DRIFT = "DYNAMIC_TARGET_IDENTITY_DRIFT"
DYNAMIC_TARGET_NOT_REACHABLE = "DYNAMIC_TARGET_NOT_REACHABLE"
NUCLEI_SECURITY_FLAG_UNAVAILABLE = "NUCLEI_SECURITY_FLAG_UNAVAILABLE"
NUCLEI_EXECUTION_FAILED = "NUCLEI_EXECUTION_FAILED"
NUCLEI_TIMEOUT = "NUCLEI_TIMEOUT"
NUCLEI_OUTPUT_BUDGET_EXCEEDED = "NUCLEI_OUTPUT_BUDGET_EXCEEDED"
NUCLEI_INVALID_JSONL = "NUCLEI_INVALID_JSONL"
NUCLEI_PARTIAL_OUTPUT = "NUCLEI_PARTIAL_OUTPUT"


# ---------------------------------------------------------------------------
# Task 4 — Candidate-to-template resolver
# ---------------------------------------------------------------------------

class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class CandidateTemplateResolution:
    candidate_id: str
    cve_id: str
    templates: tuple[ApprovedTemplate, ...] = ()
    resolution_status: ResolutionStatus = ResolutionStatus.UNRESOLVED


def _extract_cve_id(candidate: Any) -> str | None:
    if isinstance(candidate, str):
        return candidate.strip() or None
    if isinstance(candidate, Mapping):
        for key in ("cve_id", "canonical_cve_id"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None
    for attr in ("cve_id", "canonical_cve_id"):
        value = getattr(candidate, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # PrioritizedCVE / EnrichedCVE / AggregatedCVE shape
    enriched = getattr(candidate, "enriched", None)
    if enriched is not None:
        aggregate = getattr(enriched, "aggregate", None)
        if aggregate is not None:
            value = getattr(aggregate, "cve_id", None)
            if isinstance(value, str) and value.strip():
                return value.strip()
    aggregate = getattr(candidate, "aggregate", None)
    if aggregate is not None:
        value = getattr(aggregate, "cve_id", None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_candidate_id(candidate: Any, cve_id: str) -> str:
    if isinstance(candidate, Mapping):
        value = candidate.get("candidate_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    elif not isinstance(candidate, str):
        value = getattr(candidate, "candidate_id", None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return cve_id


def resolve_candidates_to_templates(
    candidates: Iterable[Any],
    manifest: ApprovedTemplateManifest,
) -> tuple[CandidateTemplateResolution, ...]:
    """Deterministic exact-CVE resolution against the approved manifest only.

    Only exact canonical CVE equality is used. No alias inference, no GHSA
    conversion, no template-tree discovery, no network access.
    """
    index: dict[str, list[ApprovedTemplate]] = {}
    for template in manifest.templates:
        for cve in template.mapped_cves:
            index.setdefault(cve, []).append(template)
    for templates in index.values():
        templates.sort(key=lambda t: (t.template_id, t.relative_path))

    merged: dict[tuple[str, str], CandidateTemplateResolution] = {}
    for candidate in candidates:
        cve_id = _extract_cve_id(candidate)
        if not cve_id:
            continue
        candidate_id = _extract_candidate_id(candidate, cve_id)
        key = (cve_id, candidate_id)
        if key in merged:
            continue
        matched = tuple(index.get(cve_id, ()))
        status = ResolutionStatus.RESOLVED if matched else ResolutionStatus.UNRESOLVED
        merged[key] = CandidateTemplateResolution(candidate_id, cve_id, matched, status)
    return tuple(sorted(merged.values(), key=lambda r: (r.cve_id, r.candidate_id)))


# ---------------------------------------------------------------------------
# Task 5 — Runtime template preflight (HTTP-only profile)
# ---------------------------------------------------------------------------

FORBIDDEN_TOP_LEVEL_KEYS = frozenset({
    "network", "tcp", "dns", "headless", "code", "javascript", "js",
    "workflow", "workflows", "file", "ssl", "websocket",
})
_REDIRECT_SUBSTRINGS = ("redirect",)
_OAST_MARKERS = ("interactsh", "oast.")
_FILEISH_KEYS = frozenset({
    "include", "includes", "import", "imports", "template", "templates",
    "file", "path",
})
_TRUSTED_SIGNATURE_STATUSES = frozenset({"verified", "signed", "trusted"})
_MAX_TEMPLATE_BYTES = 512 * 1024


@dataclass(frozen=True)
class TemplatePreflightResult:
    ok: bool
    template_id: str
    template_path: str
    sha256: str


def _tags_from_info(info: Any) -> set[str]:
    tags: set[str] = set()
    if not isinstance(info, Mapping):
        return tags
    raw = info.get("tags")
    if isinstance(raw, str):
        for part in re.split(r"[,\s]+", raw):
            if part.strip():
                tags.add(part.strip().lower())
    elif isinstance(raw, (list, tuple)):
        for part in raw:
            if isinstance(part, str) and part.strip():
                tags.add(part.strip().lower())
    return tags


def _walk_strings(node: Any) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(node, Mapping):
        for key, value in node.items():
            path = (str(key),)
            if isinstance(value, str):
                yield path, value
            else:
                for sub_path, text in _walk_strings(value):
                    yield path + sub_path, text
    elif isinstance(node, (list, tuple)):
        for value in node:
            if isinstance(value, str):
                yield (), value
            else:
                yield from _walk_strings(value)


def runtime_preflight_template(
    template_root: Path,
    approved: ApprovedTemplate,
    *,
    policy_excluded_tags: frozenset[str] | None = None,
    require_signature: bool | None = None,
) -> TemplatePreflightResult:
    """Inspect exact template content before execution. Fail closed."""
    from .dynamic_probe import NucleiTemplatePolicy  # local import, no cycle

    excluded = {t.lower() for t in (policy_excluded_tags or NucleiTemplatePolicy("safe-cve-http").excluded_tags)}
    path = resolve_approved_template_path(template_root, approved.relative_path)
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_NOT_APPROVED,
                                  f"approved template is not readable: {exc}") from exc
    if len(raw_bytes) > _MAX_TEMPLATE_BYTES:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED, "template exceeds size budget")
    actual_sha = sha256_file(path)
    if actual_sha != approved.expected_sha256:
        raise TemplatePolicyError("NUCLEI_TEMPLATE_HASH_MISMATCH",
                                  "template hash does not match approved manifest")
    raw_text = raw_bytes.decode("utf-8", errors="strict") if raw_bytes else ""
    lowered = raw_text.lower()
    if any(marker in lowered for marker in _OAST_MARKERS):
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_OAST_FORBIDDEN,
                                  "template references Interactsh/OAST markers")
    try:
        document = yaml.safe_load(raw_text) if raw_text.strip() else None
    except yaml.YAMLError as exc:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                  f"template YAML cannot be classified: {exc}") from exc
    if not isinstance(document, Mapping):
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                  "template top-level YAML must be a mapping")
    top_keys = {str(k).lower() for k in document.keys()}
    forbidden_present = sorted(top_keys & FORBIDDEN_TOP_LEVEL_KEYS)
    if forbidden_present:
        raise TemplatePolicyError(
            DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL,
            f"template uses unsupported protocol/capability: {', '.join(forbidden_present)}")
    if "http" not in top_keys:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                  "only HTTP templates are allowed; no http block found")
    tags = _tags_from_info(document.get("info"))
    bad_tags = sorted(tags & excluded)
    if bad_tags:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                  f"template carries excluded tags: {', '.join(bad_tags)}")
    # Redirect controls inside http requests: reject truthy redirect enablement.
    http_block = document.get("http")
    requests_list = http_block if isinstance(http_block, list) else [http_block] if isinstance(http_block, Mapping) else None
    if requests_list is None:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                  "http block has unknown shape; failing closed")
    for entry in requests_list:
        if not isinstance(entry, Mapping):
            raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                      "http request entry must be a mapping")
        for key, value in entry.items():
            key_lower = str(key).lower().replace("_", "-")
            if "redirect" in key_lower:
                truthy = value is True or (
                    isinstance(value, str) and value.strip().lower() in {"true", "yes", "1"}) or (
                    isinstance(value, int) and not isinstance(value, bool) and value > 0)
                if truthy:
                    raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                              f"template enables redirects via {key!r}")
    # Absolute remote imports / root escape via file-ish keys.
    for key_path, text in _walk_strings(document):
        leaf = key_path[-1].lower() if key_path else ""
        if leaf in _FILEISH_KEYS:
            stripped = text.strip()
            low = stripped.lower()
            if low.startswith(("http://", "https://")):
                raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                          f"absolute remote template import is forbidden: {stripped[:120]}")
            if stripped.startswith("/") or ".." in Path(stripped).parts:
                raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                          f"template reference escapes approved root: {stripped[:120]}")
    needs_signature = require_signature
    if needs_signature is None:
        needs_signature = (approved.expected_signature_status is not None
                           and approved.expected_signature_status.strip().lower()
                           in _TRUSTED_SIGNATURE_STATUSES)
    if needs_signature:
        digest = document.get("digest", document.get("signature"))
        if not (isinstance(digest, str) and digest.strip()):
            raise TemplatePolicyError(DYNAMIC_TEMPLATE_POLICY_REJECTED,
                                      "trusted signature required but template has no digest/signature")
    # NOTE: the template's self-declared `id` field is informational only and is
    # never used for allowlisting or correlation (the runner records the
    # manifest's approved template_id and executes the exact approved path),
    # so an id mismatch is not a policy rejection on its own.
    return TemplatePreflightResult(True, approved.template_id, str(path), actual_sha)


# ---------------------------------------------------------------------------
# Task 6 — Run-scoped network sandbox (Docker CLI via CommandRunner)
# ---------------------------------------------------------------------------

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9]{5}$")
_ATTEMPT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,60}$")
_FORBIDDEN_RUNNER_NETWORKS = frozenset({"kalama-net", "bridge", "host"})


class SandboxError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def sandbox_network_name(run_id: str, attempt: str | int) -> str:
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "run_id must be five ASCII letters/digits")
    attempt_text = str(attempt)
    if not _ATTEMPT_RE.fullmatch(attempt_text):
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "probe attempt must be a safe label")
    return f"kalama-probe-{run_id}-{attempt_text}"


def _inspect_container(runner: Any, name: str) -> dict[str, Any]:
    result = runner.run(("docker", "container", "inspect", name))
    if result.exit_code != 0:
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                           f"unable to inspect container {name!r}: {result.stderr.strip() or result.stdout.strip()}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "container inspect returned invalid JSON") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "container inspect returned unexpected shape")
    return payload[0]


def _inspect_network(runner: Any, name: str) -> dict[str, Any]:
    result = runner.run(("docker", "network", "inspect", name))
    if result.exit_code != 0:
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                           f"unable to inspect network {name!r}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "network inspect returned invalid JSON") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "network inspect returned unexpected shape")
    return payload[0]


@dataclass(frozen=True)
class SandboxConfig:
    run_id: str
    attempt: str | int
    victim_container_name: str
    expected_container_id: str
    port: int
    scheme: str = "http"
    runner_image: str = "kalama/nuclei-probe:pinned"
    runner_name: str | None = None
    template_root_host_path: str | None = None

    def network_name(self) -> str:
        return sandbox_network_name(self.run_id, self.attempt)

    def effective_runner_name(self) -> str:
        return self.runner_name or f"{self.network_name()}-runner"


@dataclass(frozen=True)
class SandboxIdentitySnapshot:
    run_id: str
    container_id: str
    container_name: str
    network: str
    ip_address: str
    port: int
    scheme: str


class ProbeSandbox:
    """Ephemeral internal Docker network containing only victim + runner."""

    def __init__(self, config: SandboxConfig, runner: Any):
        self.config = config
        self.runner = runner
        self.network_name = config.network_name()
        self.runner_name = config.effective_runner_name()
        self._victim_original_networks: set[str] = set()
        self._created_network = False
        self._connected_victim = False
        self._created_runner = False
        self._connected_runner = False
        self.identity_before: SandboxIdentitySnapshot | None = None
        self.identity_after: SandboxIdentitySnapshot | None = None
        self.endpoint: DynamicEndpoint | None = None

    # -- lifecycle ------------------------------------------------------
    def setup(self) -> DynamicEndpoint:
        cfg = self.config
        if not cfg.runner_image or not cfg.runner_image.strip():
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "probe runner image must be pinned")
        if ":" not in cfg.runner_image and "@" not in cfg.runner_image:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                               "probe runner image must carry an explicit tag or digest")
        if not 1 <= cfg.port <= 65535:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "probe port out of range")
        if cfg.scheme not in {"http", "https"}:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "probe scheme must be http or https")
        try:
            created = self.runner.run((
                "docker", "network", "create", "--internal",
                "--label", "kalama.managed=true",
                "--label", f"kalama.run_id={cfg.run_id}",
                "--label", f"kalama.probe_attempt={cfg.attempt}",
                self.network_name,
            ))
        except Exception as exc:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, f"sandbox create failed: {exc}") from exc
        if created.exit_code != 0:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                               f"sandbox network create failed: {created.stderr.strip() or created.stdout.strip()}")
        self._created_network = True
        try:
            net_data = _inspect_network(self.runner, self.network_name)
            if net_data.get("Internal") is not True:
                raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED, "sandbox network is not internal")
            pre = _inspect_container(self.runner, cfg.victim_container_name)
            self._victim_original_networks = set(
                ((pre.get("NetworkSettings") or {}).get("Networks") or {}).keys())
            connected = self.runner.run(("docker", "network", "connect", self.network_name,
                                         cfg.victim_container_name))
            if connected.exit_code != 0:
                raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                                   f"unable to attach victim to sandbox: {connected.stderr.strip()}")
            self._connected_victim = True
            victim = _inspect_container(self.runner, cfg.victim_container_name)
            victim_id = str(victim.get("Id") or "")
            if not victim_id or victim_id != cfg.expected_container_id:
                raise SandboxError(DYNAMIC_TARGET_IDENTITY_DRIFT,
                                   "victim container identity changed before execution")
            networks = ((victim.get("NetworkSettings") or {}).get("Networks") or {})
            if self.network_name not in networks:
                raise SandboxError(DYNAMIC_SANDBOX_MEMBERSHIP_INVALID,
                                   "victim is not attached to the sandbox network")
            sandbox_ip = ((networks.get(self.network_name) or {}).get("IPAddress") or "")
            if not sandbox_ip:
                raise SandboxError(DYNAMIC_SANDBOX_MEMBERSHIP_INVALID,
                                   "victim has no IP on the sandbox network")
            # Runner: create directly on the sandbox network so it is never
            # attached anywhere else. (A container created with
            # `--network none` uses the private "none" network mode, which
            # the Docker daemon refuses to join to any further network, so
            # create-then-connect is not viable; direct creation yields the
            # same sandbox-only final topology.)
            create_args: list[str] = [
                "docker", "create", "--name", self.runner_name,
                "--network", self.network_name,
                "--label", "kalama.managed=true",
                "--label", f"kalama.run_id={cfg.run_id}",
                "--label", "kalama.role=nuclei-probe-runner",
            ]
            if cfg.template_root_host_path:
                create_args += ["--volume", f"{cfg.template_root_host_path}:/templates:ro"]
            create_args += [cfg.runner_image, "sleep", "infinity"]
            created_runner = self.runner.run(tuple(create_args))
            if created_runner.exit_code != 0:
                raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                                   f"unable to create probe runner: {created_runner.stderr.strip()}")
            self._created_runner = True
            self._connected_runner = True
            runner_data = _inspect_container(self.runner, self.runner_name)
            runner_networks = set(((runner_data.get("NetworkSettings") or {}).get("Networks") or {}).keys())
            if runner_networks != {self.network_name}:
                raise SandboxError(
                    DYNAMIC_SANDBOX_MEMBERSHIP_INVALID,
                    f"runner must be attached only to the sandbox network, got {sorted(runner_networks)}")
            if runner_networks & _FORBIDDEN_RUNNER_NETWORKS:
                raise SandboxError(DYNAMIC_SANDBOX_MEMBERSHIP_INVALID,
                                   "runner is attached to a forbidden network")
            self.identity_before = SandboxIdentitySnapshot(
                cfg.run_id, victim_id, cfg.victim_container_name,
                self.network_name, sandbox_ip, cfg.port, cfg.scheme)
            self.endpoint = DynamicEndpoint(
                cfg.run_id, victim_id, cfg.victim_container_name,
                self.network_name, sandbox_ip, cfg.port, cfg.scheme, "READY")
            return self.endpoint
        except Exception:
            self.cleanup()
            raise

    def verify_after(self) -> SandboxIdentitySnapshot:
        if self.identity_before is None:
            raise SandboxError(DYNAMIC_SANDBOX_MEMBERSHIP_INVALID, "sandbox was not established")
        victim = _inspect_container(self.runner, self.config.victim_container_name)
        victim_id = str(victim.get("Id") or "")
        networks = ((victim.get("NetworkSettings") or {}).get("Networks") or {})
        sandbox_ip = ((networks.get(self.network_name) or {}).get("IPAddress") or "")
        before = self.identity_before
        # Critical regression rule: same IP + different container ID is rejected.
        if victim_id != before.container_id:
            raise SandboxError(DYNAMIC_TARGET_IDENTITY_DRIFT,
                               "victim container identity changed during execution")
        if sandbox_ip != before.ip_address or self.network_name not in networks:
            raise SandboxError(DYNAMIC_TARGET_IDENTITY_DRIFT,
                               "victim sandbox identity changed during execution")
        # Original networks must be preserved.
        if not self._victim_original_networks.issubset(set(networks.keys())):
            raise SandboxError(DYNAMIC_TARGET_IDENTITY_DRIFT,
                               "victim lost a pre-existing network during probing")
        self.identity_after = SandboxIdentitySnapshot(
            before.run_id, victim_id, before.container_name,
            self.network_name, sandbox_ip, before.port, before.scheme)
        return self.identity_after

    def start_runner(self) -> None:
        """Start the previously created runner so `docker exec` works in it.

        Creation deliberately does not start the container; execution inside
        the sandbox namespace (Nuclei, reachability) requires an explicit
        start. Membership is unaffected.
        """
        if not self._created_runner:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                               "probe runner was not created")
        try:
            started = self.runner.run(("docker", "start", self.runner_name))
        except Exception as exc:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                               f"unable to start probe runner: {exc}") from exc
        if started.exit_code != 0:
            raise SandboxError(DYNAMIC_SANDBOX_CREATE_FAILED,
                               f"unable to start probe runner: "
                               f"{started.stderr.strip() or started.stdout.strip()}")

    def cleanup(self) -> None:
        # Best-effort, sandbox-scoped only; never touch unrelated resources.
        try:
            if self._connected_victim:
                try:
                    self.runner.run(("docker", "network", "disconnect",
                                     self.network_name, self.config.victim_container_name))
                except Exception:
                    pass
                finally:
                    self._connected_victim = False
        finally:
            try:
                if self._created_runner:
                    try:
                        self.runner.run(("docker", "rm", "-f", self.runner_name))
                    except Exception:
                        pass
                    finally:
                        self._created_runner = False
                        self._connected_runner = False
            finally:
                if self._created_network:
                    try:
                        self.runner.run(("docker", "network", "rm", self.network_name))
                    except Exception:
                        pass
                    finally:
                        self._created_network = False

    def __enter__(self) -> DynamicEndpoint:
        return self.setup()

    def __exit__(self, *exc: Any) -> None:
        self.cleanup()


@contextmanager
def sandbox_session(config: SandboxConfig, runner: Any):
    box = ProbeSandbox(config, runner)
    try:
        yield box.setup(), box
        box.verify_after()
    finally:
        box.cleanup()


# ---------------------------------------------------------------------------
# Task 7 — Constrained Nuclei runner + Task 8 JSONL + reachability
# ---------------------------------------------------------------------------

class NucleiExecutionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    PARTIAL_OUTPUT = "PARTIAL_OUTPUT"
    INVALID_OUTPUT = "INVALID_OUTPUT"


@dataclass(frozen=True)
class NucleiRunnerConfig:
    binary_path: str
    template_root: Path
    per_template_timeout: float = 60.0
    process_timeout: float = 90.0
    rate_limit: int = 10
    concurrency: int = 5
    retries: int = 1
    stdout_budget_bytes: int = 1_048_576
    stderr_budget_bytes: int = 262_144
    max_records: int = 1000

    def __post_init__(self) -> None:
        if not self.binary_path.strip():
            raise ValueError("nuclei binary path is required")
        for name in ("per_template_timeout", "process_timeout"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("rate_limit", "concurrency", "max_records"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.retries < 0:
            raise ValueError("retries must be >= 0")


@dataclass(frozen=True)
class NucleiMatchRecord:
    template_id: str | None
    matcher_name: str | None
    matched_at: str | None
    host: str | None
    severity: str | None
    cve_id: str | None
    timestamp: str | None
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class JsonlParseOutcome:
    records: tuple[NucleiMatchRecord, ...]
    truncated: bool
    malformed_line: int | None
    malformed_text: str | None


@dataclass(frozen=True)
class ProbeExecutionResult:
    run_id: str
    attempt: str
    endpoint_identity: Mapping[str, Any]
    candidate_cve: str
    template_id: str
    template_path: str
    template_sha256: str
    execution_status: NucleiExecutionStatus
    started_at: str
    finished_at: str
    duration_seconds: float
    reachable: bool | None
    exit_code: int | None
    records: tuple[NucleiMatchRecord, ...] = ()
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error_code: str | None = None
    error_detail: str | None = None
    # Exact bounded stdout captured for the execution (raw JSONL artifact
    # source). Never reconstructed from normalized records.
    raw_stdout: bytes = b""
    # In-container template path actually passed to Nuclei, when it differs
    # from the host-side approved path (container mount mapping).
    template_runtime_path: str | None = None
    # Application scope binding. Defaults preserve legacy root-only behavior:
    # base_path "/" with no application key. Executions against different
    # base paths carry distinct application_endpoint_key values.
    base_path: str = "/"
    base_path_source: str | None = None
    application_endpoint_key: str | None = None
    effective_target_url: str | None = None


class ProcessBackend(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float | None = None,
            stdout_budget: int | None = None,
            stderr_budget: int | None = None) -> Any: ...


@dataclass
class BackendResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


_DEFAULT_STDOUT_BUDGET = 1_048_576
_DEFAULT_STDERR_BUDGET = 262_144
_READ_CHUNK_BYTES = 65536


class _BoundedStreamDrain:
    """Incrementally accumulate at most ``limit`` bytes from one pipe."""

    def __init__(self, limit: int):
        import threading as _threading
        self._lock = _threading.Lock()
        self._buffer = bytearray()
        self._limit = max(0, int(limit))
        self.total_seen = 0
        self.exceeded = False

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            self.total_seen += len(chunk)
            if len(self._buffer) < self._limit:
                self._buffer.extend(chunk[:self._limit - len(self._buffer)])
            if self.total_seen > self._limit:
                self.exceeded = True

    def snapshot(self) -> bytes:
        with self._lock:
            return bytes(self._buffer)


def _drain_stream(stream: Any, drain: _BoundedStreamDrain) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            drain.feed(chunk)
    except (OSError, ValueError):
        return


class SubprocessBackend:
    """Real backend: explicit argv, shell=False, budgets enforced incrementally.

    Stdout/stderr are read on background threads while the process runs, so a
    configured byte budget is enforced *before* an untrusted child can force
    Kalama to buffer unlimited output. No Unix-only primitives are used, so
    this works under Windows/Docker Desktop conditions.
    """

    def __init__(self, *, poll_interval: float = 0.02, join_grace: float = 5.0):
        if poll_interval <= 0 or join_grace <= 0:
            raise ValueError("poll_interval and join_grace must be positive")
        self._poll_interval = poll_interval
        self._join_grace = join_grace

    def run(self, argv: Sequence[str], *, timeout: float | None = None,
            stdout_budget: int | None = None,
            stderr_budget: int | None = None) -> BackendResult:
        import threading as _threading
        import time as _time

        args = tuple(str(x) for x in argv)
        out_limit = _DEFAULT_STDOUT_BUDGET if stdout_budget is None else stdout_budget
        err_limit = _DEFAULT_STDERR_BUDGET if stderr_budget is None else stderr_budget
        try:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False)
        except FileNotFoundError as exc:
            return BackendResult(args, 127, b"", str(exc).encode())
        except OSError as exc:
            return BackendResult(args, 127, b"", f"process start failed: {exc}".encode())
        stdout_drain = _BoundedStreamDrain(out_limit)
        stderr_drain = _BoundedStreamDrain(err_limit)
        readers = []
        for stream, drain in ((proc.stdout, stdout_drain), (proc.stderr, stderr_drain)):
            thread = _threading.Thread(target=_drain_stream, args=(stream, drain),
                                       daemon=True)
            thread.start()
            readers.append(thread)
        deadline = None if timeout is None else _time.monotonic() + max(0.0, timeout)
        timed_out = False
        budget_hit = False
        try:
            while proc.poll() is None:
                if stdout_drain.exceeded or stderr_drain.exceeded:
                    budget_hit = True
                    break
                if deadline is not None and _time.monotonic() >= deadline:
                    timed_out = True
                    break
                _time.sleep(self._poll_interval)
        finally:
            if timed_out or budget_hit:
                # Safe termination first; then best-effort drain/reap so no
                # child or pipe resource leaks even on violation paths.
                try:
                    proc.kill()
                except (OSError, ValueError):
                    pass
            try:
                proc.wait(timeout=self._join_grace)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                pass
            for thread in readers:
                thread.join(timeout=self._join_grace)
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except (OSError, ValueError):
                    pass
        exit_code = proc.returncode
        if exit_code is None:
            exit_code = 124 if timed_out else 137
        return BackendResult(args, exit_code, stdout_drain.snapshot(),
                             stderr_drain.snapshot(), timed_out,
                             stdout_drain.exceeded, stderr_drain.exceeded)


@dataclass(frozen=True)
class NucleiSecurityCapability:
    """One non-negotiable engine control with its accepted argv spellings.

    Alternatives are ordered preferred-first. ``-doast`` is deliberately not
    listed anywhere: the Interactsh/OAST control is ``-ni``/``-no-interactsh``
    unless a pinned binary proves otherwise, and an unrecognized token must
    never satisfy a capability.
    """

    name: str
    alternatives: tuple[str, ...]


REQUIRED_SECURITY_CAPABILITIES: tuple[NucleiSecurityCapability, ...] = (
    NucleiSecurityCapability("jsonl-output", ("-jsonl",)),
    NucleiSecurityCapability("disable-update-check", ("-duc", "-disable-update-check")),
    NucleiSecurityCapability("disable-redirects", ("-dr", "-disable-redirects")),
    NucleiSecurityCapability("no-interactsh", ("-ni", "-no-interactsh")),
    NucleiSecurityCapability("disable-unsigned-templates", ("-dut", "-disable-unsigned-templates")),
)

# Display-only flags kept in every invocation; they are not security
# capabilities and are not capability-gated.
_DISPLAY_FLAGS: tuple[str, ...] = ("-silent", "-nc")

_HELP_PROBE_STDOUT_BUDGET = 65536
_HELP_PROBE_STDERR_BUDGET = 65536


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def _help_contains_flag(help_text: str, token: str) -> bool:
    """Match an argv token in ``-h`` output without substring false positives.

    ANSI color escapes are stripped first: ``-h`` output may be colorized
    when the child emits codes before flag tokens.
    """
    cleaned = _ANSI_ESCAPE_RE.sub("", help_text)
    return re.search(r"(?:^|[\s\(\[])"+re.escape(token)+r"(?=$|[\s,=\)\]:;.])",
                     cleaned) is not None


def check_security_flags_available(help_text: str) -> list[str]:
    """Return the names of required capabilities missing from ``-h`` output."""
    return [capability.name for capability in REQUIRED_SECURITY_CAPABILITIES
            if not any(_help_contains_flag(help_text, token)
                       for token in capability.alternatives)]


def select_security_flags(help_text: str) -> dict[str, str]:
    """Choose the actually-supported argv token for every required capability.

    Raises TemplatePolicyError(NUCLEI_SECURITY_FLAG_UNAVAILABLE) fail-closed
    when any capability cannot be satisfied by the pinned binary.
    """
    missing = check_security_flags_available(help_text)
    if missing:
        raise TemplatePolicyError(
            NUCLEI_SECURITY_FLAG_UNAVAILABLE,
            f"required Nuclei security capabilities unavailable: {', '.join(missing)}")
    selected: dict[str, str] = {}
    for capability in REQUIRED_SECURITY_CAPABILITIES:
        for token in capability.alternatives:
            if _help_contains_flag(help_text, token):
                selected[capability.name] = token
                break
    return selected


def endpoint_url(endpoint: DynamicEndpoint) -> str:
    return f"{endpoint.scheme}://{endpoint.ip_address}:{endpoint.port}/"


_SANDBOX_NETWORK_RE = re.compile(r"^kalama-probe-[A-Za-z0-9]{5}-[A-Za-z0-9][A-Za-z0-9_.\-]{0,60}$")


# Approved in-runner reachability primitives, probed in order. Detection is
# shell-free: `docker exec` runs binaries directly (no shell), so the shell
# builtin `command -v` cannot work there. Each tool lists explicit absolute
# candidate paths probed with `ls`; the first path with exit 0 wins.
_APPROVED_REACHABILITY_TOOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nc", ("/usr/bin/nc", "/bin/nc")),
    ("wget", ("/usr/bin/wget", "/bin/wget")),
    ("curl", ("/usr/bin/curl", "/bin/curl")),
)


class SandboxReachabilityProbe:
    """Reachability checked from inside the probe runner's net namespace.

    Capability strategy (deterministic, fail closed):
    1. detect an approved tool explicitly via shell-free
       ``docker exec <runner> ls <absolute-candidate-path>``, trying
       ``nc``, then ``wget``, then ``curl``;
    2. probe the sandbox endpoint with the first available tool;
    3. otherwise report unreachable.

    No packages are installed, no host-side check is substituted, and only
    ``kalama-probe-*`` sandbox endpoints are accepted, so a host endpoint or
    host-published port can never be probed. Any failure returns False.
    """

    def __init__(self, command_runner: Any, runner_container: str,
                 *, timeout: float = 5.0,
                 tools: Sequence[str] | None = None):
        if not runner_container or not runner_container.strip():
            raise ValueError("runner container name is required")
        if timeout <= 0:
            raise ValueError("probe timeout must be positive")
        self._runner = command_runner
        self._container = runner_container
        self._timeout = float(timeout)
        self._tools = tuple(tools) if tools is not None else tuple(
            name for name, _ in _APPROVED_REACHABILITY_TOOLS)
        self._detected_tool: str | None = None
        self._detection_done = False

    @property
    def detected_tool(self) -> str | None:
        """Approved tool found in the runner, or None after a failed scan."""
        return self._detected_tool if self._detection_done else None

    def _detect_tool(self) -> str | None:
        if self._detection_done:
            return self._detected_tool
        approved = dict(_APPROVED_REACHABILITY_TOOLS)
        try:
            for name in self._tools:
                for candidate in approved.get(name, ()):
                    result = self._runner.run(
                        ("docker", "exec", self._container, "ls", candidate),
                        timeout=self._timeout)
                    if result is not None and getattr(result, "exit_code", 1) == 0:
                        self._detected_tool = name
                        break
                if self._detected_tool is not None:
                    break
        except Exception:
            self._detected_tool = None
        finally:
            self._detection_done = True
        return self._detected_tool

    def build_probe_argv(self, endpoint: DynamicEndpoint) -> tuple[str, ...]:
        url = validate_probe_url(endpoint_url(endpoint), endpoint)
        if not _SANDBOX_NETWORK_RE.fullmatch(endpoint.network):
            raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                      "reachability requires a sandbox network endpoint")
        tool = self._detect_tool()
        if tool == "nc":
            return ("docker", "exec", self._container, "nc", "-w",
                    str(max(1, int(self._timeout))),
                    endpoint.ip_address, str(endpoint.port))
        if tool == "wget":
            return ("docker", "exec", self._container, "wget", "-q", "-O", "/dev/null",
                    "-T", str(max(1, int(self._timeout))), "-t", "1", url)
        if tool == "curl":
            return ("docker", "exec", self._container, "curl", "-fsS", "--max-time",
                    str(float(self._timeout)), "-o", "/dev/null", url)
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                  "no approved reachability tool in runner image")

    def __call__(self, endpoint: DynamicEndpoint) -> bool:
        try:
            argv = self.build_probe_argv(endpoint)
        except (TemplatePolicyError, ValueError):
            return False
        try:
            result = self._runner.run(argv, timeout=self._timeout)
        except Exception:
            return False
        return bool(result is not None and getattr(result, "exit_code", 1) == 0)


def container_template_path(host_template_abs: Path, host_root: Path,
                              container_root: str) -> str:
    """Map a host-side approved template path to its in-container mount path.

    The orchestrator mounts the host template tree read-only at
    ``container_root``; Nuclei inside the runner must receive the mapped path.
    Fail closed on any escape from either root. No shell involved.
    """
    if not container_root or not container_root.startswith("/"):
        raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                  "container template root must be absolute")
    try:
        relative = host_template_abs.resolve(strict=False).relative_to(
            host_root.resolve(strict=False))
    except ValueError as exc:
        raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                  "template path escapes pinned root") from exc
    if ".." in relative.parts or relative.is_absolute():
        raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                  "template path escapes pinned root")
    return (container_root.rstrip("/") + "/" + relative.as_posix()).replace("//", "/")


class ContainerExecBackend:
    """ProcessBackend executing argv inside a container via ``docker exec``.

    Production Nuclei runs inside the sandbox runner (the host cannot route
    to a Docker-internal victim IP), so the validated argv is prefixed with
    ``docker exec <runner>`` and streamed through an inner backend with the
    same incremental budgets. Explicit argv only, ``shell=False`` inside.
    """

    def __init__(self, runner_container: str, *,
                 inner: ProcessBackend | None = None,
                 docker_binary: str = "docker"):
        if not runner_container or not runner_container.strip():
            raise ValueError("runner container name is required")
        if not docker_binary or not docker_binary.strip():
            raise ValueError("docker binary is required")
        self._container = runner_container
        self._inner = inner if inner is not None else SubprocessBackend()
        self._docker = docker_binary

    def wrapped_argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        return (self._docker, "exec", self._container) + tuple(str(x) for x in argv)

    def run(self, argv: Sequence[str], *, timeout: float | None = None,
            stdout_budget: int | None = None,
            stderr_budget: int | None = None) -> Any:
        return self._inner.run(self.wrapped_argv(argv), timeout=timeout,
                               stdout_budget=stdout_budget,
                               stderr_budget=stderr_budget)


def validate_probe_url(url: str,
                       endpoint: DynamicEndpoint | HttpApplicationEndpoint) -> str:
    """Reject arbitrary/external URLs. Only the sandbox endpoint is allowed.

    When an application endpoint is supplied, the URL path must additionally
    equal the approved normalized base path exactly, so a bound execution
    can never drift to a different application scope.
    """
    network = (endpoint.network_endpoint if isinstance(endpoint, HttpApplicationEndpoint)
               else endpoint)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.scheme != network.scheme:
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE, "probe URL scheme is not the sandbox scheme")
    if parsed.username or parsed.password:
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE, "probe URL must not carry credentials")
    host = (parsed.hostname or "")
    if host != network.ip_address:
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                  "probe URL host is not the sandbox victim IP")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port != network.port:
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE, "probe URL port is not the sandbox port")
    if isinstance(endpoint, HttpApplicationEndpoint):
        if (parsed.path or "/") != endpoint.base_path:
            raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                      "probe URL path is not the approved application base path")
        if parsed.query or parsed.fragment:
            raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                      "probe URL must not carry query or fragment")
    return url


def application_target_url(app: HttpApplicationEndpoint) -> str:
    """Deterministic Nuclei target binding for one approved application scope."""
    return validate_probe_url(app.effective_target_url, app)


def build_nuclei_argv(
    config: NucleiRunnerConfig,
    *,
    template_path: Path,
    target_url: str,
    security_flags: Mapping[str, str],
) -> tuple[str, ...]:
    """One template per invocation; exact approved path; explicit argv only.

    ``security_flags`` must map every required capability name to the argv
    token proven supported by the pinned binary (see select_security_flags).
    No flag spelling is assumed here.
    """
    resolved = Path(template_path)
    root = config.template_root.resolve(strict=False)
    try:
        resolved.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise TemplatePolicyError("NUCLEI_TEMPLATE_OUTSIDE_ROOT",
                                  "template path escapes pinned root") from exc
    ordered = [security_flags.get(capability.name)
               for capability in REQUIRED_SECURITY_CAPABILITIES]
    if any(token is None for token in ordered):
        raise TemplatePolicyError(NUCLEI_SECURITY_FLAG_UNAVAILABLE,
                                  "security flags must cover every required capability")
    argv = (
        config.binary_path,
        "-t", str(template_path),
        "-u", target_url,
        *ordered,
        *_DISPLAY_FLAGS,
        "-timeout", str(int(config.per_template_timeout)),
        "-retries", str(int(config.retries)),
        "-rl", str(int(config.rate_limit)),
        "-c", str(int(config.concurrency)),
    )
    # Defensive: exactly one -t with the exact path; never a directory scan.
    if argv.count("-t") != 1:
        raise TemplatePolicyError(NUCLEI_EXECUTION_FAILED, "exactly one template per invocation is required")
    return argv


def _extract_cve_from_record(raw: Mapping[str, Any]) -> str | None:
    info = raw.get("info")
    if isinstance(info, Mapping):
        for key in ("cve", "cve-id", "cve_id"):
            value = info.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        classification = info.get("classification")
        if isinstance(classification, Mapping):
            value = classification.get("cve-id", classification.get("cve_id"))
            if isinstance(value, str) and value.strip():
                return value.strip()
            ids = classification.get("cve-ids", classification.get("cve_ids"))
            if isinstance(ids, list) and ids and isinstance(ids[0], str):
                return ids[0].strip()
    for key in ("cve", "cve-id", "cve_id"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def parse_nuclei_jsonl(stdout: bytes | str) -> JsonlParseOutcome:
    text = stdout.decode("utf-8", errors="strict") if isinstance(stdout, bytes) else stdout
    # Strict UTF-8: undecodable output is malformed, not silently replaced.
    records: list[NucleiMatchRecord] = []
    malformed_line: int | None = None
    malformed_text: str | None = None
    truncated = False
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            malformed_line, malformed_text = index, line[:500]
            truncated = index == len(lines)
            break
        if not isinstance(parsed, dict):
            malformed_line, malformed_text = index, line[:500]
            truncated = index == len(lines)
            break
        info = parsed.get("info", {}) if isinstance(parsed.get("info"), dict) else {}
        records.append(NucleiMatchRecord(
            template_id=parsed.get("template-id", parsed.get("templateID", parsed.get("template_id"))),
            matcher_name=parsed.get("matcher-name", parsed.get("matcher_name")),
            matched_at=parsed.get("matched-at", parsed.get("matched_at", parsed.get("host"))),
            host=parsed.get("host"),
            severity=(info.get("severity") if isinstance(info, dict) else None),
            cve_id=_extract_cve_from_record(parsed),
            timestamp=parsed.get("timestamp"),
            raw=parsed,
        ))
    else:
        truncated = False
    return JsonlParseOutcome(tuple(records), truncated, malformed_line, malformed_text)


def execute_single_template(
    config: NucleiRunnerConfig,
    *,
    endpoint: DynamicEndpoint,
    approved: ApprovedTemplate,
    candidate_cve: str,
    run_id: str,
    attempt: str | int,
    backend: ProcessBackend,
    reachability: Callable[[DynamicEndpoint], bool | None] | None = None,
    help_text: str | None = None,
    now: Callable[[], datetime] | None = None,
    template_container_root: str | None = None,
    app_endpoint: HttpApplicationEndpoint | None = None,
) -> ProbeExecutionResult:
    """Execute ONE endpoint x ONE template x ONE process. Fail closed.

    ``template_container_root`` optionally maps the ``-t`` value to the
    in-container mount path (validated mapping); identity and hash always
    stay bound to the host-side approved file.

    ``app_endpoint``, when supplied, must wrap ``endpoint`` and binds the
    Nuclei target to its approved base path; the execution record then
    carries the application scope so same-template/different-path runs
    never merge. Omitted (None) preserves legacy root-only behavior.
    """
    clock = now or (lambda: datetime.now(timezone.utc))
    started = clock()
    template_abs = resolve_approved_template_path(config.template_root, approved.relative_path)
    try:
        template_sha = sha256_file(template_abs)
    except OSError as exc:
        raise TemplatePolicyError(DYNAMIC_TEMPLATE_NOT_APPROVED, f"template unreadable: {exc}") from exc
    if template_sha != approved.expected_sha256:
        raise TemplatePolicyError("NUCLEI_TEMPLATE_HASH_MISMATCH", "template hash mismatch at execution")
    if app_endpoint is not None and app_endpoint.network_endpoint != endpoint:
        raise TemplatePolicyError(DYNAMIC_TARGET_NOT_REACHABLE,
                                  "application endpoint does not belong to this probe endpoint")
    if app_endpoint is None:
        target = validate_probe_url(endpoint_url(endpoint), endpoint)
        app_scope: dict[str, Any] = {}
    else:
        target = application_target_url(app_endpoint)
        app_scope = {"base_path": app_endpoint.base_path,
                     "base_path_source": app_endpoint.base_path_source,
                     "application_endpoint_key": app_endpoint.application_endpoint_key,
                     "effective_target_url": target}
    # Security-flag availability gate, discovered from the pinned binary
    # through the same command abstraction (never assumed).
    if help_text is None:
        help_result = backend.run((config.binary_path, "-h"), timeout=15,
                                  stdout_budget=_HELP_PROBE_STDOUT_BUDGET,
                                  stderr_budget=_HELP_PROBE_STDERR_BUDGET)
        help_text = ((help_result.stdout or b"").decode("utf-8", errors="replace")
                     if isinstance(getattr(help_result, "stdout", b""), bytes)
                     else str(getattr(help_result, "stdout", "")))
        help_text += ((help_result.stderr or b"").decode("utf-8", errors="replace")
                      if isinstance(getattr(help_result, "stderr", b""), bytes)
                      else str(getattr(help_result, "stderr", "")))
    missing = check_security_flags_available(help_text or "")
    finished_flag = clock()
    if missing:
        return ProbeExecutionResult(
            run_id, str(attempt), endpoint.to_dict(), candidate_cve,
            approved.template_id, str(template_abs), template_sha,
            NucleiExecutionStatus.FAILED, started.isoformat(), finished_flag.isoformat(),
            max(0.0, (finished_flag - started).total_seconds()), None, None, (),
            False, False, NUCLEI_SECURITY_FLAG_UNAVAILABLE,
            f"required Nuclei security flags unavailable: {', '.join(missing)}",
            **app_scope)
    argv = build_nuclei_argv(config, template_path=template_abs, target_url=target,
                             security_flags=select_security_flags(help_text or ""))
    if template_container_root is not None:
        # In-container execution: swap only the -t value for the validated
        # mapped mount path. Identity/hash stay bound to the host file.
        runtime_template = container_template_path(
            template_abs, config.template_root, template_container_root)
        argv = tuple(runtime_template if (i > 0 and argv[i - 1] == "-t") else item
                     for i, item in enumerate(argv))
    else:
        runtime_template = str(template_abs)
    result = backend.run(argv, timeout=config.process_timeout,
                         stdout_budget=config.stdout_budget_bytes,
                         stderr_budget=config.stderr_budget_bytes)
    finished = clock()
    duration = max(0.0, (finished - started).total_seconds())
    base_kwargs: dict[str, Any] = dict(
        run_id=run_id, attempt=str(attempt), endpoint_identity=endpoint.to_dict(),
        candidate_cve=candidate_cve, template_id=approved.template_id,
        template_path=str(template_abs), template_sha256=template_sha,
        template_runtime_path=runtime_template,
        started_at=started.isoformat(), finished_at=finished.isoformat(),
        duration_seconds=duration, **app_scope)

    def _reachability() -> bool | None:
        if reachability is None:
            return None
        try:
            return reachability(endpoint)
        except Exception:
            return False

    raw_stdout = getattr(result, "stdout", b"") or b""
    if isinstance(raw_stdout, str):
        raw_stdout = raw_stdout.encode()
    if getattr(result, "timed_out", False):
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.TIMED_OUT,
            reachable=_reachability(), exit_code=getattr(result, "exit_code", None),
            records=(), stdout_truncated=False, stderr_truncated=False,
            error_code=NUCLEI_TIMEOUT, error_detail="per-template timeout exceeded",
            raw_stdout=raw_stdout)
    stdout = raw_stdout
    stderr = getattr(result, "stderr", b"") or b""
    if isinstance(stderr, str):
        stderr = stderr.encode()
    stdout_over = bool(getattr(result, "stdout_truncated", False)
                       ) or len(stdout) > config.stdout_budget_bytes
    stderr_over = bool(getattr(result, "stderr_truncated", False)
                       ) or len(stderr) > config.stderr_budget_bytes
    if stdout_over or stderr_over:
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.BUDGET_EXCEEDED,
            reachable=_reachability(), exit_code=getattr(result, "exit_code", None),
            records=(), stdout_truncated=stdout_over, stderr_truncated=stderr_over,
            error_code=NUCLEI_OUTPUT_BUDGET_EXCEEDED, error_detail="output budget exceeded",
            raw_stdout=stdout)
    exit_code = getattr(result, "exit_code", 1)
    # Decode + record-count budgets before trusting output.
    try:
        outcome = parse_nuclei_jsonl(stdout)
    except UnicodeDecodeError:
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.INVALID_OUTPUT,
            reachable=_reachability(), exit_code=exit_code, records=(),
            error_code=NUCLEI_INVALID_JSONL, error_detail="stdout is not valid UTF-8",
            raw_stdout=stdout)
    if len(outcome.records) > config.max_records:
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.BUDGET_EXCEEDED,
            reachable=_reachability(), exit_code=exit_code, records=outcome.records[:config.max_records],
            stdout_truncated=True, error_code=NUCLEI_OUTPUT_BUDGET_EXCEEDED,
            error_detail="record budget exceeded", raw_stdout=stdout)
    if outcome.malformed_line is not None:
        if exit_code == 0:
            return ProbeExecutionResult(
                **base_kwargs, execution_status=NucleiExecutionStatus.INVALID_OUTPUT,
                reachable=_reachability(), exit_code=exit_code, records=outcome.records,
                error_code=NUCLEI_INVALID_JSONL,
                error_detail=f"malformed JSONL at line {outcome.malformed_line}",
                raw_stdout=stdout)
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.PARTIAL_OUTPUT,
            reachable=_reachability(), exit_code=exit_code, records=outcome.records,
            error_code=NUCLEI_PARTIAL_OUTPUT,
            error_detail=f"truncated/invalid JSONL at line {outcome.malformed_line}",
            raw_stdout=stdout)
    if exit_code != 0:
        # Valid records already emitted but the process failed -> partial.
        if outcome.records:
            return ProbeExecutionResult(
                **base_kwargs, execution_status=NucleiExecutionStatus.PARTIAL_OUTPUT,
                reachable=_reachability(), exit_code=exit_code, records=outcome.records,
                error_code=NUCLEI_PARTIAL_OUTPUT,
                error_detail=f"process exited {exit_code} after emitting records",
                raw_stdout=stdout)
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.FAILED,
            reachable=_reachability(), exit_code=exit_code, records=(),
            error_code=NUCLEI_EXECUTION_FAILED, error_detail=f"process exited {exit_code}",
            raw_stdout=stdout)
    # Trusted completion requires proven sandbox-namespace reachability: an
    # exit-0 zero-match run with unknown or failed reachability must never
    # look like completed coverage to a future NOT_OBSERVED derivation.
    reachable_value = _reachability()
    if reachable_value is not True:
        if reachable_value is False:
            detail = ("endpoint was not reachable from the sandbox namespace; "
                      "output is not trusted coverage")
        else:
            detail = ("endpoint reachability is unknown; "
                      "output is not trusted coverage")
        return ProbeExecutionResult(
            **base_kwargs, execution_status=NucleiExecutionStatus.FAILED,
            reachable=reachable_value, exit_code=exit_code, records=outcome.records,
            error_code=DYNAMIC_TARGET_NOT_REACHABLE, error_detail=detail,
            raw_stdout=stdout)
    return ProbeExecutionResult(
        **base_kwargs, execution_status=NucleiExecutionStatus.SUCCEEDED,
        reachable=reachable_value, exit_code=exit_code, records=outcome.records,
        raw_stdout=stdout)
