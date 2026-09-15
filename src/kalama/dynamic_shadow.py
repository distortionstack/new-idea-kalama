"""Wave 3 opt-in SHADOW dynamic-probe integration (BEFORE-prioritization evidence).

Shadow placement: runs after Step 3 (priority-v1) completes, operating on
the committed Top-N candidates as validation only. The Top30 artifact and
priority-v1 scores/ranking are never modified; all dynamic output lands in
separate attempt-scoped immutable artifacts plus one state artifact
reference. ``score_delta`` is always 0.

No priority-v2, no scoring change, no AFTER probing in this Wave.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping, Sequence

from .dynamic_probe import (
    ApprovedTemplate,
    ApprovedTemplateManifest,
    DynamicEndpoint,
    DynamicEvidence,
    DynamicSignal,
    HttpApplicationEndpoint,
    TemplatePolicyError,
    load_approved_template_manifest,
    normalize_http_base_path,
    sha256_file,
    template_tree_sha256,
)
from .dynamic_probe_runtime import (
    NUCLEI_EXECUTION_FAILED,
    ContainerExecBackend,
    NucleiExecutionStatus,
    NucleiRunnerConfig,
    ProbeExecutionResult,
    ProbeSandbox,
    SandboxConfig,
    SandboxError,
    SandboxReachabilityProbe,
    execute_single_template,
    resolve_candidates_to_templates,
    runtime_preflight_template,
)
from .state.models import (
    ArtifactKind,
    ArtifactReference,
    IntegrationFailureCode,
    PipelineStage,
    RunError,
    RunNotice,
    RunState,
    RunStatus,
    StageStatus,
)
from .state.store import StateStore, utc_text
from .target.victim_manager import SubprocessCommandRunner


DYNAMIC_SHADOW_SCHEMA = "kalama.dynamic-shadow/v1"
DYNAMIC_RESULT_SCHEMA = "kalama.dynamic-result/v1"
DYNAMIC_TEMPLATES_SCHEMA = "kalama.dynamic-templates/v1"

DYNAMIC_PROVIDER = "nuclei"
DYNAMIC_PROFILE = "safe-cve-http"
DYNAMIC_PHASE = "before"
DYNAMIC_CONTAINER_TEMPLATE_ROOT = "/templates"

ENV_MANIFEST = "KALAMA_NUCLEI_MANIFEST"
ENV_TEMPLATE_ROOT = "KALAMA_NUCLEI_TEMPLATE_ROOT"
ENV_BINARY = "KALAMA_NUCLEI_BINARY"
ENV_RUNNER_IMAGE = "KALAMA_NUCLEI_RUNNER_IMAGE"
ENV_PORT = "KALAMA_NUCLEI_PORT"
ENV_CONTAINER_TEMPLATES = "KALAMA_NUCLEI_CONTAINER_TEMPLATES"
ENV_APP_PATHS = "KALAMA_NUCLEI_APP_PATHS"

DEFAULT_ROOT_SOURCE = "default_root"
REVIEWED_APP_SOURCE = "explicit_reviewed_binding"
MAX_APP_PATHS = 8


class DynamicShadowError(RuntimeError):
    """Structured Wave 3 failure with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DynamicShadowConfig:
    enabled: bool = False
    profile: str = DYNAMIC_PROFILE
    required: bool = False
    phase: str = DYNAMIC_PHASE
    manifest_path: Path | None = None
    template_root: Path | None = None
    nuclei_binary: str = "nuclei"
    runner_image: str | None = None
    container_template_root: str = DYNAMIC_CONTAINER_TEMPLATE_ROOT
    port: int | None = None
    # Reviewed HTTP application scopes. "/" is always first (legacy
    # root-only scope preserved); extras come only from explicit reviewed
    # run-level input, never from crawling, fuzzing, or CVE inference.
    app_paths: tuple[str, ...] = ("/",)


def dynamic_config_from_env(*, dynamic_scan: str, nuclei_profile: str,
                            required: bool,
                            env: Mapping[str, str] | None = None) -> DynamicShadowConfig:
    """Build shadow config from CLI options + environment. No execution."""
    if dynamic_scan not in ("off", "nuclei"):
        raise ValueError(f"DYNAMIC_CONFIG_INVALID: --dynamic-scan must be off|nuclei, got {dynamic_scan!r}")
    if nuclei_profile != DYNAMIC_PROFILE:
        raise ValueError(f"DYNAMIC_CONFIG_INVALID: unsupported nuclei profile {nuclei_profile!r}")
    source = env if env is not None else os.environ
    manifest = source.get(ENV_MANIFEST, "").strip() or None
    root = source.get(ENV_TEMPLATE_ROOT, "").strip() or None
    port_text = source.get(ENV_PORT, "").strip() or None
    port = None
    if port_text is not None:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"DYNAMIC_CONFIG_INVALID: {ENV_PORT} must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"DYNAMIC_CONFIG_INVALID: {ENV_PORT} out of range")
    app_paths = parse_app_paths(source.get(ENV_APP_PATHS, ""))
    return DynamicShadowConfig(
        enabled=dynamic_scan == "nuclei", profile=nuclei_profile, required=required,
        manifest_path=Path(manifest) if manifest else None,
        template_root=Path(root) if root else None,
        nuclei_binary=source.get(ENV_BINARY, "").strip() or "nuclei",
        runner_image=source.get(ENV_RUNNER_IMAGE, "").strip() or None,
        container_template_root=source.get(ENV_CONTAINER_TEMPLATES, "").strip()
        or DYNAMIC_CONTAINER_TEMPLATE_ROOT,
        port=port, app_paths=app_paths)


def parse_app_paths(raw: str | None) -> tuple[str, ...]:
    """Reviewed run-level application scopes. Root is always first.

    Extra paths come only from explicit operator input (comma-separated);
    each is normalized and validated fail-closed. "/" is always probed to
    preserve legacy root-only behavior. No crawling, fuzzing, or
    CVE-derived inference anywhere.
    """
    paths = ["/"]
    for chunk in (raw or "").split(","):
        text = chunk.strip()
        if not text:
            continue
        try:
            normalized = normalize_http_base_path(text)
        except ValueError as exc:
            raise ValueError(f"DYNAMIC_CONFIG_INVALID: {ENV_APP_PATHS} rejects {text!r}: {exc}") from exc
        if normalized not in paths:
            paths.append(normalized)
    if len(paths) > MAX_APP_PATHS:
        raise ValueError(f"DYNAMIC_CONFIG_INVALID: {ENV_APP_PATHS} allows at most "
                         f"{MAX_APP_PATHS} application paths")
    return tuple(paths)


def app_path_source(base_path: str) -> str:
    """Provenance label: legacy root scope vs explicit reviewed binding."""
    return DEFAULT_ROOT_SOURCE if base_path == "/" else REVIEWED_APP_SOURCE


def build_application_endpoints(endpoint: DynamicEndpoint,
                                app_paths: Sequence[str]) -> tuple[HttpApplicationEndpoint, ...]:
    """Bind one network endpoint to every approved application scope."""
    return tuple(HttpApplicationEndpoint(endpoint, path, app_path_source(path))
                 for path in app_paths)


# ---------------------------------------------------------------------------
# Artifact layout + atomic writes
# ---------------------------------------------------------------------------

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_artifact_component(value: str) -> str:
    cleaned = _SAFE_COMPONENT_RE.sub("_", value.strip())
    return cleaned if cleaned else "_"


def dynamic_dir(output_root: Path, run_id: str) -> Path:
    return output_root / "dynamic" / DYNAMIC_PHASE / run_id


def _artifact_paths(base_dir: Path, run_id: str, attempt: int,
                    cve_id: str, template_id: str,
                    base_path: str = "/") -> dict[str, Path]:
    safe_cve = sanitize_artifact_component(cve_id)
    safe_template = sanitize_artifact_component(template_id)
    core = f"{run_id}_attempt_{attempt}_{safe_cve}_{safe_template}"
    if base_path != "/":
        # Distinct files per application scope; root keeps legacy names.
        core += f"_{sanitize_artifact_component(base_path)}"
    paths = {
        "raw": base_dir / f"dynamic_nuclei_{core}.jsonl",
        "result": base_dir / f"dynamic_nuclei_result_{core}.json",
    }
    for path in paths.values():
        if path.resolve(strict=False).parent != base_dir.resolve(strict=False):
            raise DynamicShadowError("DYNAMIC_ARTIFACT_TRAVERSAL",
                                     "artifact path escapes the attempt directory")
    return paths


def resolved_manifest_path(base_dir: Path, run_id: str, attempt: int) -> Path:
    return base_dir / f"dynamic_nuclei_templates_{run_id}_attempt_{attempt}.json"


def shadow_summary_path(base_dir: Path, run_id: str, attempt: int) -> Path:
    return base_dir / f"dynamic_shadow_{run_id}_attempt_{attempt}.json"


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomic immutable write (temp + fsync + replace), mirroring repo convention."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise DynamicShadowError("DYNAMIC_ARTIFACT_EXISTS",
                                 f"refusing to overwrite immutable artifact {path}")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as handle:
            temporary = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise DynamicShadowError("DYNAMIC_ARTIFACT_WRITE_FAILED",
                                 f"cannot persist dynamic artifact {path}: {exc}") from exc


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execution_result_manifest(result: ProbeExecutionResult, *,
                              provenance: Mapping[str, Any]) -> dict[str, Any]:
    """Full provenance manifest for one template execution (pure)."""
    return {
        "schema": DYNAMIC_RESULT_SCHEMA,
        "run_id": result.run_id,
        "attempt": result.attempt,
        "phase": provenance.get("phase", DYNAMIC_PHASE),
        "candidate_cve": result.candidate_cve,
        "template_id": result.template_id,
        "template_sha256": result.template_sha256,
        "template_path": result.template_path,
        "template_runtime_path": result.template_runtime_path,
        "nuclei": dict(provenance.get("nuclei", {})),
        "template_manifest": dict(provenance.get("template_manifest", {})),
        "endpoint": dict(result.endpoint_identity),
        "base_path": result.base_path,
        "base_path_source": result.base_path_source,
        "application_endpoint_key": result.application_endpoint_key,
        "effective_target_url": result.effective_target_url,
        "sandbox_network": result.endpoint_identity.get("network"),
        "container_id": result.endpoint_identity.get("container_id"),
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_seconds": result.duration_seconds,
        "execution_status": result.execution_status.value,
        "reachable": result.reachable,
        "reachability_tool": provenance.get("reachability_tool"),
        "exit_code": result.exit_code,
        "error_code": result.error_code,
        "error_detail": result.error_detail,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "match_count": len(result.records),
        "raw_artifact": dict(provenance.get("raw_artifact", {})),
    }


def resolved_template_manifest(*, run_id: str, attempt: int, phase: str,
                               manifest: ApprovedTemplateManifest,
                               manifest_sha256: str,
                               resolutions: Sequence[Any],
                               app_endpoints: Sequence[HttpApplicationEndpoint] = ()
                               ) -> dict[str, Any]:
    """Persisted candidate->template resolution snapshot (pure)."""
    return {
        "schema": DYNAMIC_TEMPLATES_SCHEMA,
        "run_id": run_id,
        "attempt": attempt,
        "phase": phase,
        "profile": manifest.profile,
        "template_revision": manifest.template_revision,
        "manifest_sha256": manifest_sha256,
        "application_endpoints": [
            {"base_path": app.base_path, "base_path_source": app.base_path_source,
             "application_endpoint_key": app.application_endpoint_key}
            for app in app_endpoints],
        "resolutions": [
            {"candidate_id": item.candidate_id, "cve_id": item.cve_id,
             "resolution_status": item.resolution_status.value,
             "templates": [
                 {"template_id": template.template_id,
                  "relative_path": template.relative_path,
                  "expected_sha256": template.expected_sha256,
                  "mapped_cves": list(template.mapped_cves)}
                 for template in item.templates]}
            for item in resolutions],
    }


# ---------------------------------------------------------------------------
# Normalization (execution -> DynamicEvidence) + identity + correlation
# ---------------------------------------------------------------------------

def normalize_evidence(result: ProbeExecutionResult, *,
                       run_id: str, phase: str, attempt: str,
                       container_id: str,
                       raw_artifact_path: str, raw_artifact_sha256: str,
                       execution_manifest_path: str) -> list[DynamicEvidence]:
    """Trusted SUCCEEDED executions with matches -> DynamicEvidence.

    Zero-match, untrusted, or unreachable executions yield no evidence items
    (never invented). No package identity is inferred anywhere.
    """
    if result.execution_status != NucleiExecutionStatus.SUCCEEDED:
        return []
    if result.reachable is not True or not result.records:
        return []
    endpoint_key = result.endpoint_identity.get("endpoint_key")
    if not isinstance(endpoint_key, str) or not endpoint_key:
        return []
    items = []
    for record in result.records:
        items.append(DynamicEvidence(
            endpoint_key=endpoint_key, template_id=result.template_id, matched=True,
            matcher_name=record.matcher_name, cve_id=record.cve_id,
            metadata={
                "run_id": run_id, "phase": phase, "attempt": attempt,
                "container_id": container_id, "candidate_cve": result.candidate_cve,
                "template_sha256": result.template_sha256,
                "matched_at": record.matched_at, "host": record.host,
                "severity": record.severity,
                "execution_status": result.execution_status.value,
                "reachable": result.reachable,
                "base_path": result.base_path,
                "base_path_source": result.base_path_source,
                "application_endpoint_key": result.application_endpoint_key,
                "effective_target_url": result.effective_target_url,
                "raw_artifact_path": raw_artifact_path,
                "raw_artifact_sha256": raw_artifact_sha256,
                "execution_manifest_path": execution_manifest_path,
            }))
    return items


def dynamic_evidence_identity(run_id: str, phase: str,
                              evidence: DynamicEvidence) -> tuple[str, ...]:
    """Evidence identity: run/phase/endpoint/template/matcher/CVE. No package."""
    metadata = evidence.metadata if isinstance(evidence.metadata, Mapping) else {}
    return (run_id, phase, evidence.endpoint_key, evidence.template_id,
            evidence.matcher_name or "", evidence.cve_id or "",
            str(metadata.get("attempt", "")))


def correlate_evidence(items: Sequence[DynamicEvidence], *, run_id: str,
                       cve_id: str, manifest: ApprovedTemplateManifest,
                       endpoint_key: str) -> list[DynamicEvidence]:
    """Exact correlation only: same run, exact CVE, approved template mapped
    to that CVE, current-run endpoint. No fuzzy/alias/GHSA/package logic."""
    approved = {template.template_id for template in manifest.templates
                if cve_id in template.mapped_cves}
    correlated = []
    for item in items:
        metadata = item.metadata if isinstance(item.metadata, Mapping) else {}
        if metadata.get("run_id") != run_id:
            continue
        if metadata.get("candidate_cve") != cve_id:
            continue
        if item.template_id not in approved:
            continue
        if item.endpoint_key != endpoint_key:
            continue
        correlated.append(item)
    return correlated


# ---------------------------------------------------------------------------
# Signal derivation (pure)
# ---------------------------------------------------------------------------

MATCHED = "matched"
CLEAN = "clean"
INCOMPLETE = "incomplete"


def binding_key(template_id: str, record: Mapping[str, Any]) -> str:
    """Signal-derivation identity: one template bound to one base path.

    The ``template@path`` key lets the unchanged ``derive_dynamic_signal``
    aggregate multi-path coverage: any MATCHED binding corroborates, all
    CLEAN bindings are required for NOT_OBSERVED, anything else is
    INCONCLUSIVE. Records predating application scopes default to root.
    """
    base = record.get("base_path", "/")
    path = base if isinstance(base, str) and base else "/"
    return f"{template_id}@{path}"


def classify_execution(result: ProbeExecutionResult) -> str:
    """Trusted completed match/zero-match vs incomplete (pure)."""
    if result.execution_status == NucleiExecutionStatus.SUCCEEDED and result.reachable is True:
        return MATCHED if result.records else CLEAN
    return INCOMPLETE


def derive_dynamic_signal(*, enabled: bool, resolved: bool = True,
                          applicable_templates: Sequence[str] = (),
                          outcomes: Mapping[str, str] | None = None) -> DynamicSignal:
    """Approved taxonomy derivation (pure). Never yields NOT_VULNERABLE."""
    if not enabled:
        return DynamicSignal.NOT_RUN
    if not resolved:
        return DynamicSignal.INCONCLUSIVE
    applicable = [str(item) for item in applicable_templates]
    if not applicable:
        return DynamicSignal.NOT_APPLICABLE
    table = outcomes or {}
    states = [table.get(template, INCOMPLETE) for template in applicable]
    if any(state == MATCHED for state in states):
        return DynamicSignal.CORROBORATED
    if all(state == CLEAN for state in states):
        return DynamicSignal.NOT_OBSERVED
    return DynamicSignal.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Endpoint + Top30 helpers (pure)
# ---------------------------------------------------------------------------

def _as_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 1 <= value <= 65535:
        return value
    return None


def _is_routable_listen_address(value: Any) -> bool:
    """True unless the address is loopback (e.g. docker's 127.0.0.11 stub).

    A listening entry on loopback names a port that is NOT reachable on the
    container's sandbox IP, so it must never select the probe port.
    """
    import ipaddress as _ipaddress
    try:
        return not _ipaddress.ip_address(str(value)).is_loopback
    except ValueError:
        return False


def select_probe_port(facts: Mapping[str, Any] | None, *,
                      override: int | None = None) -> int | None:
    """Smallest deterministic port choice for the sandbox namespace.

    Order: image-declared exposed TCP service ports, then observed
    non-loopback listening TCP ports, then published container ports, then
    host-view reachable ports (least appropriate inside the sandbox, kept as
    a last resort that fails closed to INCONCLUSIVE when wrong). None means
    no eligible endpoint (-> NOT_RUN).
    """
    if override is not None:
        return override if 1 <= override <= 65535 else None
    if not isinstance(facts, Mapping):
        return None

    def tcp_ports(entries: Any) -> list[int]:
        ports: list[int] = []
        if not isinstance(entries, (list, tuple)):
            return ports
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("protocol", "tcp")).lower() != "tcp":
                continue
            port = _as_port(entry.get("container_port"))
            if port is not None:
                ports.append(port)
        return ports

    for port in tcp_ports(facts.get("exposed_ports")):
        return port
    entries = facts.get("listening_ports")
    if isinstance(entries, (list, tuple)):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("protocol", "tcp")).lower() != "tcp":
                continue
            if not _is_routable_listen_address(entry.get("address")):
                continue
            port = _as_port(entry.get("container_port"))
            if port is not None:
                return port
    for port in tcp_ports(facts.get("published_ports")):
        return port
    reachable = facts.get("reachable_ports") or ()
    if isinstance(reachable, (list, tuple)):
        for port in reachable:
            if _as_port(port) is not None:
                return int(port)
    return None


def build_probe_endpoint(*, run_id: str, facts: Mapping[str, Any],
                         port: int) -> DynamicEndpoint | None:
    """Run-bound endpoint from Step 2 target facts. None when ineligible."""
    try:
        ip_address = facts.get("ip_address")
        network = facts.get("network")
        container_id = facts.get("container_id")
        container_name = facts.get("container_name")
        if not all(isinstance(value, str) and value.strip() for value in (
                ip_address, network, container_id, container_name)):
            return None
        return DynamicEndpoint(run_id, container_id, container_name, network,
                               ip_address, port, "http", "READY")
    except (ValueError, TypeError):
        return None


def read_top30_candidates(top30_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Minimal candidate extraction from a committed Top30 artifact."""
    try:
        data = json.loads(top30_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE",
                                 f"cannot read committed Top30 artifact: {exc}") from exc
    if not isinstance(data, Mapping) or data.get("schema") != "kalama.prioritization/v1":
        raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE",
                                 "Top30 artifact has an incompatible schema")
    ranked = data.get("ranked_cves")
    if not isinstance(ranked, list):
        raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE", "Top30 ranked_cves missing")
    candidates = []
    for entry in ranked:
        if not isinstance(entry, Mapping):
            raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE", "Top30 entry malformed")
        cve_id = entry.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE", "Top30 entry lacks cve_id")
        candidates.append({"rank": entry.get("rank"), "cve_id": cve_id,
                           "score": entry.get("score")})
    meta = data.get("artifact") if isinstance(data.get("artifact"), Mapping) else {}
    return candidates, {"top_n_returned": meta.get("top_n_returned"),
                        "top_n_requested": meta.get("top_n_requested")}


def probe_nuclei_identity(exec_backend: Any, binary: str, *,
                          timeout: float = 15.0) -> dict[str, str | None]:
    """Best-effort Nuclei version/hash provenance via the runner namespace.

    Version is read from stdout, falling back to stderr (Nuclei logs its
    version line on stderr). The hash needs a file path, not a PATH-resolved
    name, so bounded absolute candidates are tried explicitly, all shell-free.
    Anything unavailable stays None; identity never aborts execution.
    """
    version: str | None = None
    digest: str | None = None
    try:
        result = exec_backend.run((binary, "-version"), timeout=timeout,
                                  stdout_budget=65536, stderr_budget=65536)
        for stream in (getattr(result, "stdout", b""), getattr(result, "stderr", b"")):
            raw = stream or b""
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            first = text.strip().splitlines()
            if first and first[0].strip():
                version = first[0].strip()[:200]
                break
    except Exception:
        version = None
    candidates = [binary] if "/" in binary else [
        binary, f"/usr/local/bin/{binary}", f"/usr/bin/{binary}"]
    for candidate in candidates:
        try:
            result = exec_backend.run(("sha256sum", candidate), timeout=timeout,
                                      stdout_budget=65536, stderr_budget=65536)
            if getattr(result, "exit_code", 1) != 0:
                continue
            stdout = getattr(result, "stdout", b"") or b""
            text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else ""
            token = text.strip().split()
            if token and re.fullmatch(r"[0-9a-f]{64}", token[0].lower()):
                digest = token[0].lower()
                break
        except Exception:
            continue
    return {"version": version, "sha256": digest}


# ---------------------------------------------------------------------------
# Resume: verified prior executions
# ---------------------------------------------------------------------------

def stable_target_identity(container_id: str | None, scheme: str | None,
                             port: int | None, base_path: str | None
                             ) -> tuple[str, str, int, str] | None:
    """Stable application-target identity for resume reuse decisions.

    Equivalent to (run_id, container_id, scheme, service port, normalized
    base path); run_id is enforced separately by the caller. Ephemeral
    sandbox IP/network are execution provenance only and never part of
    this identity. Returns None when any component is missing or invalid,
    which callers treat as not reusable.
    """
    if (not isinstance(container_id, str) or not container_id.strip()
            or scheme not in {"http", "https"}
            or not isinstance(port, int) or not 1 <= port <= 65535):
        return None
    try:
        normalized = normalize_http_base_path(
            base_path if isinstance(base_path, str) else "/")
    except ValueError:
        return None
    return (container_id, scheme, port, normalized)


def load_verified_results(base_dir: Path, run_id: str, *,
                           manifest_entries: Mapping[str, str],
                           manifest_sha256: str,
                           expected_container_id: str | None = None,
                           expected_scheme: str | None = None,
                           expected_port: int | None = None
                           ) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Hash-verified completed executions. File existence alone never counts.

    A recorded execution counts only when: its raw file exists with matching
    SHA-256, recorded template SHA matches the current manifest entry,
    recorded manifest SHA matches the current manifest, status is SUCCEEDED
    and reachable is True, and its stable target identity (container,
    scheme, port, base path) matches the current probe target. Keys are
    (CVE, template, base path); the full application endpoint key stays
    execution provenance only, since sandbox IPs are DHCP-assigned per
    attempt. Records written before application scopes existed carry no
    base path and count as the legacy root scope. When expected target
    identity is supplied, an execution produced against a different
    container (or scheme/port) is never reused.
    """
    verified: dict[tuple[str, str], dict[str, Any]] = {}
    if not base_dir.is_dir():
        return verified
    for path in sorted(base_dir.glob(f"dynamic_nuclei_result_{run_id}_attempt_*.json")):
        try:
            record = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(record, Mapping):
            continue
        cve_id = record.get("candidate_cve")
        template_id = record.get("template_id")
        raw = record.get("raw_artifact") if isinstance(record.get("raw_artifact"), Mapping) else {}
        raw_path = raw.get("path")
        raw_sha = raw.get("sha256")
        try:
            if (record.get("schema") != DYNAMIC_RESULT_SCHEMA
                    or record.get("run_id") != run_id
                    or not isinstance(cve_id, str) or not isinstance(template_id, str)
                    or record.get("execution_status") != NucleiExecutionStatus.SUCCEEDED.value
                    or record.get("reachable") is not True
                    or not isinstance(raw_path, str) or not isinstance(raw_sha, str)):
                continue
            actual = hashlib.sha256(Path(raw_path).read_bytes()).hexdigest()
            if actual != raw_sha:
                continue
            if manifest_entries.get(template_id) != record.get("template_sha256"):
                continue
            template_manifest = record.get("template_manifest")
            if not isinstance(template_manifest, Mapping) or template_manifest.get(
                    "sha256") != manifest_sha256:
                continue
            if expected_container_id is not None:
                endpoint = record.get("endpoint")
                endpoint = endpoint if isinstance(endpoint, Mapping) else {}
                recorded = stable_target_identity(
                    record.get("container_id"), endpoint.get("scheme"),
                    endpoint.get("port"), record.get("base_path", "/"))
                current = stable_target_identity(
                    expected_container_id, expected_scheme, expected_port,
                    record.get("base_path", "/"))
                if recorded is None or current is None or recorded != current:
                    continue
        except (OSError, ValueError):
            continue
        attempt = record.get("attempt")
        base = record.get("base_path", "/")
        key = (cve_id, template_id, base if isinstance(base, str) and base else "/")
        current = verified.get(key)
        if current is None or str(attempt) > str(current.get("attempt")):
            verified[key] = dict(record)
    return verified


# ---------------------------------------------------------------------------
# Shadow summary (pure assembly)
# ---------------------------------------------------------------------------

def build_shadow_summary(*, run_id: str, phase: str, attempt: int,
                         created_at: str, candidates: Sequence[Mapping[str, Any]],
                         top_context: Mapping[str, Any],
                         top30_sha256: str,
                         inputs: Mapping[str, Any],
                         signals: Mapping[str, DynamicSignal],
                         evidence_refs: Mapping[str, list[dict[str, Any]]],
                         execution_refs: Mapping[str, list[dict[str, Any]]],
                         template_lists: Mapping[str, list[str]],
                         binding_lists: Mapping[str, list[dict[str, str]]] | None = None,
                         notices: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
    summary = {
        "schema": DYNAMIC_SHADOW_SCHEMA,
        "artifact": {"kind": "dynamic_shadow_before", "run_id": run_id,
                     "phase": phase, "attempt": attempt, "created_at": created_at,
                     "candidate_universe": "top_n",
                     "top_n": top_context.get("top_n_returned")},
        "inputs": dict(inputs),
        "priority_v1": {"score_model": "kalama-priority-v1",
                        "top30_sha256": top30_sha256, "unchanged": True},
        "candidates": [],
        "notices": list(notices),
    }
    for candidate in candidates:
        cve_id = candidate["cve_id"]
        signal = signals.get(cve_id, DynamicSignal.INCONCLUSIVE)
        summary["candidates"].append({
            "rank": candidate.get("rank"), "cve_id": cve_id,
            "score": candidate.get("score"),
            "applicable_templates": list(template_lists.get(cve_id, [])),
            "applicable_bindings": list((binding_lists or {}).get(cve_id, [])),
            "signal": signal.value,
            "dynamic_validation": {
                "provider": DYNAMIC_PROVIDER, "profile": DYNAMIC_PROFILE,
                "signal": signal.value, "score_delta": 0,
                "evidence_refs": list(evidence_refs.get(cve_id, [])),
                "execution_refs": list(execution_refs.get(cve_id, [])),
            },
        })
    return summary


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class DynamicShadowOrchestrator:
    """Opt-in shadow probing after Step 3. Never modifies v1 outputs."""

    def __init__(self, store: StateStore, *,
                 clock: Callable[[], datetime] | None = None,
                 command_runner: Any | None = None,
                 sandbox_factory: Callable[[SandboxConfig], Any] | None = None,
                 backend_factory: Callable[[str], Any] | None = None,
                 reachability_factory: Callable[[Any, str], Any] | None = None):
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._command_runner = command_runner
        self._sandbox_factory = sandbox_factory
        self._backend_factory = backend_factory
        self._reachability_factory = reachability_factory

    # -- injectable runtime pieces (production defaults) ------------------
    def _cli_runner(self) -> Any:
        return self._command_runner or SubprocessCommandRunner()

    def _sandbox(self, config: SandboxConfig) -> Any:
        if self._sandbox_factory is not None:
            return self._sandbox_factory(config)
        return ProbeSandbox(config, self._cli_runner())

    def _exec_backend(self, runner_container: str) -> Any:
        if self._backend_factory is not None:
            return self._backend_factory(runner_container)
        return ContainerExecBackend(runner_container)

    def _reachability(self, runner_container: str) -> Any:
        if self._reachability_factory is not None:
            return self._reachability_factory(self._cli_runner(), runner_container)
        return SandboxReachabilityProbe(self._cli_runner(), runner_container)

    def _now(self) -> str:
        return utc_text(self.clock())

    # -- state transitions (existing conventions) -------------------------
    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _warn(self, run_id: str, code: str, message: str) -> RunState:
        timestamp = self._now()
        state = self.store.load(run_id)
        state = replace(state, warnings=state.warnings + (
            RunNotice(code, message, timestamp),), updated_at=timestamp)
        return self._save(state)

    def _fail_required(self, run_id: str, code: str, message: str, *,
                       details: Mapping[str, Any] | None = None) -> RunState:
        timestamp = self._now()
        state = self.store.load(run_id)
        state = state.with_stage(PipelineStage.STEP_3_PRIORITIZATION,
                                 StageStatus.FAILED, timestamp)
        error = RunError(f"E{len(state.errors) + 1:04d}",
                         PipelineStage.STEP_3_PRIORITIZATION, code, message,
                         timestamp, False, tuple(sorted((details or {}).items())))
        state = replace(state, status=RunStatus.FAILED_FATAL,
                        current_stage=PipelineStage.STEP_3_PRIORITIZATION,
                        errors=state.errors + (error,), updated_at=timestamp)
        return self._save(state)

    # -- main entry --------------------------------------------------------
    def run_shadow(self, run_id: str, config: DynamicShadowConfig) -> RunState:
        """Total function: never raises dynamic-subsystem errors.

        Feature off returns state untouched. Best-effort records INCONCLUSIVE
        + warnings and preserves PAUSED. Required fails the run through the
        existing FAILED_FATAL transition after persisting artifacts.
        """
        state = self.store.load(run_id)
        if not config.enabled:
            return state
        base_dir = dynamic_dir(self.store.output_root, run_id)
        timestamp = self._now()
        try:
            return self._run_attempts(run_id, config, base_dir, timestamp)
        except DynamicShadowError as exc:
            return self._finish_with_error(run_id, config, exc.code, str(exc))
        except Exception as exc:  # fail closed, never leak an exception type
            return self._finish_with_error(run_id, config, "DYNAMIC_PROBE_FAILED",
                                           f"dynamic shadow failed: {type(exc).__name__}: {exc}")

    def _finish_with_error(self, run_id: str, config: DynamicShadowConfig,
                           code: str, message: str) -> RunState:
        if config.required:
            return self._fail_required(run_id, code, message)
        state = self._warn(run_id, code, message)
        return state

    def _run_attempts(self, run_id: str, config: DynamicShadowConfig,
                      base_dir: Path, timestamp: str) -> RunState:
        top30_ref = self.store.load(run_id).artifact(ArtifactKind.TOP30_BEFORE)
        if top30_ref is None:
            raise DynamicShadowError("DYNAMIC_TOP30_UNREADABLE",
                                     "no committed Top30 artifact for shadow probing")
        top30_path = Path(top30_ref.path)
        top30_before_sha = sha256_file(top30_path) if top30_path.is_file() else None
        candidates, top_context = read_top30_candidates(top30_path)
        cve_ids = [item["cve_id"] for item in candidates]

        manifest, manifest_sha, manifest_error = self._load_manifest(config)
        if manifest is None:
            # Missing capability: applicability unknown -> INCONCLUSIVE.
            signals = {cve_id: DynamicSignal.INCONCLUSIVE for cve_id in cve_ids}
            return self._publish(run_id, config, base_dir, timestamp, candidates,
                                 top_context, top30_ref, top30_before_sha,
                                 manifest=None, manifest_sha=None,
                                 endpoint=None, resolutions=(),
                                 outcomes={}, evidence_refs={},
                                 refs_by_cve={}, templates_by_cve={},
                                 signals=signals,
                                 notices=[{"code": "DYNAMIC_PROBE_INCONCLUSIVE",
                                           "message": manifest_error or "template manifest unavailable"}])

        resolutions = resolve_candidates_to_templates(cve_ids, manifest)
        resolution_by_cve = {item.cve_id: item for item in resolutions}
        templates_by_cve = {item.cve_id: [t.template_id for t in item.templates]
                            for item in resolutions}

        facts = self._target_facts(run_id)
        port = select_probe_port(facts, override=config.port)
        endpoint = (build_probe_endpoint(run_id=run_id, facts=facts, port=port)
                    if facts is not None and port is not None else None)
        if endpoint is None:
            signals = {cve_id: DynamicSignal.NOT_RUN for cve_id in cve_ids}
            return self._publish(run_id, config, base_dir, timestamp, candidates,
                                 top_context, top30_ref, top30_before_sha,
                                 manifest=manifest, manifest_sha=manifest_sha,
                                 endpoint=None, resolutions=resolutions,
                                 outcomes={}, evidence_refs={},
                                 refs_by_cve={}, templates_by_cve=templates_by_cve,
                                 signals=signals,
                                 notices=[{"code": "DYNAMIC_PROBE_NO_ENDPOINT",
                                           "message": "no eligible run-bound endpoint; probing not run"}])

        manifest_entries = {t.template_id: t.expected_sha256 for t in manifest.templates}
        verified = load_verified_results(
            base_dir, run_id, manifest_entries=manifest_entries,
            manifest_sha256=manifest_sha,
            expected_container_id=endpoint.container_id,
            expected_scheme=endpoint.scheme, expected_port=endpoint.port)
        app_endpoints = build_application_endpoints(endpoint, config.app_paths)

        def _is_verified(cve_id: str, template_id: str,
                         app: HttpApplicationEndpoint) -> bool:
            return (cve_id, template_id, app.base_path) in verified

        pending: list[tuple[str, ApprovedTemplate, HttpApplicationEndpoint]] = []
        for item in resolutions:
            for template in item.templates:
                for app in app_endpoints:
                    if not _is_verified(item.cve_id, template.template_id, app):
                        pending.append((item.cve_id, template, app))
        next_attempt = 1
        for record in verified.values():
            try:
                next_attempt = max(next_attempt, int(record.get("attempt", 0)) + 1)
            except (TypeError, ValueError):
                continue

        outcomes: dict[str, dict[str, str]] = {cve: {} for cve in cve_ids}
        evidence_by_cve: dict[str, list[DynamicEvidence]] = {cve: [] for cve in cve_ids}
        evidence_refs: dict[str, list[dict[str, Any]]] = {cve: [] for cve in cve_ids}
        exec_refs_by_cve: dict[str, list[dict[str, Any]]] = {cve: [] for cve in cve_ids}
        for (cve_id, template_id, app_key), record in verified.items():
            binding = binding_key(template_id, record)
            outcomes[cve_id][binding] = MATCHED if int(
                record.get("match_count", 0)) > 0 else CLEAN
            raw = record.get("raw_artifact", {})
            if outcomes[cve_id][binding] == MATCHED:
                evidence_refs[cve_id].append({"path": raw.get("path"),
                                              "sha256": raw.get("sha256")})
            exec_refs_by_cve[cve_id].append(
                {"attempt": record.get("attempt"), "template_id": template_id,
                 "base_path": record.get("base_path", "/"),
                 "status": record.get("execution_status"), "reused": True})

        attempt = next_attempt
        executed_here = False
        provenance_inputs: dict[str, Any] = {}
        # One attempt number per shadow invocation: every binding executed
        # here shares it, keeping (run, attempt, cve, template, path) unique
        # while a retry advances to a fresh attempt namespace.
        for cve_id, template, app in pending:
            record = self._execute_pair(run_id, config, manifest, manifest_sha,
                                        endpoint, cve_id, template, attempt,
                                        base_dir, timestamp, app=app)
            executed_here = True
            binding = binding_key(template.template_id, record)
            if not provenance_inputs and record.get("nuclei") is not None:
                provenance_inputs = {
                    "nuclei": record["nuclei"],
                    "reachability_tool": record.get("reachability_tool"),
                }
            if record.get("outcome") == MATCHED:
                outcomes[cve_id][binding] = MATCHED
                for item in record.get("evidence", ()):
                    evidence_by_cve[cve_id].append(item)
                evidence_refs[cve_id].append(
                    {"path": record["raw_artifact"]["path"],
                     "sha256": record["raw_artifact"]["sha256"]})
            elif record.get("outcome") == CLEAN:
                outcomes[cve_id][binding] = CLEAN
            else:
                outcomes[cve_id][binding] = INCOMPLETE
            exec_refs_by_cve[cve_id].append(
                {"attempt": record.get("attempt"), "template_id": template.template_id,
                 "base_path": app.base_path, "base_path_source": app.base_path_source,
                 "status": record.get("status"), "reused": False,
                 "error_code": record.get("error_code")})

        signals = {item.cve_id: derive_dynamic_signal(
            enabled=True, resolved=True,
            applicable_templates=[binding_key(t.template_id, {"base_path": app.base_path})
                                  for t in item.templates for app in app_endpoints],
            outcomes=outcomes.get(item.cve_id, {})) for item in resolutions}
        return self._publish(run_id, config, base_dir, timestamp, candidates,
                             top_context, top30_ref, top30_before_sha,
                             manifest=manifest, manifest_sha=manifest_sha,
                             endpoint=endpoint, resolutions=resolutions,
                             outcomes=outcomes, evidence_refs=evidence_refs,
                             refs_by_cve=exec_refs_by_cve,
                             templates_by_cve=templates_by_cve,
                             app_endpoints=app_endpoints,
                             signals=signals, notices=[],
                             provenance_inputs=provenance_inputs,
                             resolved_attempt=(next_attempt if executed_here else None))

    # -- pieces ------------------------------------------------------------
    def _load_manifest(self, config: DynamicShadowConfig
                       ) -> tuple[ApprovedTemplateManifest | None, str | None, str | None]:
        if config.manifest_path is None or config.template_root is None:
            return None, None, "dynamic probing requested but template manifest is not configured"
        try:
            manifest = load_approved_template_manifest(config.manifest_path,
                                                       config.template_root)
            return manifest, sha256_file(config.manifest_path), None
        except (TemplatePolicyError, OSError) as exc:
            code = exc.code if isinstance(exc, TemplatePolicyError) else "DYNAMIC_MANIFEST_UNREADABLE"
            return None, None, f"{code}: approved template manifest unavailable: {exc}"

    def _target_facts(self, run_id: str) -> Mapping[str, Any] | None:
        state = self.store.load(run_id)
        if state.target is None or not isinstance(state.target.facts, Mapping):
            return None
        return state.target.facts

    def _execute_pair(self, run_id: str, config: DynamicShadowConfig,
                      manifest: ApprovedTemplateManifest, manifest_sha: str,
                      endpoint: DynamicEndpoint, cve_id: str,
                      approved: ApprovedTemplate, attempt: int,
                      base_dir: Path, timestamp: str,
                      app: HttpApplicationEndpoint | None = None) -> dict[str, Any]:
        """One template x one application-scope execution. Never raises."""
        requested = app.base_path if app is not None else "/"
        requested_source = (app.base_path_source if app is not None
                            else DEFAULT_ROOT_SOURCE)
        try:
            runtime_preflight_template(config.template_root, approved)
        except TemplatePolicyError as exc:
            return {"attempt": attempt, "outcome": INCOMPLETE, "status": "PREFLIGHT_REJECTED",
                    "error_code": exc.code, "error_detail": str(exc),
                    "base_path": requested}
        box = self._sandbox(SandboxConfig(
            run_id=run_id, attempt=attempt,
            victim_container_name=endpoint.container_name,
            expected_container_id=endpoint.container_id,
            port=endpoint.port, scheme=endpoint.scheme,
            runner_image=config.runner_image or "kalama/nuclei-probe:pinned",
            template_root_host_path=str(config.template_root)))
        try:
            sandbox_endpoint = box.setup()
            box.start_runner()
            # Re-bind the requested application scope to the sandbox
            # endpoint: the sandbox network/IP is the effective target,
            # and it differs from the pre-sandbox endpoint by design.
            app = HttpApplicationEndpoint(sandbox_endpoint, requested,
                                          requested_source)
            exec_backend = self._exec_backend(box.runner_name)
            identity = probe_nuclei_identity(exec_backend, config.nuclei_binary)
            reachability = self._reachability(box.runner_name)
            nuclei_config = NucleiRunnerConfig(
                binary_path=config.nuclei_binary, template_root=config.template_root)
            result = execute_single_template(
                nuclei_config, endpoint=sandbox_endpoint, approved=approved,
                candidate_cve=cve_id, run_id=run_id, attempt=attempt,
                backend=exec_backend, reachability=reachability,
                template_container_root=config.container_template_root,
                app_endpoint=app)
        except (SandboxError, TemplatePolicyError) as exc:
            box.cleanup()
            code = exc.code if isinstance(exc, (SandboxError, TemplatePolicyError)) else "DYNAMIC_PROBE_FAILED"
            return {"attempt": attempt, "outcome": INCOMPLETE, "status": "SANDBOX_FAILED",
                    "error_code": code, "error_detail": str(exc),
                    "base_path": requested}
        except Exception as exc:
            box.cleanup()
            return {"attempt": attempt, "outcome": INCOMPLETE, "status": "EXECUTION_FAILED",
                    "error_code": NUCLEI_EXECUTION_FAILED, "error_detail": f"{type(exc).__name__}: {exc}",
                    "base_path": requested}
        try:
            raw_ref = self._persist_raw(base_dir, run_id, attempt, cve_id,
                                        approved.template_id, result.raw_stdout,
                                        base_path=app.base_path)
            reach_tool = getattr(reachability, "detected_tool", None)
            nuclei_info = {"binary": config.nuclei_binary,
                           "version": identity.get("version"),
                           "sha256": identity.get("sha256"),
                           "runner_image": config.runner_image}
            result_ref = self._persist_result(
                base_dir, run_id, attempt, cve_id, approved, result, manifest,
                manifest_sha, identity, sandbox_endpoint,
                reach_tool, raw_ref,
                config.nuclei_binary, config.runner_image,
                base_path=app.base_path)
        except DynamicShadowError as exc:
            box.cleanup()
            return {"attempt": attempt, "outcome": INCOMPLETE, "status": "ARTIFACT_FAILED",
                    "error_code": exc.code, "error_detail": str(exc),
                    "base_path": app.base_path}
        try:
            box.verify_after()
        except SandboxError as exc:
            box.cleanup()
            return {"attempt": attempt, "outcome": INCOMPLETE, "status": "IDENTITY_DRIFT",
                    "error_code": exc.code, "error_detail": str(exc),
                    "base_path": app.base_path,
                    "raw_artifact": raw_ref, "result": result}
        box.cleanup()
        outcome = classify_execution(result)
        record: dict[str, Any] = {
            "attempt": attempt, "outcome": outcome,
            "status": result.execution_status.value,
            "error_code": result.error_code, "error_detail": result.error_detail,
            "base_path": app.base_path, "base_path_source": app.base_path_source,
            "application_endpoint_key": app.application_endpoint_key,
            "effective_target_url": app.effective_target_url,
            "raw_artifact": raw_ref, "result": result,
            "nuclei": nuclei_info, "reachability_tool": reach_tool,
        }
        if outcome == MATCHED:
            record["evidence"] = normalize_evidence(
                result, run_id=run_id, phase=config.phase, attempt=str(attempt),
                container_id=sandbox_endpoint.container_id,
                raw_artifact_path=raw_ref["path"],
                raw_artifact_sha256=raw_ref["sha256"],
                execution_manifest_path=result_ref["path"])
        return record

    def _persist_raw(self, base_dir: Path, run_id: str, attempt: int,
                     cve_id: str, template_id: str, payload: bytes,
                     base_path: str = "/") -> dict[str, str]:
        paths = _artifact_paths(base_dir, run_id, attempt, cve_id, template_id,
                                base_path=base_path)
        atomic_write_bytes(paths["raw"], payload)
        return {"path": str(paths["raw"]), "sha256": sha256_bytes(payload)}

    def _persist_result(self, base_dir: Path, run_id: str, attempt: int,
                        cve_id: str, approved: ApprovedTemplate,
                        result: ProbeExecutionResult,
                        manifest: ApprovedTemplateManifest, manifest_sha: str,
                        identity: Mapping[str, Any], endpoint: DynamicEndpoint,
                        reachability_tool: str | None,
                        raw_ref: Mapping[str, str],
                        nuclei_binary: str, runner_image: str | None,
                        base_path: str = "/") -> dict[str, str]:
        try:
            tree_sha: str | None = template_tree_sha256(manifest.template_root)
        except OSError:
            tree_sha = None
        paths = _artifact_paths(base_dir, run_id, attempt, cve_id, approved.template_id,
                                base_path=base_path)
        document = execution_result_manifest(result, provenance={
            "phase": DYNAMIC_PHASE,
            "nuclei": {"binary": nuclei_binary,
                       "version": identity.get("version"),
                       "sha256": identity.get("sha256"),
                       "runner_image": runner_image},
            "template_manifest": {"path": str(manifest.manifest_path),
                                  "sha256": manifest_sha,
                                  "revision": manifest.template_revision,
                                  "tree_sha256": tree_sha},
            "reachability_tool": reachability_tool,
            "raw_artifact": dict(raw_ref),
        })
        payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        atomic_write_bytes(paths["result"], payload)
        return {"path": str(paths["result"]), "sha256": sha256_bytes(payload)}

    def _persist_resolved(self, base_dir: Path, run_id: str, attempt: int,
                           manifest: ApprovedTemplateManifest, manifest_sha: str,
                           resolutions: Sequence[Any],
                           app_endpoints: Sequence[HttpApplicationEndpoint] = ()
                           ) -> dict[str, str]:
        path = resolved_manifest_path(base_dir, run_id, attempt)
        document = resolved_template_manifest(
            run_id=run_id, attempt=attempt, phase=DYNAMIC_PHASE, manifest=manifest,
            manifest_sha256=manifest_sha, resolutions=resolutions,
            app_endpoints=app_endpoints)
        payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        atomic_write_bytes(path, payload)
        return {"path": str(path), "sha256": sha256_bytes(payload)}

    def _publish(self, run_id: str, config: DynamicShadowConfig, base_dir: Path,
                 timestamp: str, candidates: Sequence[Mapping[str, Any]],
                 top_context: Mapping[str, Any], top30_ref: Any,
                 top30_before_sha: str | None, *, manifest: Any,
                 manifest_sha: str | None, endpoint: Any, resolutions: Sequence[Any],
                 outcomes: Mapping[str, Mapping[str, str]],
                 evidence_refs: Mapping[str, list[dict[str, Any]]],
                  refs_by_cve: Mapping[str, list[dict[str, Any]]],
                  templates_by_cve: Mapping[str, list[str]],
                  signals: Mapping[str, DynamicSignal],
                  notices: Sequence[Mapping[str, str]],
                  provenance_inputs: Mapping[str, Any] | None = None,
                  resolved_attempt: int | None = None,
                  app_endpoints: Sequence[HttpApplicationEndpoint] = ()) -> RunState:
        # Reuse check: no new executions and a referenced summary already
        # exists -> keep state untouched (idempotent resume).
        state = self.store.load(run_id)
        existing_ref = state.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        attempt_no = resolved_attempt
        if attempt_no is None:
            prior = sorted(base_dir.glob(f"dynamic_shadow_{run_id}_attempt_*.json"))
            if existing_ref is not None and prior:
                latest = prior[-1]
                if str(existing_ref.path) == str(latest):
                    return state
            attempt_no = self._next_summary_attempt(base_dir, run_id)
        summary_inputs: dict[str, Any] = {
            "top30": {"path": top30_ref.path, "sha256": top30_ref.sha256},
            "endpoint": dict(endpoint.to_dict()) if endpoint is not None else None,
            "candidate_universe": "top_n",
        }
        for key in ("nuclei", "reachability_tool"):
            if provenance_inputs and provenance_inputs.get(key) is not None:
                summary_inputs[key] = provenance_inputs[key]
        if manifest is not None:
            summary_inputs["template_manifest"] = {
                "path": str(manifest.manifest_path), "sha256": manifest_sha,
                "revision": manifest.template_revision}
        if app_endpoints:
            summary_inputs["application_endpoints"] = [
                {"base_path": app.base_path, "base_path_source": app.base_path_source,
                 "application_endpoint_key": app.application_endpoint_key}
                for app in app_endpoints]
        bindings_by_cve: dict[str, list[dict[str, str]]] = {}
        for item in resolutions:
            entries = []
            for template in getattr(item, "templates", ()):
                for app in app_endpoints:
                    entries.append({"template_id": template.template_id,
                                    "base_path": app.base_path,
                                    "base_path_source": app.base_path_source})
            bindings_by_cve[item.cve_id] = entries
        summary = build_shadow_summary(
            run_id=run_id, phase=config.phase, attempt=attempt_no, created_at=timestamp,
            candidates=candidates, top_context=top_context,
            top30_sha256=top30_before_sha or top30_ref.sha256,
            inputs=summary_inputs, signals=signals,
            evidence_refs=evidence_refs,
            execution_refs=refs_by_cve, template_lists=templates_by_cve,
            binding_lists=bindings_by_cve,
            notices=notices)
        summary_path = shadow_summary_path(base_dir, run_id, attempt_no)
        atomic_write_bytes(
            summary_path,
            (json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())
        summary_sha = sha256_file(summary_path)
        if manifest is not None and resolved_attempt is not None:
            self._persist_resolved(base_dir, run_id, resolved_attempt,
                                   manifest, manifest_sha or "", resolutions,
                                   app_endpoints)
        # Priority-v1 self-check: Top30 bytes must be untouched.
        current_top30 = sha256_file(Path(top30_ref.path)) if Path(top30_ref.path).is_file() else None
        if current_top30 != top30_ref.sha256:
            raise DynamicShadowError("DYNAMIC_TOP30_MODIFIED",
                                     "refusing to publish shadow state: Top30 artifact changed")
        counts: dict[str, int] = {}
        for signal in signals.values():
            counts[signal.value] = counts.get(signal.value, 0) + 1
        reference = ArtifactReference(
            ArtifactKind.DYNAMIC_SHADOW_BEFORE, str(summary_path.resolve()), summary_sha,
            DYNAMIC_SHADOW_SCHEMA, timestamp, PipelineStage.STEP_3_PRIORITIZATION,
            (("attempt", attempt_no), ("phase", config.phase),
             ("signals", ",".join(f"{key}={counts[key]}" for key in sorted(counts))),
             ("top_n", top_context.get("top_n_returned"))))
        state = self.store.load(run_id)
        state = state.with_artifact(reference, timestamp)
        all_notices = list(notices)
        inconclusive = [cve for cve, signal in signals.items()
                        if signal == DynamicSignal.INCONCLUSIVE]
        if inconclusive and not config.required and not any(
                str(item.get("code", "")).startswith("DYNAMIC_PROBE_") for item in all_notices):
            all_notices.append({
                "code": "DYNAMIC_PROBE_INCONCLUSIVE",
                "message": f"dynamic probing inconclusive for {len(inconclusive)} candidate(s)"})
        for notice in all_notices:
            state = replace(state, warnings=state.warnings + (
                RunNotice(notice.get("code", "DYNAMIC_PROBE_NOTICE"),
                          notice.get("message", ""), timestamp),))
        state = replace(state, updated_at=timestamp)
        state = self._save(state)
        if config.required and inconclusive:
            return self._fail_required(
                run_id, IntegrationFailureCode.DYNAMIC_PROBE_FAILED.value,
                f"required dynamic probing inconclusive for {len(inconclusive)} candidate(s)",
                details={"candidates": ",".join(sorted(inconclusive))})
        return self.store.load(run_id)

    def _next_summary_attempt(self, base_dir: Path, run_id: str) -> int:
        attempt = 1
        for path in base_dir.glob(f"dynamic_shadow_{run_id}_attempt_*.json"):
            try:
                attempt = max(attempt, int(path.stem.rsplit("_attempt_", 1)[1]) + 1)
            except (ValueError, IndexError):
                continue
        for path in base_dir.glob(f"dynamic_nuclei_result_{run_id}_attempt_*.json"):
            try:
                attempt = max(attempt, int(path.stem.split("_attempt_")[1].split("_")[0]) + 1)
            except (ValueError, IndexError):
                continue
        return attempt
