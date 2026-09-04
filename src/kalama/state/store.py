"""Validated, deterministic, atomic persistence for canonical run state."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import string
import tempfile
from typing import Any, Callable, Mapping

from .models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, PipelineStage, RunError, RunNotice, RunState,
    RunStatus, StageState, StageStatus, TargetState, RUN_STATE_SCHEMA, initial_stages,
)


RUN_ID_RE = re.compile(r"^[A-Za-z0-9]{5}$")
STATE_NAME_RE = re.compile(r"^run_([A-Za-z0-9]{5})\.json$")


class StateStoreError(RuntimeError):
    def __init__(self, code: str, message: str, path: Path | None = None):
        super().__init__(message)
        self.code, self.path = code, path


def utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def default_run_id() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(5))


def serialize_run_state(state: RunState) -> bytes:
    return (json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _required_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _optional_timestamp(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be a UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    return value


def _required_timestamp(value: Any, name: str) -> str:
    parsed = _optional_timestamp(value, name)
    if parsed is None:
        raise ValueError(f"{name} is required")
    return parsed


def run_state_from_dict(data: Any, *, expected_run_id: str | None = None) -> RunState:
    root = _required_mapping(data, "state")
    if root.get("schema") != RUN_STATE_SCHEMA:
        raise ValueError(f"unsupported state schema: {root.get('schema')!r}")
    run_id = root.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid run_id")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError(f"state run_id {run_id!r} does not match filename {expected_run_id!r}")
    created_at = _required_timestamp(root.get("created_at"), "created_at")
    updated_at = _required_timestamp(root.get("updated_at"), "updated_at")
    request = _required_mapping(root.get("request"), "request")
    research = _required_mapping(root.get("research_context"), "research_context")
    if not isinstance(request.get("victim_image"), str) or not request["victim_image"]:
        raise ValueError("request.victim_image is required")
    epss_date = research.get("epss_data_date")
    if not isinstance(epss_date, str):
        raise ValueError("research_context.epss_data_date is required")
    try:
        datetime.strptime(epss_date, "%Y-%m-%d")
        status = RunStatus(root.get("status"))
        current = PipelineStage(root["current_stage"]) if root.get("current_stage") else None
    except (ValueError, KeyError) as exc:
        raise ValueError("invalid date, run status, or current stage") from exc

    raw_stages = _required_mapping(root.get("stages"), "stages")
    stages = []
    if set(raw_stages) != {item.value for item in PipelineStage}:
        raise ValueError("stages must contain every known pipeline stage exactly once")
    for stage in PipelineStage:
        value = _required_mapping(raw_stages[stage.value], f"stages.{stage.value}")
        stages.append(StageState(
            stage, StageStatus(value.get("status")),
            _optional_timestamp(value.get("started_at"), f"{stage.value}.started_at"),
            _optional_timestamp(value.get("completed_at"), f"{stage.value}.completed_at"),
        ))

    raw_artifacts = _required_mapping(root.get("artifacts"), "artifacts")
    artifacts = []
    for key in sorted(raw_artifacts):
        try:
            kind = ArtifactKind(key)
        except ValueError as exc:
            raise ValueError(f"unknown artifact kind {key!r}") from exc
        value = _required_mapping(raw_artifacts[key], f"artifacts.{key}")
        if (value.get("kind") != key or not isinstance(value.get("path"), str)
                or not value.get("path")):
            raise ValueError(f"invalid artifact reference {key}")
        artifact_schema = value.get("schema")
        if isinstance(artifact_schema, bool) or not isinstance(artifact_schema, (str, int)):
            raise ValueError(f"invalid schema for {key}")
        sha = value.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"invalid sha256 for {key}")
        summary = value.get("summary") or {}
        if not isinstance(summary, Mapping):
            raise ValueError(f"invalid summary for {key}")
        artifacts.append(ArtifactReference(
            kind, value["path"], sha, artifact_schema,
            _optional_timestamp(value.get("created_at"), f"{key}.created_at"),
            PipelineStage(value.get("producer_stage")), tuple(sorted(summary.items())),
        ))

    history = []
    raw_history = root.get("artifact_history", [])
    if not isinstance(raw_history, list):
        raise ValueError("artifact_history must be an array")
    for value in raw_history:
        item = _required_mapping(value, "artifact_history item")
        try:
            kind = ArtifactKind(item.get("kind"))
            sha = item.get("sha256")
            schema = item.get("schema")
            summary = item.get("summary") or {}
            if (not isinstance(item.get("path"), str) or not item["path"]
                    or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)
                    or isinstance(schema, bool) or not isinstance(schema, (str, int))
                    or not isinstance(summary, Mapping)):
                raise ValueError("invalid historical artifact")
            history.append(ArtifactReference(
                kind, item["path"], sha, schema,
                _optional_timestamp(item.get("created_at"), "artifact_history.created_at"),
                PipelineStage(item.get("producer_stage")), tuple(sorted(summary.items()))))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid artifact_history item") from exc

    raw_target = root.get("target")
    target = None
    if raw_target is not None:
        target_map = _required_mapping(raw_target, "target")
        image = _required_mapping(target_map.get("image_identity"), "target.image_identity")
        facts_raw = target_map.get("facts")
        if facts_raw is not None and not isinstance(facts_raw, Mapping):
            raise ValueError("target.facts must be an object or null")
        target = TargetState(dict(image), dict(facts_raw) if facts_raw is not None else None)
    raw_after = root.get("after_target")
    after_target = None
    if raw_after is not None:
        after_map = _required_mapping(raw_after, "after_target")
        after_image = _required_mapping(after_map.get("image_identity"), "after_target.image_identity")
        after_facts = after_map.get("facts")
        if after_facts is not None and not isinstance(after_facts, Mapping):
            raise ValueError("after_target.facts must be an object or null")
        after_target = TargetState(dict(after_image), dict(after_facts) if after_facts else None)
    patched_raw = root.get("patched_image")
    if patched_raw is not None and not isinstance(patched_raw, Mapping):
        raise ValueError("patched_image must be an object or null")

    errors = []
    raw_errors = root.get("errors")
    if not isinstance(raw_errors, list):
        raise ValueError("errors must be an array")
    for value in raw_errors:
        item = _required_mapping(value, "error")
        details = item.get("details") or {}
        if (not isinstance(item.get("error_id"), str) or not item["error_id"]
                or not isinstance(item.get("code"), str)
                or not isinstance(item.get("message"), str)
                or not isinstance(details, Mapping)):
            raise ValueError("invalid structured error")
        errors.append(RunError(item["error_id"],
                               PipelineStage(item["stage"]) if item.get("stage") else None,
                               item["code"], item["message"],
                               _required_timestamp(item.get("timestamp"), "error.timestamp"),
                               bool(item.get("retryable", False)), tuple(sorted(details.items()))))
    warnings = []
    raw_warnings = root.get("warnings")
    if not isinstance(raw_warnings, list):
        raise ValueError("warnings must be an array")
    for value in raw_warnings:
        item = _required_mapping(value, "warning")
        if not isinstance(item.get("code"), str) or not isinstance(item.get("message"), str):
            raise ValueError("invalid structured warning")
        warnings.append(RunNotice(item["code"], item["message"],
                                  _required_timestamp(item.get("timestamp"), "warning.timestamp")))
    mode = root.get("mode")
    if not isinstance(mode, str) or not mode:
        raise ValueError("mode is required")
    raw_cves = root.get("cves", {})
    if not isinstance(raw_cves, Mapping):
        raise ValueError("cves must be an object")
    cves = []
    seen_ranks = set()
    for cve_id, value in raw_cves.items():
        item = _required_mapping(value, f"cves.{cve_id}")
        rank = item.get("rank")
        resolver_status = item.get("resolver_status")
        patch_action_status = item.get("patch_action_status")
        after_scan_status = item.get("after_scan_status")
        after_exploit = item.get("after_exploit_disposition")
        remediation_status = item.get("remediation_status")
        if (not isinstance(cve_id, str) or not cve_id.startswith("CVE-")
                or isinstance(rank, bool) or not isinstance(rank, int) or rank < 1
                or rank in seen_ranks or not isinstance(resolver_status, str)
                or (patch_action_status is not None and not isinstance(patch_action_status, str))
                or (after_scan_status is not None and after_scan_status not in
                    {"FOUND", "NOT_FOUND", "UNKNOWN"})
                or (after_exploit is not None and not isinstance(after_exploit, str))
                or (remediation_status is not None and remediation_status not in
                    {"VERIFIED", "FAILED", "INCONCLUSIVE", "NOT_EVALUATED"})):
            raise ValueError(f"invalid CVE summary {cve_id!r}")
        seen_ranks.add(rank)
        cves.append(CVEStateSummary(cve_id, rank, resolver_status,
                                    patch_action_status, after_scan_status,
                                    after_exploit, remediation_status))
    waiting_reason = root.get("waiting_reason")
    if waiting_reason is not None and not isinstance(waiting_reason, str):
        raise ValueError("waiting_reason must be a string or null")
    return RunState(run_id, created_at, updated_at, mode, status, current,
                    request["victim_image"], epss_date, tuple(stages), tuple(artifacts), tuple(history),
                    target, after_target, dict(patched_raw) if patched_raw else None,
                    tuple(errors), tuple(warnings),
                    tuple(sorted(cves, key=lambda x: x.rank)), waiting_reason)


class StateStore:
    def __init__(self, output_root: Path):
        self.output_root = output_root.resolve()
        self.state_dir = self.output_root / "state"

    def path_for(self, run_id: str) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise StateStoreError("INVALID_RUN_ID", "run_id must be five alphanumeric characters")
        return self.state_dir / f"run_{run_id}.json"

    def load(self, path_or_run_id: Path | str) -> RunState:
        path = path_or_run_id if isinstance(path_or_run_id, Path) else self.path_for(path_or_run_id)
        match = STATE_NAME_RE.fullmatch(path.name)
        expected = match.group(1) if match else None
        try:
            data = json.loads(path.read_bytes())
            return run_state_from_dict(data, expected_run_id=expected)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise StateStoreError("STATE_LOAD_ERROR", f"cannot load canonical state {path}: {exc}", path) from exc

    def save(self, state: RunState) -> Path:
        path = self.path_for(state.run_id)
        temporary: str | None = None
        try:
            payload = serialize_run_state(state)
            # Round-trip validation prevents a malformed model from replacing canonical state.
            run_state_from_dict(json.loads(payload), expected_run_id=state.run_id)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("wb", dir=self.state_dir,
                                             prefix=f".{path.name}.", delete=False) as handle:
                temporary = handle.name
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            return path
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
            raise StateStoreError("STATE_WRITE_ERROR", f"cannot atomically save state: {exc}", path) from exc

    def discover(self) -> tuple[RunState, ...]:
        if not self.state_dir.exists():
            return ()
        return tuple(self.load(path) for path in sorted(self.state_dir.glob("run_*.json")))

    def assert_no_active_run(self) -> None:
        active = [state.run_id for state in self.discover() if state.status == RunStatus.RUNNING]
        if active:
            raise StateStoreError("ACTIVE_RUN_CONFLICT",
                                  f"another run is active: {', '.join(sorted(active))}")

    def create(self, victim_image: str, *, now: datetime,
               run_id_generator: Callable[[], str] = default_run_id,
               mode: str = "through-prioritization", max_attempts: int = 100) -> RunState:
        self.assert_no_active_run()
        selected = None
        for _ in range(max_attempts):
            candidate = run_id_generator()
            if not isinstance(candidate, str) or not RUN_ID_RE.fullmatch(candidate):
                raise StateStoreError("INVALID_RUN_ID", "run ID generator returned an invalid value")
            if not self.path_for(candidate).exists():
                selected = candidate
                break
        if selected is None:
            raise StateStoreError("RUN_ID_COLLISION", "could not generate an unused run ID")
        timestamp = utc_text(now)
        state = RunState(selected, timestamp, timestamp, mode, RunStatus.INITIALIZING,
                         None, victim_image, timestamp[:10], initial_stages())
        self.save(state)
        return state
