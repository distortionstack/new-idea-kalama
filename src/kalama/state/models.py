"""Canonical immutable run-state contracts for Kalama orchestration."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping


RUN_STATE_SCHEMA = "kalama.run-state/v1"


class RunStatus(str, Enum):
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    WAITING_FOR_USER_INPUT = "WAITING_FOR_USER_INPUT"
    RETRY_REQUIRED = "RETRY_REQUIRED"
    COMPLETED = "COMPLETED"
    FAILED_FATAL = "FAILED_FATAL"
    ABORTED = "ABORTED"


class PipelineStage(str, Enum):
    STEP_2_TARGET_SCAN = "STEP_2_TARGET_SCAN"
    STEP_3_PRIORITIZATION = "STEP_3_PRIORITIZATION"
    STEP_4_RESOLVER = "STEP_4_RESOLVER"
    STEP_4_BEFORE_EXPLOIT = "STEP_4_BEFORE_EXPLOIT"
    STEP_5_PATCH = "STEP_5_PATCH"
    STEP_5_PATCH_PLAN = "STEP_5_PATCH_PLAN"
    STEP_5_PATCH_EXECUTION = "STEP_5_PATCH_EXECUTION"
    STEP_6_AFTER_SCAN = "STEP_6_AFTER_SCAN"
    STEP_7_REEXPLOIT = "STEP_7_REEXPLOIT"
    STEP_8_EVALUATION = "STEP_8_EVALUATION"


class StageStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    WAITING = "WAITING"
    RETRY_REQUIRED = "RETRY_REQUIRED"
    SKIPPED = "SKIPPED"


class ArtifactKind(str, Enum):
    TRIVY_BEFORE = "TRIVY_BEFORE"
    TOP30_BEFORE = "TOP30_BEFORE"
    RESOLVER = "RESOLVER"
    RESOLVER_BEFORE = "RESOLVER_BEFORE"
    LLM_GUIDANCE = "LLM_GUIDANCE"
    ATTACK_FORM = "ATTACK_FORM"
    ATTACK_FORM_SUBMISSION = "ATTACK_FORM_SUBMISSION"
    EXPLOIT_CONFIG_BEFORE = "EXPLOIT_CONFIG_BEFORE"
    ATTACK_BEFORE = "ATTACK_BEFORE"
    REMEDIATION_DISCOVERY = "REMEDIATION_DISCOVERY"
    PATCH_PLAN = "PATCH_PLAN"
    PATCH_FORM = "PATCH_FORM"
    PATCH_FORM_SUBMISSION = "PATCH_FORM_SUBMISSION"
    PATCH_RESULT = "PATCH_RESULT"
    PATCH = "PATCH"
    TRIVY_AFTER = "TRIVY_AFTER"
    REMEDIATION_SCAN_RESULT = "REMEDIATION_SCAN_RESULT"
    EXPLOIT_CONFIG_AFTER = "EXPLOIT_CONFIG_AFTER"
    ATTACK_AFTER = "ATTACK_AFTER"
    REMEDIATION_RESULT = "REMEDIATION_RESULT"
    EVALUATION_DATASET = "EVALUATION_DATASET"
    EVALUATION_METRICS = "EVALUATION_METRICS"
    RUN_SUMMARY = "RUN_SUMMARY"


class IntegrationFailureCode(str, Enum):
    ACTIVE_RUN_CONFLICT = "ACTIVE_RUN_CONFLICT"
    RUN_ID_COLLISION = "RUN_ID_COLLISION"
    STATE_LOAD_ERROR = "STATE_LOAD_ERROR"
    STATE_WRITE_ERROR = "STATE_WRITE_ERROR"
    ARTIFACT_INTEGRITY_ERROR = "ARTIFACT_INTEGRITY_ERROR"
    STEP_RESULT_INVALID = "STEP_RESULT_INVALID"
    STEP_2_FAILED = "STEP_2_FAILED"
    STEP_3_FAILED = "STEP_3_FAILED"
    NEXT_STAGE_NOT_INTEGRATED = "NEXT_STAGE_NOT_INTEGRATED"
    NO_RANKABLE_CVES = "NO_RANKABLE_CVES"
    TOP30_INTEGRITY_ERROR = "TOP30_INTEGRITY_ERROR"
    RESOLVER_BACKEND_ERROR = "RESOLVER_BACKEND_ERROR"
    RESOLVER_ARTIFACT_WRITE_FAILED = "RESOLVER_ARTIFACT_WRITE_FAILED"
    ATTACK_FORM_WRITE_FAILED = "ATTACK_FORM_WRITE_FAILED"
    NO_EXECUTABLE_MSF_CANDIDATE = "NO_EXECUTABLE_MSF_CANDIDATE"
    ATTACK_FORM_REQUIRED = "ATTACK_FORM_REQUIRED"
    BEFORE_EXPLOIT_NOT_INTEGRATED = "BEFORE_EXPLOIT_NOT_INTEGRATED"
    ATTACK_FORM_INVALID_YAML = "ATTACK_FORM_INVALID_YAML"
    ATTACK_FORM_SCHEMA_MISMATCH = "ATTACK_FORM_SCHEMA_MISMATCH"
    ATTACK_FORM_RUN_MISMATCH = "ATTACK_FORM_RUN_MISMATCH"
    ATTACK_FORM_PHASE_MISMATCH = "ATTACK_FORM_PHASE_MISMATCH"
    ATTACK_FORM_STALE = "ATTACK_FORM_STALE"
    ATTACK_FORM_UNKNOWN_CVE = "ATTACK_FORM_UNKNOWN_CVE"
    ATTACK_FORM_CVE_NOT_EDITABLE = "ATTACK_FORM_CVE_NOT_EDITABLE"
    ATTACK_FORM_UNKNOWN_FIELD = "ATTACK_FORM_UNKNOWN_FIELD"
    ATTACK_FORM_INVALID_MODULE = "ATTACK_FORM_INVALID_MODULE"
    ATTACK_FORM_INVALID_TARGET = "ATTACK_FORM_INVALID_TARGET"
    ATTACK_FORM_INVALID_OPTION = "ATTACK_FORM_INVALID_OPTION"
    ATTACK_FORM_INVALID_PAYLOAD = "ATTACK_FORM_INVALID_PAYLOAD"
    CONFIG_BASE_INTEGRITY_ERROR = "CONFIG_BASE_INTEGRITY_ERROR"
    CONFIG_APPLICATION_ERROR = "CONFIG_APPLICATION_ERROR"
    CONFIG_ARTIFACT_WRITE_FAILED = "CONFIG_ARTIFACT_WRITE_FAILED"
    SUBMISSION_SNAPSHOT_WRITE_FAILED = "SUBMISSION_SNAPSHOT_WRITE_FAILED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    CONFIG_ARTIFACT_INTEGRITY_ERROR = "CONFIG_ARTIFACT_INTEGRITY_ERROR"
    TARGET_BINDING_MISMATCH = "TARGET_BINDING_MISMATCH"
    ENVIRONMENT_BINDING_STALE = "ENVIRONMENT_BINDING_STALE"
    MSF_BACKEND_UNAVAILABLE = "MSF_BACKEND_UNAVAILABLE"
    ATTACK_ARTIFACT_WRITE_FAILED = "ATTACK_ARTIFACT_WRITE_FAILED"
    PATCH_NOT_INTEGRATED = "PATCH_NOT_INTEGRATED"
    PATCH_INPUT_INTEGRITY_ERROR = "PATCH_INPUT_INTEGRITY_ERROR"
    PATCH_PLAN_WRITE_FAILED = "PATCH_PLAN_WRITE_FAILED"
    PATCH_FORM_WRITE_FAILED = "PATCH_FORM_WRITE_FAILED"
    PATCH_EXECUTION_NOT_INTEGRATED = "PATCH_EXECUTION_NOT_INTEGRATED"
    NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS = "NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS"
    PATCH_PLAN_INTEGRITY_ERROR = "PATCH_PLAN_INTEGRITY_ERROR"
    PATCH_PLAN_NOT_READY = "PATCH_PLAN_NOT_READY"
    PATCH_ACTION_FAILED = "PATCH_ACTION_FAILED"
    PATCH_RESULT_WRITE_FAILED = "PATCH_RESULT_WRITE_FAILED"
    AFTER_SCAN_NOT_INTEGRATED = "AFTER_SCAN_NOT_INTEGRATED"
    PATCH_RESULT_INTEGRITY_ERROR = "PATCH_RESULT_INTEGRITY_ERROR"
    PATCHED_IMAGE_IDENTITY_MISMATCH = "PATCHED_IMAGE_IDENTITY_MISMATCH"
    AFTER_TARGET_IMAGE_MISMATCH = "AFTER_TARGET_IMAGE_MISMATCH"
    NO_AFTER_TARGET = "NO_AFTER_TARGET"
    TRIVY_AFTER_FAILED = "TRIVY_AFTER_FAILED"
    REMEDIATION_SCAN_RESULT_WRITE_FAILED = "REMEDIATION_SCAN_RESULT_WRITE_FAILED"
    REEXPLOIT_NOT_INTEGRATED = "REEXPLOIT_NOT_INTEGRATED"
    REEXPLOIT_INPUT_INTEGRITY_ERROR = "REEXPLOIT_INPUT_INTEGRITY_ERROR"
    INVARIANT_CONFIG_CHANGED = "INVARIANT_CONFIG_CHANGED"
    EXPLOIT_CONFIG_AFTER_WRITE_FAILED = "EXPLOIT_CONFIG_AFTER_WRITE_FAILED"
    ATTACK_AFTER_WRITE_FAILED = "ATTACK_AFTER_WRITE_FAILED"
    REMEDIATION_RESULT_WRITE_FAILED = "REMEDIATION_RESULT_WRITE_FAILED"
    EVALUATION_NOT_INTEGRATED = "EVALUATION_NOT_INTEGRATED"
    EVALUATION_INPUT_INTEGRITY_ERROR = "EVALUATION_INPUT_INTEGRITY_ERROR"
    EVALUATION_EVIDENCE_INCONSISTENT = "EVALUATION_EVIDENCE_INCONSISTENT"
    EVALUATION_DATASET_WRITE_FAILED = "EVALUATION_DATASET_WRITE_FAILED"
    EVALUATION_METRICS_WRITE_FAILED = "EVALUATION_METRICS_WRITE_FAILED"
    RUN_SUMMARY_WRITE_FAILED = "RUN_SUMMARY_WRITE_FAILED"


@dataclass(frozen=True)
class CVEStateSummary:
    cve_id: str
    rank: int
    resolver_status: str
    patch_action_status: str | None = None
    after_scan_status: str | None = None
    after_exploit_disposition: str | None = None
    remediation_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"rank": self.rank, "resolver_status": self.resolver_status,
                "patch_action_status": self.patch_action_status,
                "after_scan_status": self.after_scan_status,
                "after_exploit_disposition": self.after_exploit_disposition,
                "remediation_status": self.remediation_status}


@dataclass(frozen=True)
class StageState:
    stage: PipelineStage
    status: StageStatus = StageStatus.NOT_STARTED
    started_at: str | None = None
    completed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "started_at": self.started_at,
                "completed_at": self.completed_at}


@dataclass(frozen=True)
class ArtifactReference:
    kind: ArtifactKind
    path: str
    sha256: str
    schema: str | int
    created_at: str | None
    producer_stage: PipelineStage
    summary: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "path": self.path, "sha256": self.sha256,
                "schema": self.schema, "created_at": self.created_at,
                "producer_stage": self.producer_stage.value,
                "summary": {key: value for key, value in self.summary}}


@dataclass(frozen=True)
class TargetState:
    image_identity: Mapping[str, Any]
    facts: Mapping[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {"image_identity": dict(self.image_identity),
                "facts": dict(self.facts) if self.facts is not None else None}


@dataclass(frozen=True)
class RunError:
    error_id: str
    stage: PipelineStage | None
    code: str
    message: str
    timestamp: str
    retryable: bool = False
    details: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"error_id": self.error_id,
                "stage": self.stage.value if self.stage else None,
                "code": self.code, "message": self.message,
                "timestamp": self.timestamp, "retryable": self.retryable,
                "details": {key: value for key, value in self.details}}


@dataclass(frozen=True)
class RunNotice:
    code: str
    message: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "timestamp": self.timestamp}


@dataclass(frozen=True)
class RunState:
    run_id: str
    created_at: str
    updated_at: str
    mode: str
    status: RunStatus
    current_stage: PipelineStage | None
    victim_image: str
    epss_data_date: str
    stages: tuple[StageState, ...]
    artifacts: tuple[ArtifactReference, ...] = ()
    artifact_history: tuple[ArtifactReference, ...] = ()
    target: TargetState | None = None
    after_target: TargetState | None = None
    patched_image: Mapping[str, Any] | None = None
    errors: tuple[RunError, ...] = ()
    warnings: tuple[RunNotice, ...] = ()
    cves: tuple[CVEStateSummary, ...] = ()
    waiting_reason: str | None = None
    schema: str = RUN_STATE_SCHEMA

    def stage(self, stage: PipelineStage) -> StageState:
        return next(item for item in self.stages if item.stage == stage)

    def artifact(self, kind: ArtifactKind) -> ArtifactReference | None:
        return next((item for item in self.artifacts if item.kind == kind), None)

    def with_stage(self, stage: PipelineStage, status: StageStatus, timestamp: str) -> "RunState":
        updated = []
        for item in self.stages:
            if item.stage != stage:
                updated.append(item)
                continue
            started = item.started_at or (timestamp if status == StageStatus.RUNNING else None)
            completed = timestamp if status in (StageStatus.SUCCEEDED, StageStatus.FAILED,
                                                   StageStatus.SKIPPED) else item.completed_at
            updated.append(replace(item, status=status, started_at=started, completed_at=completed))
        return replace(self, stages=tuple(updated), updated_at=timestamp)

    def with_artifact(self, reference: ArtifactReference, timestamp: str) -> "RunState":
        previous = self.artifact(reference.kind)
        history = self.artifact_history
        if previous is not None and previous.sha256 != reference.sha256:
            history = history + (previous,)
        items = [item for item in self.artifacts if item.kind != reference.kind] + [reference]
        items.sort(key=lambda item: item.kind.value)
        return replace(self, artifacts=tuple(items), artifact_history=history, updated_at=timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "run_id": self.run_id, "mode": self.mode,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "status": self.status.value,
            "current_stage": self.current_stage.value if self.current_stage else None,
            "request": {"victim_image": self.victim_image},
            "research_context": {"epss_data_date": self.epss_data_date},
            "target": self.target.to_dict() if self.target else None,
            "after_target": self.after_target.to_dict() if self.after_target else None,
            "patched_image": dict(self.patched_image) if self.patched_image else None,
            "artifacts": {item.kind.value: item.to_dict() for item in self.artifacts},
            "artifact_history": [item.to_dict() for item in self.artifact_history],
            "stages": {item.stage.value: item.to_dict() for item in self.stages},
            "errors": [item.to_dict() for item in self.errors],
            "warnings": [item.to_dict() for item in self.warnings],
            "cves": {item.cve_id: item.to_dict() for item in sorted(self.cves, key=lambda x: x.rank)},
            "waiting_reason": self.waiting_reason,
        }


def initial_stages() -> tuple[StageState, ...]:
    return tuple(StageState(stage) for stage in PipelineStage)
