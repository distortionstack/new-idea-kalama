"""Immutable before-exploit planning and evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class CheckVerdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    APPEARS = "APPEARS"
    DETECTED = "DETECTED"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"
    NOT_RUN = "NOT_RUN"


class OperationState(str, Enum):
    NOT_RUN = "NOT_RUN"
    EXECUTED = "EXECUTED"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    TIMEOUT = "TIMEOUT"
    BACKEND_ERROR = "BACKEND_ERROR"


class SessionCollectionStatus(str, Enum):
    COLLECTED = "COLLECTED"
    UNKNOWN = "UNKNOWN"


class OracleVerdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"


class EvidenceCompleteness(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"
    NONE = "NONE"


@dataclass(frozen=True)
class EnvironmentValidation:
    valid: bool
    code: str | None = None
    message: str | None = None
    observed: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "code": self.code, "message": self.message,
                "observed": dict(self.observed)}


@dataclass(frozen=True)
class ExecutionPlan:
    cve_id: str
    rank: int
    module: str
    target_index: int | None
    target_name: str | None
    module_options: tuple[tuple[str, Any], ...]
    payload: str | None
    payload_options: tuple[tuple[str, Any], ...]
    run_check: bool
    run_exploit: bool
    session_confirmation_expected: bool
    precondition_commands: tuple[str, ...]
    precondition_target: str | None
    precondition_required: bool
    pre_attack_command: str | None
    pre_attack_target: str | None


@dataclass(frozen=True)
class CommandEvidence:
    state: OperationState
    started_at: str | None = None
    ended_at: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    submitted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state.value, "started_at": self.started_at,
                "ended_at": self.ended_at, "exit_code": self.exit_code,
                "stdout": self.stdout, "stderr": self.stderr, "submitted": self.submitted}


@dataclass(frozen=True)
class CheckEvidence:
    verdict: CheckVerdict
    operation: CommandEvidence

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "operation": self.operation.to_dict()}


@dataclass(frozen=True)
class SessionEvidence:
    status: SessionCollectionStatus
    baseline_ids: tuple[str, ...] = ()
    post_ids: tuple[str, ...] = ()
    new_ids: tuple[str, ...] = ()
    attribution: str = "UNKNOWN"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "baseline_session_ids": list(self.baseline_ids),
                "post_session_ids": list(self.post_ids), "new_session_ids": list(self.new_ids),
                "attribution": self.attribution, "error": self.error}


@dataclass(frozen=True)
class MetricEligibility:
    eligible: bool
    conditions: tuple[tuple[str, bool], ...]
    exclusion_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"eligible": self.eligible, "conditions": dict(self.conditions),
                "exclusion_reason": self.exclusion_reason}


@dataclass(frozen=True)
class OracleResult:
    verdict: OracleVerdict
    evidence_basis: str
    completeness: EvidenceCompleteness
    evidence_conflict: bool
    metric_eligibility: MetricEligibility

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "evidence_basis": self.evidence_basis,
                "completeness": self.completeness.value,
                "evidence_conflict": self.evidence_conflict,
                "metric_eligibility": self.metric_eligibility.to_dict()}
