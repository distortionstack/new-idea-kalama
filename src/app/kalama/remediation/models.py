"""Immutable remediation-planning contracts; no mutation behavior lives here."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class FixType(str, Enum):
    A = "A"
    B = "B"
    C = "C"


class PatchStrategy(str, Enum):
    COPACETIC = "COPACETIC"
    PACKAGE_MANAGER = "PACKAGE_MANAGER"
    ARTIFACT_REPLACEMENT = "ARTIFACT_REPLACEMENT"
    MUTATION = "MUTATION"
    REBUILD = "REBUILD"
    PREBUILT_IMAGE_REPLACEMENT = "PREBUILT_IMAGE_REPLACEMENT"
    DOCKER_COMMIT = "DOCKER_COMMIT"
    HUMAN_COMMAND = "HUMAN_COMMAND"


class PlanningStatus(str, Enum):
    READY_FOR_PATCH_EXECUTION = "READY_FOR_PATCH_EXECUTION"
    WAITING_FOR_USER_INPUT = "WAITING_FOR_USER_INPUT"
    NOT_REMEDIATION_TARGET = "NOT_REMEDIATION_TARGET"
    PATCH_UNSUPPORTED = "PATCH_UNSUPPORTED"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"


class PlanningReason(str, Enum):
    FIX_TYPE_UNRESOLVED = "FIX_TYPE_UNRESOLVED"
    PACKAGE_MAPPING_UNRESOLVED = "PACKAGE_MAPPING_UNRESOLVED"
    TARGET_VERSION_UNRESOLVED = "TARGET_VERSION_UNRESOLVED"
    BRANCH_SEMANTICS_UNRESOLVED = "BRANCH_SEMANTICS_UNRESOLVED"
    ARTIFACT_SOURCE_UNRESOLVED = "ARTIFACT_SOURCE_UNRESOLVED"
    PATCH_STRATEGY_UNRESOLVED = "PATCH_STRATEGY_UNRESOLVED"
    BUILD_PLAN_REQUIRES_HUMAN_INPUT = "BUILD_PLAN_REQUIRES_HUMAN_INPUT"
    MAJOR_VERSION_CONFIRMATION_REQUIRED = "MAJOR_VERSION_CONFIRMATION_REQUIRED"
    EOL_DATA_LIMITATION = "EOL_DATA_LIMITATION"
    PATCH_ACTION_CONFLICT = "PATCH_ACTION_CONFLICT"


@dataclass(frozen=True)
class RemediationCandidate:
    target_version: str | None = None
    fix_type: FixType | None = None
    strategy: PatchStrategy | None = None
    source_type: str | None = None
    source_authority: str | None = None
    source_identifier: str | None = None
    source_url: str | None = None
    checksum: str | None = None
    retrieved_at: str | None = None
    trusted: bool = False
    same_branch: bool | None = None
    fallback_used: bool = False
    fallback_reason: str | None = None
    artifact_name: str | None = None
    replacement_target: str | None = None
    build_system: str | None = None
    eol: bool = False
    classification: str | None = None
    classification_status: str | None = None
    version_status: str | None = None
    candidate_status: str | None = None
    execution_readiness: str | None = None
    availability: str | None = None
    discovery_issue: str | None = None
    evidence: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        values = {key: (value.value if isinstance(value, Enum) else value)
                  for key, value in self.__dict__.items()}
        values["evidence"] = [dict(x) for x in self.evidence]
        return values


@dataclass(frozen=True)
class PatchAction:
    action_id: str
    target_cves: tuple[str, ...]
    incidental_cves: tuple[str, ...]
    package_key: str
    package_name: str | None
    ecosystem: str | None
    occurrences: tuple[Mapping[str, Any], ...]
    before_versions: tuple[str, ...]
    scanner_fixed_versions: tuple[str, ...]
    fix_type: FixType | None
    strategy: PatchStrategy | None
    candidate: RemediationCandidate | None
    status: PlanningStatus
    input_reasons: tuple[PlanningReason, ...]
    execution: Mapping[str, Any] = None
    human_confirmed_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return ({"action_id": self.action_id, "target_cves": list(self.target_cves),
                "incidental_cves": list(self.incidental_cves), "package_key": self.package_key,
                "package_name": self.package_name, "ecosystem": self.ecosystem,
                "occurrences": [dict(x) for x in self.occurrences],
                "before_versions": list(self.before_versions),
                "scanner_fixed_versions": list(self.scanner_fixed_versions),
                "fix_type": self.fix_type.value if self.fix_type else None,
                "strategy": self.strategy.value if self.strategy else None,
                "candidate": self.candidate.to_dict() if self.candidate else None,
                "status": self.status.value,
                "input_reasons": [x.value for x in self.input_reasons]}
                | {"execution": dict(self.execution or {}),
                   "human_confirmed_fields": list(self.human_confirmed_fields)})


@dataclass(frozen=True)
class PatchPlan:
    run_id: str
    actions: tuple[PatchAction, ...]
    readiness: PlanningStatus

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "readiness": self.readiness.value,
                "actions": [x.to_dict() for x in self.actions]}
