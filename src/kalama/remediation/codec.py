"""PatchPlan reconstruction and pure readiness validation."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from .models import (
    FixType, PatchAction, PatchPlan, PatchStrategy, PlanningReason, PlanningStatus,
    RemediationCandidate,
)


def candidate_from_dict(raw: Any) -> RemediationCandidate | None:
    if raw is None: return None
    if not isinstance(raw, Mapping): raise ValueError("candidate must be an object")
    values = dict(raw)
    values["fix_type"] = FixType(values["fix_type"]) if values.get("fix_type") else None
    values["strategy"] = PatchStrategy(values["strategy"]) if values.get("strategy") else None
    return RemediationCandidate(**values)


def action_from_dict(raw: Any) -> PatchAction:
    if not isinstance(raw, Mapping): raise ValueError("action must be an object")
    return PatchAction(
        raw["action_id"], tuple(raw.get("target_cves") or ()),
        tuple(raw.get("incidental_cves") or ()), raw["package_key"], raw.get("package_name"),
        raw.get("ecosystem"), tuple(dict(x) for x in raw.get("occurrences") or ()),
        tuple(raw.get("before_versions") or ()), tuple(raw.get("scanner_fixed_versions") or ()),
        FixType(raw["fix_type"]) if raw.get("fix_type") else None,
        PatchStrategy(raw["strategy"]) if raw.get("strategy") else None,
        candidate_from_dict(raw.get("candidate")), PlanningStatus(raw["status"]),
        tuple(PlanningReason(x) for x in raw.get("input_reasons") or ()),
        dict(raw.get("execution") or {}), tuple(raw.get("human_confirmed_fields") or ()))


def patch_plan_from_artifact(raw: Mapping[str, Any]) -> PatchPlan:
    return PatchPlan(raw["run_id"], tuple(action_from_dict(x) for x in raw.get("actions") or ()),
                     PlanningStatus(raw["readiness"]))


def validate_patch_action(action: PatchAction) -> tuple[PlanningReason, ...]:
    reasons = []
    candidate = action.candidate
    if action.fix_type is None: reasons.append(PlanningReason.FIX_TYPE_UNRESOLVED)
    if action.strategy is None: reasons.append(PlanningReason.PATCH_STRATEGY_UNRESOLVED)
    if candidate is None or not candidate.target_version:
        reasons.append(PlanningReason.TARGET_VERSION_UNRESOLVED)
    if candidate is None or not candidate.trusted or not candidate.source_authority:
        reasons.append(PlanningReason.ARTIFACT_SOURCE_UNRESOLVED)
    execution = action.execution or {}
    if action.strategy == PatchStrategy.HUMAN_COMMAND and (
            not execution.get("command") or execution.get("execution_target") != "patch-workspace"):
        reasons.append(PlanningReason.PATCH_STRATEGY_UNRESOLVED)
    if action.strategy == PatchStrategy.PREBUILT_IMAGE_REPLACEMENT and not (
            candidate and candidate.source_identifier):
        reasons.append(PlanningReason.ARTIFACT_SOURCE_UNRESOLVED)
    if action.strategy == PatchStrategy.REBUILD and not (
            candidate and candidate.source_identifier and candidate.build_system
            and execution.get("command")):
        reasons.append(PlanningReason.BUILD_PLAN_REQUIRES_HUMAN_INPUT)
    if action.strategy == PatchStrategy.ARTIFACT_REPLACEMENT and not (
            candidate and candidate.source_url and candidate.replacement_target):
        reasons.append(PlanningReason.ARTIFACT_SOURCE_UNRESOLVED)
    if PlanningReason.MAJOR_VERSION_CONFIRMATION_REQUIRED in action.input_reasons and (
            "major_version_approved" not in action.human_confirmed_fields):
        reasons.append(PlanningReason.MAJOR_VERSION_CONFIRMATION_REQUIRED)
    return tuple(sorted(set(reasons), key=lambda x: x.value))


def validate_patch_plan(plan: PatchPlan) -> PatchPlan:
    actions = []
    for action in plan.actions:
        reasons = validate_patch_action(action)
        status = (PlanningStatus.READY_FOR_PATCH_EXECUTION if not reasons
                  else PlanningStatus.WAITING_FOR_USER_INPUT)
        actions.append(replace(action, status=status, input_reasons=reasons))
    readiness = (PlanningStatus.READY_FOR_PATCH_EXECUTION
                 if all(x.status == PlanningStatus.READY_FOR_PATCH_EXECUTION for x in actions)
                 else PlanningStatus.WAITING_FOR_USER_INPUT)
    return PatchPlan(plan.run_id, tuple(actions), readiness)
