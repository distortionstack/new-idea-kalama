"""Allowlisted immutable Patch Form application."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from .codec import validate_patch_plan
from .models import FixType, PatchPlan, PatchStrategy, RemediationCandidate


class PatchSubmissionError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message); self.code = code


def _confirmed(raw: Any) -> tuple[bool, Any]:
    return (isinstance(raw, Mapping) and raw.get("confirmed") is not None,
            raw.get("confirmed") if isinstance(raw, Mapping) else None)


def apply_patch_confirmations(plan: PatchPlan, submitted: Mapping[str, Any]) -> PatchPlan:
    allowed_root = {"schema", "run_id", "phase", "revision",
                    "base_patch_plan_sha256", "actions"}
    if set(submitted) - allowed_root:
        raise PatchSubmissionError("PATCH_FORM_UNKNOWN_FIELD", "unknown top-level field")
    actions_raw = submitted.get("actions")
    if not isinstance(actions_raw, Mapping):
        raise PatchSubmissionError("PATCH_FORM_UNKNOWN_FIELD", "actions must be an object")
    known = {x.action_id: x for x in plan.actions}
    unknown = set(actions_raw) - set(known)
    if unknown: raise PatchSubmissionError("UNKNOWN_PATCH_ACTION", ", ".join(sorted(unknown)))
    updated = []
    allowed = {"target_cves", "package", "input_reasons", "fix_type", "target_version",
               "artifact", "strategy", "command", "validation_command", "notes",
               "major_version_approved", "execution_target"}
    for action in plan.actions:
        raw = actions_raw.get(action.action_id)
        if raw is None:
            updated.append(action); continue
        if not isinstance(raw, Mapping) or set(raw) - allowed:
            raise PatchSubmissionError("PATCH_FORM_UNKNOWN_FIELD", action.action_id)
        if ("target_cves" in raw and tuple(raw["target_cves"]) != action.target_cves):
            raise PatchSubmissionError("PATCH_FORM_TAMPERED", "target CVEs changed")
        if "package" in raw:
            package = raw["package"]
            if (not isinstance(package, Mapping) or package.get("name") != action.package_name
                    or package.get("ecosystem") != action.ecosystem
                    or tuple(package.get("before_versions") or ()) != action.before_versions
                    or tuple(package.get("scanner_fixed_versions") or ())
                    != action.scanner_fixed_versions):
                raise PatchSubmissionError("PATCH_FORM_TAMPERED", "package evidence changed")
        if ("input_reasons" in raw
                and tuple(raw["input_reasons"]) != tuple(x.value for x in action.input_reasons)):
            raise PatchSubmissionError("PATCH_FORM_TAMPERED", "input reasons changed")
        candidate = action.candidate or RemediationCandidate()
        projections = (
            ("fix_type", action.fix_type.value if action.fix_type else None, "suggested"),
            ("strategy", action.strategy.value if action.strategy else None, "suggested"),
            ("target_version", candidate.target_version, "suggested"),
        )
        for key, expected, field in projections:
            if key in raw and (not isinstance(raw[key], Mapping)
                               or raw[key].get(field) != expected):
                raise PatchSubmissionError("PATCH_FORM_TAMPERED", f"{key} suggestion changed")
        if "artifact" in raw:
            artifact_projection = raw["artifact"]
            checksum_projection = (artifact_projection.get("checksum")
                                   if isinstance(artifact_projection, Mapping) else None)
            if (not isinstance(artifact_projection, Mapping)
                    or artifact_projection.get("suggested_source") != candidate.source_url
                    or not isinstance(checksum_projection, Mapping)
                    or checksum_projection.get("suggested") != candidate.checksum):
                raise PatchSubmissionError("PATCH_FORM_TAMPERED", "artifact evidence changed")
        fields = set(action.human_confirmed_fields)
        present, value = _confirmed(raw.get("fix_type"))
        fix_type = action.fix_type
        if present: fix_type = FixType(value); fields.add("fix_type")
        present, value = _confirmed(raw.get("strategy"))
        strategy = action.strategy
        if present: strategy = PatchStrategy(value); fields.add("strategy")
        present, value = _confirmed(raw.get("target_version"))
        if present:
            if not isinstance(value, str) or not value: raise PatchSubmissionError("PATCH_TARGET_INVALID", "target version")
            candidate = replace(candidate, target_version=value, trusted=True,
                                source_authority=candidate.source_authority or "human_patch_form")
            fields.add("target_version")
        artifact = raw.get("artifact")
        if isinstance(artifact, Mapping) and artifact.get("confirmed_source") is not None:
            source = artifact["confirmed_source"]
            if not isinstance(source, str) or not source: raise PatchSubmissionError("PATCH_SOURCE_INVALID", "source")
            candidate = replace(candidate, source_url=source, source_identifier=source,
                                trusted=True, source_authority="human_patch_form",
                                source_type="human_confirmed")
            fields.add("artifact_source")
        checksum_present, checksum_value = _confirmed(
            artifact.get("checksum") if isinstance(artifact, Mapping) else None)
        if checksum_present:
            if not isinstance(checksum_value, str) or not checksum_value:
                raise PatchSubmissionError("PATCH_CHECKSUM_INVALID", "checksum")
            candidate = replace(candidate, checksum=checksum_value)
            fields.add("artifact_checksum")
        execution = dict(action.execution or {})
        present, value = _confirmed(raw.get("command"))
        if present:
            if not isinstance(value, str) or not value: raise PatchSubmissionError("PATCH_COMMAND_INVALID", "command")
            execution["command"] = value; fields.add("command")
        present, value = _confirmed(raw.get("validation_command"))
        if present:
            execution["validation_command"] = value; fields.add("validation_command")
        if raw.get("execution_target") is not None:
            if raw["execution_target"] != "patch-workspace":
                raise PatchSubmissionError("PATCH_EXECUTION_TARGET_INVALID", "target")
            execution["execution_target"] = "patch-workspace"; fields.add("execution_target")
        if raw.get("major_version_approved") is True:
            fields.add("major_version_approved")
        updated.append(replace(action, fix_type=fix_type, strategy=strategy, candidate=candidate,
                               execution=execution, human_confirmed_fields=tuple(sorted(fields))))
    return validate_patch_plan(PatchPlan(plan.run_id, tuple(updated), plan.readiness))
