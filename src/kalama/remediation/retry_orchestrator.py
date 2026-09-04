"""Patch Execution retry orchestration for immutable attempt lineage."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from ..resolution.artifacts import PATCH_FORM_SCHEMA, PATCH_PLAN_SCHEMA, PATCH_RESULT_SCHEMA, write_patch_form_immutable
from ..state.models import ArtifactKind, ArtifactReference, PipelineStage, RunError, RunState, RunStatus, StageStatus
from ..state.store import StateStore, utc_text
from .codec import patch_plan_from_artifact, validate_patch_plan
from .models import PlanningStatus


RECOVERABLE_PATCH_FAILURES = {
    "AFTER_TARGET_IDENTITY_ERROR",
    "PATCH_ACTION_FAILED",
    "PATCH_EXECUTION_FAILED",
    "PATCHED_IMAGE_CREATE_FAILED",
    "PATCH_VALIDATION_FAILED",
    "PATCH_WORKSPACE_CREATE_FAILED",
    "PATCH_WORKSPACE_START_FAILED",
    "PATCH_WORKSPACE_INSPECT_FAILED",
}
INTEGRITY_FAILURES = {
    "PATCH_PLAN_INTEGRITY_ERROR",
    "PATCH_INPUT_INTEGRITY_ERROR",
    "PATCH_RESULT_INTEGRITY_ERROR",
    "SOURCE_IMAGE_IDENTITY_MISMATCH",
    "SOURCE_IMAGE_PRESERVATION_ERROR",
    "PATCHED_IMAGE_IDENTITY_ERROR",
}


class PatchRetryError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _revision(ref: ArtifactReference | None) -> int:
    if ref:
        for key, value in ref.summary:
            if key == "revision":
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return 0
    return 0


def _revisions_on_disk(root: Path, run_id: str) -> set[int]:
    found = set()
    patterns = (
        (root / "patch" / "forms", re.compile(rf"^patch_form_{re.escape(run_id)}_r(\d+)\.yaml$")),
        (root / "patch" / "forms" / "submissions",
         re.compile(rf"^patch_form_submission_{re.escape(run_id)}_r(\d+)\.yaml$")),
    )
    for directory, pattern in patterns:
        if not directory.exists():
            continue
        for path in sorted(directory.iterdir()):
            match = pattern.fullmatch(path.name)
            if match:
                found.add(int(match.group(1)))
    return found


def _attempt(ref: ArtifactReference | None) -> int:
    if ref:
        for key, value in ref.summary:
            if key == "attempt":
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return 0
        if "_attempt_" in Path(ref.path).name:
            try:
                return int(Path(ref.path).name.split("_attempt_", 1)[1].split(".", 1)[0])
            except ValueError:
                return 0
    return 0


def _attempts_on_disk(root: Path, run_id: str) -> set[int]:
    found = {}
    directory = root / "patch" / "results"
    pattern = re.compile(rf"^patch_result_\d{{4}}-\d{{2}}-\d{{2}}_{re.escape(run_id)}_attempt_(\d+)\.json$")
    if not directory.exists():
        return set()
    for path in sorted(directory.iterdir()):
        match = pattern.fullmatch(path.name)
        if not match:
            continue
        attempt = int(match.group(1))
        if attempt in found:
            raise PatchRetryError("PATCH_RESULT_ATTEMPT_AMBIGUOUS",
                                  f"multiple Patch Result files for attempt {attempt}")
        try:
            value = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise PatchRetryError("PATCH_RESULT_INTEGRITY_ERROR", str(exc)) from exc
        if (not isinstance(value, Mapping) or value.get("schema") != PATCH_RESULT_SCHEMA
                or value.get("run_id") != run_id or value.get("phase") != "patch"
                or value.get("attempt") != attempt):
            raise PatchRetryError("PATCH_RESULT_INTEGRITY_ERROR",
                                  f"invalid Patch Result identity: {path}")
        found[attempt] = path
    return set(found)


class PatchRetryOrchestrator:
    def __init__(self, store: StateStore, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store, self.clock = store, clock

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _load_plan(self, state: RunState) -> tuple[ArtifactReference, Mapping[str, Any]]:
        ref = state.artifact(ArtifactKind.PATCH_PLAN)
        if ref is None:
            raise PatchRetryError("PATCH_PLAN_INTEGRITY_ERROR", "missing Patch Plan")
        try:
            path = Path(ref.path)
            if not path.is_file() or _sha(path) != ref.sha256 or ref.schema != PATCH_PLAN_SCHEMA:
                raise ValueError("file, digest, or schema mismatch")
            value = json.loads(path.read_bytes())
            if (not isinstance(value, Mapping) or value.get("schema") != PATCH_PLAN_SCHEMA
                    or value.get("run_id") != state.run_id or value.get("phase") != "patch"):
                raise ValueError("plan identity mismatch")
            source = dict(value.get("source_image") or {})
            if state.target and source.get("image_id") != dict(state.target.image_identity).get("image_id"):
                raise ValueError("source image identity mismatch")
            plan = validate_patch_plan(patch_plan_from_artifact(value))
            if plan.readiness != PlanningStatus.READY_FOR_PATCH_EXECUTION:
                raise ValueError("plan is not ready for execution")
            return ref, value
        except PatchRetryError:
            raise
        except Exception as exc:
            raise PatchRetryError("PATCH_PLAN_INTEGRITY_ERROR", str(exc)) from exc

    def _load_form(self, state: RunState) -> Mapping[str, Any] | None:
        ref = state.artifact(ArtifactKind.PATCH_FORM)
        if ref is None:
            return None
        try:
            path = Path(ref.path)
            if not path.is_file() or _sha(path) != ref.sha256 or ref.schema != PATCH_FORM_SCHEMA:
                raise ValueError("file, digest, or schema mismatch")
            value = yaml.safe_load(path.read_bytes())
            if (not isinstance(value, Mapping) or value.get("schema") != PATCH_FORM_SCHEMA
                    or value.get("run_id") != state.run_id or value.get("phase") != "patch"):
                raise ValueError("form identity mismatch")
            return value
        except Exception as exc:
            raise PatchRetryError("PATCH_FORM_INTEGRITY_ERROR", str(exc)) from exc

    def _load_submission(self, state: RunState, plan_artifact: Mapping[str, Any]) -> Mapping[str, Any] | None:
        expected = dict(plan_artifact.get("provenance") or {}).get("submission_sha256")
        refs = [x for x in state.artifacts + state.artifact_history
                if x.kind == ArtifactKind.PATCH_FORM_SUBMISSION]
        if expected is None:
            if refs:
                ref = state.artifact(ArtifactKind.PATCH_FORM_SUBMISSION) or refs[-1]
            else:
                return None
        else:
            matches = [x for x in refs if x.sha256 == expected]
            if not matches:
                raise PatchRetryError("PATCH_FORM_SUBMISSION_INTEGRITY_ERROR",
                                      "active Patch Plan provenance references a missing submission")
            ref = matches[-1]
        try:
            path = Path(ref.path)
            if not path.is_file() or _sha(path) != ref.sha256 or ref.schema != PATCH_FORM_SCHEMA:
                raise ValueError("file, digest, or schema mismatch")
            value = yaml.safe_load(path.read_bytes())
            if (not isinstance(value, Mapping) or value.get("schema") != PATCH_FORM_SCHEMA
                    or value.get("run_id") != state.run_id or value.get("phase") != "patch"):
                raise ValueError("submission identity mismatch")
            return value
        except Exception as exc:
            raise PatchRetryError("PATCH_FORM_SUBMISSION_INTEGRITY_ERROR", str(exc)) from exc

    def _eligible(self, state: RunState) -> tuple[str, ArtifactReference | None]:
        if state.status != RunStatus.FAILED_FATAL:
            raise PatchRetryError("PATCH_RETRY_NOT_FAILED", "run is not FAILED_FATAL")
        if state.current_stage != PipelineStage.STEP_5_PATCH_EXECUTION:
            raise PatchRetryError("PATCH_RETRY_WRONG_STAGE", "run did not fail in Patch Execution")
        if state.stage(PipelineStage.STEP_5_PATCH_EXECUTION).status != StageStatus.FAILED:
            raise PatchRetryError("PATCH_RETRY_WRONG_STAGE", "Patch Execution stage is not failed")
        reason = state.errors[-1].code if state.errors else "UNKNOWN"
        if reason in INTEGRITY_FAILURES:
            raise PatchRetryError("PATCH_RETRY_INTEGRITY_FAILURE", reason)
        if reason not in RECOVERABLE_PATCH_FAILURES:
            raise PatchRetryError("PATCH_RETRY_UNSUPPORTED_FAILURE", reason)
        result_ref = state.artifact(ArtifactKind.PATCH_RESULT)
        if result_ref is not None:
            path = Path(result_ref.path)
            try:
                if not path.is_file() or _sha(path) != result_ref.sha256:
                    raise ValueError("result digest mismatch")
            except Exception as exc:
                raise PatchRetryError("PATCH_RESULT_INTEGRITY_ERROR", str(exc)) from exc
        return reason, result_ref

    @staticmethod
    def _form_from_plan(plan_artifact: Mapping[str, Any], *, run_id: str,
                        revision: int, base_sha: str) -> dict[str, Any]:
        actions = {}
        for action in patch_plan_from_artifact(plan_artifact).actions:
            candidate = action.candidate
            execution = dict(action.execution or {})
            actions[action.action_id] = {
                "target_cves": list(action.target_cves),
                "package": {"name": action.package_name, "ecosystem": action.ecosystem,
                            "before_versions": list(action.before_versions),
                            "scanner_fixed_versions": list(action.scanner_fixed_versions)},
                "input_reasons": [x.value for x in action.input_reasons],
                "fix_type": {"suggested": action.fix_type.value if action.fix_type else None,
                             "confirmed": action.fix_type.value if action.fix_type else None},
                "target_version": {"suggested": candidate.target_version if candidate else None,
                                   "confirmed": candidate.target_version if candidate else None},
                "artifact": {"suggested_source": candidate.source_url if candidate else None,
                             "confirmed_source": candidate.source_url if candidate else None,
                             "checksum": {"suggested": candidate.checksum if candidate else None,
                                          "confirmed": candidate.checksum if candidate else None}},
                "strategy": {"suggested": action.strategy.value if action.strategy else None,
                             "confirmed": action.strategy.value if action.strategy else None},
                "command": {"confirmed": execution.get("command")},
                "validation_command": {"confirmed": execution.get("validation_command")},
                "execution_target": execution.get("execution_target", "patch-workspace"),
                "major_version_approved": "major_version_approved" in action.human_confirmed_fields or None,
                "notes": None,
            }
        return {"schema": PATCH_FORM_SCHEMA, "run_id": run_id, "phase": "patch",
                "revision": revision, "base_patch_plan_sha256": base_sha, "actions": actions}

    def retry(self, run_id: str, *, edit_plan: bool) -> RunState:
        state = self.store.load(run_id)
        reason, result_ref = self._eligible(state)
        plan_ref, plan_artifact = self._load_plan(state)
        self._load_form(state)
        self._load_submission(state, plan_artifact)
        state_attempts = [_attempt(x) for x in state.artifacts + state.artifact_history
                          if x.kind == ArtifactKind.PATCH_RESULT]
        attempt = max(state_attempts + list(_attempts_on_disk(self.store.output_root, run_id)),
                      default=0) + 1
        now = self._now()
        if edit_plan:
            state_revisions = [_revision(x) for x in state.artifacts + state.artifact_history
                               if x.kind in {ArtifactKind.PATCH_FORM, ArtifactKind.PATCH_FORM_SUBMISSION,
                                             ArtifactKind.PATCH_PLAN}]
            revision = max(state_revisions + list(_revisions_on_disk(self.store.output_root, run_id)),
                           default=0) + 1
            form = self._form_from_plan(plan_artifact, run_id=run_id,
                                        revision=revision, base_sha=plan_ref.sha256)
            path = self.store.output_root / "patch" / "forms" / f"patch_form_{run_id}_r{revision}.yaml"
            sha = write_patch_form_immutable(path, form)
            if _sha(path) != sha or yaml.safe_load(path.read_bytes()) != form:
                raise PatchRetryError("PATCH_FORM_WRITE_FAILED", "Patch Form verification failed")
            state = self.store.load(run_id).with_artifact(ArtifactReference(
                ArtifactKind.PATCH_FORM, str(path.resolve()), sha, PATCH_FORM_SCHEMA, now,
                PipelineStage.STEP_5_PATCH_PLAN,
                (("revision", revision), ("retry_attempt", attempt), ("retry_mode", "EDIT_PLAN"),
                 ("retry_of", result_ref.sha256 if result_ref else None), ("retry_reason", reason))),
                now)
            state = state.with_stage(PipelineStage.STEP_5_PATCH_PLAN, StageStatus.WAITING, now)
            return self._save(replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                                      current_stage=PipelineStage.STEP_5_PATCH_PLAN,
                                      waiting_reason="PATCH_FORM", updated_at=now))
        stages = tuple(replace(x, status=StageStatus.NOT_STARTED, started_at=None, completed_at=None)
                       if x.stage == PipelineStage.STEP_5_PATCH_EXECUTION else x
                       for x in state.stages)
        return self._save(replace(state, status=RunStatus.PAUSED,
                                  current_stage=PipelineStage.STEP_5_PATCH_EXECUTION,
                                  waiting_reason="PATCH_EXECUTION_NOT_INTEGRATED",
                                  stages=stages, updated_at=now))
