"""Read-only Step 5A planning orchestration through canonical evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping

import yaml

from ..resolution.artifacts import (
    ATTACK_RESULT_SCHEMA, PATCH_FORM_SCHEMA, PATCH_PLAN_SCHEMA, ArtifactWriteError,
    write_patch_form_immutable, write_patch_plan,
)
from ..state.models import (
    ArtifactKind, ArtifactReference, IntegrationFailureCode, PipelineStage,
    RunError, RunNotice, RunState, RunStatus, StageStatus,
)
from ..state.store import StateStore, StateStoreError, utc_text
from .models import PlanningStatus
from .planner import RemediationProvider, build_patch_plan


class PatchPlanningError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _patched_image(reference: str, run_id: str) -> str:
    name = reference.rsplit("/", 1)[-1].split("@", 1)[0].split(":", 1)[0].lower()
    name = re.sub(r"[^a-z0-9._-]+", "-", name).strip("-.") or "victim"
    return f"kalama/{name}:patched-{run_id.lower()}"


class PatchPlanningOrchestrator:
    def __init__(self, store: StateStore, provider: RemediationProvider, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store, self.provider, self.clock = store, provider, clock

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _fail(self, run_id: str, code: str, message: str) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_5_PATCH_PLAN, StageStatus.FAILED, timestamp)
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_5_PATCH_PLAN,
                         code, message, timestamp, False)
        state = replace(state, status=RunStatus.FAILED_FATAL,
                        current_stage=PipelineStage.STEP_5_PATCH_PLAN, waiting_reason=None,
                        errors=state.errors + (error,), updated_at=timestamp)
        return self._save(state)

    def _eligible(self, state: RunState) -> None:
        active = [x.run_id for x in self.store.discover()
                  if x.run_id != state.run_id and x.status == RunStatus.RUNNING]
        if active:
            raise PatchPlanningError("ACTIVE_RUN_CONFLICT",
                                     f"another run is active: {', '.join(sorted(active))}")
        if (state.status != RunStatus.PAUSED or state.current_stage != PipelineStage.STEP_5_PATCH
                or state.waiting_reason != "PATCH_NOT_INTEGRATED"
                or state.stage(PipelineStage.STEP_4_BEFORE_EXPLOIT).status != StageStatus.SUCCEEDED
                or state.stage(PipelineStage.STEP_5_PATCH_PLAN).status != StageStatus.NOT_STARTED
                or state.target is None):
            raise PatchPlanningError("INVALID_RUN_STATE", "run is not at the Step 5 planning boundary")

    def _json(self, state: RunState, kind: ArtifactKind, schema: str | int) -> tuple[ArtifactReference, Mapping[str, Any]]:
        reference = state.artifact(kind)
        if reference is None:
            raise PatchPlanningError("PATCH_INPUT_INTEGRITY_ERROR", f"state has no {kind.value}")
        try:
            path = Path(reference.path)
            if not path.is_file() or _sha(path) != reference.sha256 or reference.schema != schema:
                raise ValueError("file, digest, or reference schema mismatch")
            value = json.loads(path.read_bytes())
            if not isinstance(value, Mapping): raise ValueError("artifact is not an object")
            if isinstance(schema, str):
                if value.get("schema") != schema: raise ValueError("artifact schema mismatch")
            elif value.get("SchemaVersion") != schema:
                raise ValueError("Trivy schema mismatch")
            if kind != ArtifactKind.TRIVY_BEFORE:
                meta = value.get("artifact")
                if (not isinstance(meta, Mapping) or meta.get("run_id") != state.run_id
                        or (kind == ArtifactKind.ATTACK_BEFORE and meta.get("phase") != "before")):
                    raise ValueError("artifact run/phase identity mismatch")
            return reference, value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise PatchPlanningError("PATCH_INPUT_INTEGRITY_ERROR",
                                     f"{kind.value} validation failed: {exc}") from exc

    @staticmethod
    def _form(plan, run_id: str, plan_sha: str) -> dict[str, Any]:
        actions = {}
        for action in plan.actions:
            if action.status != PlanningStatus.WAITING_FOR_USER_INPUT:
                continue
            candidate = action.candidate
            actions[action.action_id] = {
                "target_cves": list(action.target_cves),
                "package": {"name": action.package_name, "ecosystem": action.ecosystem,
                            "before_versions": list(action.before_versions),
                            "scanner_fixed_versions": list(action.scanner_fixed_versions)},
                "input_reasons": [x.value for x in action.input_reasons],
                "fix_type": {"suggested": action.fix_type.value if action.fix_type else None,
                             "confirmed": None},
                "target_version": {"scanner_candidates": list(action.scanner_fixed_versions),
                                   "suggested": candidate.target_version if candidate else None,
                                   "confirmed": None},
                "artifact": {"suggested_source": candidate.source_url if candidate else None,
                             "confirmed_source": None,
                             "checksum": {"suggested": candidate.checksum if candidate else None,
                                          "confirmed": None}},
                "strategy": {"suggested": action.strategy.value if action.strategy else None,
                             "confirmed": None},
                "command": {"confirmed": None},
                "validation_command": {"confirmed": None},
                "execution_target": "patch-workspace",
                "major_version_approved": None,
                "notes": None,
            }
        return {"schema": PATCH_FORM_SCHEMA, "run_id": run_id, "phase": "patch",
                "revision": 1, "base_patch_plan_sha256": plan_sha, "actions": actions}

    def run(self, run_id: str) -> RunState:
        try:
            state = self.store.load(run_id)
            self._eligible(state)
            attack_ref, attack = self._json(state, ArtifactKind.ATTACK_BEFORE, ATTACK_RESULT_SCHEMA)
            top_ref, top = self._json(state, ArtifactKind.TOP30_BEFORE, "kalama.prioritization/v1")
            trivy_ref, _ = self._json(state, ArtifactKind.TRIVY_BEFORE, 2)
        except StateStoreError as exc:
            raise PatchPlanningError(exc.code, str(exc)) from exc
        except PatchPlanningError as exc:
            if exc.code in {"ACTIVE_RUN_CONFLICT", "INVALID_RUN_STATE"}: raise
            return self._fail(run_id, exc.code, str(exc))
        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_5_PATCH_PLAN, StageStatus.RUNNING, timestamp)
        state = replace(state, status=RunStatus.RUNNING,
                        current_stage=PipelineStage.STEP_5_PATCH_PLAN,
                        waiting_reason=None, updated_at=timestamp)
        state = self._save(state)
        try:
            attack_cves = attack.get("cves")
            ranked = top.get("ranked_cves")
            if not isinstance(attack_cves, list) or not isinstance(ranked, list):
                raise ValueError("attack/top30 CVE arrays are invalid")
            valid_statuses = {"EXPLOIT_SUCCEEDED", "EXPLOIT_FAILED", "CHECK_ONLY", "INCONCLUSIVE",
                              "NO_MSF_MODULE", "UNRESOLVED_CONFIG", "ENVIRONMENT_ERROR", "NOT_EXECUTED"}
            successful = []
            top_ids = {x.get("cve_id") for x in ranked if isinstance(x, Mapping)}
            for item in attack_cves:
                if not isinstance(item, Mapping) or item.get("cve_id") not in top_ids:
                    raise ValueError("attack CVE is absent from Top30")
                disposition = item.get("disposition")
                if disposition not in valid_statuses:
                    raise ValueError("attack disposition is malformed")
                if disposition == "EXPLOIT_SUCCEEDED":
                    successful.append((int(item["rank"]), str(item["cve_id"])))
            plan = build_patch_plan(run_id, successful, ranked, self.provider,
                                    target_facts=dict(state.target.facts) if state.target.facts else None)
        except Exception as exc:
            return self._fail(run_id, "PATCH_INPUT_INTEGRITY_ERROR", str(exc))
        image = state.target.image_identity
        requested = str(image.get("requested_reference") or state.victim_image)
        artifact = {"schema": PATCH_PLAN_SCHEMA, "run_id": run_id, "phase": "patch",
                    "created_at": self._now(),
                    "inputs": {"attack_before": attack_ref.to_dict(),
                               "top30_before": top_ref.to_dict(),
                               "trivy_before": trivy_ref.to_dict()},
                    "policy": {"preferred": "SAME_BRANCH", "fallback": "LATEST_UPSTREAM",
                               "major_version_change_requires_confirmation": True},
                    "source_image": {**dict(image), "do_not_delete_source_image": True},
                    "planned_after": {"image_reference": _patched_image(requested, run_id),
                                      "container_name": f"victim-after-{run_id}",
                                      "patch_workspace": f"patch-workspace-{run_id}"},
                    "readiness": plan.readiness.value,
                    "summary": {"intended_cves": len(successful), "actions": len(plan.actions),
                                "waiting_actions": sum(x.status == PlanningStatus.WAITING_FOR_USER_INPUT
                                                       for x in plan.actions)},
                    "actions": [x.to_dict() for x in plan.actions]}
        path = self.store.output_root / "patch" / "plan" / f"patch_plan_{state.created_at[:10]}_{run_id}.json"
        try:
            plan_sha = write_patch_plan(path, artifact)
            if _sha(path) != plan_sha or json.loads(path.read_bytes()) != artifact:
                raise ArtifactWriteError("Patch Plan verification failed")
        except (OSError, json.JSONDecodeError, ArtifactWriteError) as exc:
            return self._fail(run_id, "PATCH_PLAN_WRITE_FAILED", str(exc))
        timestamp = self._now()
        state = self.store.load(run_id).with_artifact(ArtifactReference(
            ArtifactKind.PATCH_PLAN, str(path.resolve()), plan_sha, PATCH_PLAN_SCHEMA,
            artifact["created_at"], PipelineStage.STEP_5_PATCH_PLAN,
            tuple(sorted(artifact["summary"].items()))), timestamp)
        # Persist deterministic discovery evidence (if the provider produces it) so a
        # reviewer can inspect why a candidate was classified or not made executable.
        writer = getattr(self.provider, "write_discovery_artifact", None)
        discovery_ref = None
        if callable(writer):
            try:
                written = writer(run_id)
                if written:
                    discovery_path, discovery_sha = written
                    discovery_value = json.loads(Path(discovery_path).read_bytes())
                    discovery_ref = ArtifactReference(
                        ArtifactKind.REMEDIATION_DISCOVERY, discovery_path, discovery_sha,
                        discovery_value.get("schema", "kalama.remediation-discovery/v1"),
                        self._now(), PipelineStage.STEP_5_PATCH_PLAN,
                        (("target_count", len(discovery_value.get("targets") or ())),))
            except Exception:
                discovery_ref = None
        if discovery_ref is not None:
            state = state.with_artifact(discovery_ref, timestamp)
        state = self._save(state)
        if plan.readiness == PlanningStatus.WAITING_FOR_USER_INPUT:
            form = self._form(plan, run_id, plan_sha)
            form_path = self.store.output_root / "patch" / "forms" / f"patch_form_{run_id}_r1.yaml"
            try:
                form_sha = write_patch_form_immutable(form_path, form)
                if _sha(form_path) != form_sha or yaml.safe_load(form_path.read_bytes()) != form:
                    raise ArtifactWriteError("Patch Form verification failed")
            except (OSError, yaml.YAMLError, ArtifactWriteError) as exc:
                return self._fail(run_id, "PATCH_FORM_WRITE_FAILED", str(exc))
            timestamp = self._now()
            state = self.store.load(run_id).with_artifact(ArtifactReference(
                ArtifactKind.PATCH_FORM, str(form_path.resolve()), form_sha, PATCH_FORM_SCHEMA,
                timestamp, PipelineStage.STEP_5_PATCH_PLAN,
                (("action_count", len(form["actions"])), ("revision", 1))), timestamp)
            state = state.with_stage(PipelineStage.STEP_5_PATCH_PLAN, StageStatus.WAITING, timestamp)
            state = replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                            current_stage=PipelineStage.STEP_5_PATCH_PLAN,
                            waiting_reason="PATCH_FORM", updated_at=timestamp)
            return self._save(state)
        timestamp = self._now()
        state = self.store.load(run_id).with_stage(
            PipelineStage.STEP_5_PATCH_PLAN, StageStatus.SUCCEEDED, timestamp)
        empty = not plan.actions
        reason = ("NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS" if empty
                  else "PATCH_EXECUTION_NOT_INTEGRATED")
        current = PipelineStage.STEP_5_PATCH_PLAN if empty else PipelineStage.STEP_5_PATCH_EXECUTION
        state = replace(state, status=RunStatus.PAUSED, current_stage=current,
                        waiting_reason=reason,
                        warnings=state.warnings + (RunNotice(reason,
                            "no exploitation-confirmed remediation targets" if empty
                            else "patch execution is not integrated yet", timestamp),),
                        updated_at=timestamp)
        return self._save(state)
