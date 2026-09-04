"""Patch Form continuation to a canonical executable PatchPlan revision."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib, json
from pathlib import Path
from typing import Callable, Mapping
import yaml

from ..resolution.artifacts import (
    PATCH_FORM_SCHEMA, PATCH_PLAN_SCHEMA, ArtifactWriteError, write_patch_form,
    write_patch_form_immutable, write_patch_plan, write_submission_snapshot_immutable,
)
from ..state.models import ArtifactKind, ArtifactReference, PipelineStage, RunError, RunState, RunStatus, StageStatus
from ..state.store import StateStore, utc_text
from .codec import patch_plan_from_artifact
from .confirmation import PatchSubmissionError, apply_patch_confirmations
from .models import PlanningStatus


def _sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()


class PatchConfirmationOrchestrator:
    def __init__(self, store: StateStore, *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store, self.clock = store, clock
    def _now(self): return utc_text(self.clock())
    def _save(self, state): self.store.save(state); return self.store.load(state.run_id)
    def _error(self, run_id, code, message, fatal=False):
        state=self.store.load(run_id); now=self._now()
        status=StageStatus.FAILED if fatal else StageStatus.WAITING
        state=state.with_stage(PipelineStage.STEP_5_PATCH_PLAN,status,now)
        err=RunError(f"E{len(state.errors)+1:04d}",PipelineStage.STEP_5_PATCH_PLAN,code,message,now,not fatal)
        return self._save(replace(state,status=RunStatus.FAILED_FATAL if fatal else RunStatus.WAITING_FOR_USER_INPUT,
            current_stage=PipelineStage.STEP_5_PATCH_PLAN,waiting_reason=None if fatal else "PATCH_FORM",
            errors=state.errors+(err,),updated_at=now))
    def _active(self,state):
        if any(x.run_id!=state.run_id and x.status==RunStatus.RUNNING for x in self.store.discover()):
            raise RuntimeError("ACTIVE_RUN_CONFLICT")
        if state.status!=RunStatus.WAITING_FOR_USER_INPUT or state.current_stage!=PipelineStage.STEP_5_PATCH_PLAN or state.waiting_reason!="PATCH_FORM":
            raise RuntimeError("INVALID_RUN_STATE")
    def _load(self,ref,schema,yaml_doc=False):
        p=Path(ref.path)
        if not p.is_file() or _sha(p)!=ref.sha256 or ref.schema!=schema: raise ValueError("artifact integrity")
        value=yaml.safe_load(p.read_bytes()) if yaml_doc else json.loads(p.read_bytes())
        if not isinstance(value,Mapping) or value.get("schema")!=schema: raise ValueError("artifact schema")
        return value
    @staticmethod
    def _form(plan,run_id,revision,base_sha):
        actions={}
        for a in plan.actions:
            if a.status!=PlanningStatus.WAITING_FOR_USER_INPUT: continue
            c=a.candidate
            actions[a.action_id]={"target_cves":list(a.target_cves),"package":{"name":a.package_name,"ecosystem":a.ecosystem,"before_versions":list(a.before_versions),"scanner_fixed_versions":list(a.scanner_fixed_versions)},
                "input_reasons":[x.value for x in a.input_reasons],"fix_type":{"suggested":a.fix_type.value if a.fix_type else None,"confirmed":None},
                "target_version":{"suggested":c.target_version if c else None,"confirmed":None},"artifact":{"suggested_source":c.source_url if c else None,"confirmed_source":None,"checksum":{"suggested":c.checksum if c else None,"confirmed":None}},
                "strategy":{"suggested":a.strategy.value if a.strategy else None,"confirmed":None},"command":{"confirmed":None},"validation_command":{"confirmed":None},"execution_target":"patch-workspace","major_version_approved":None,"notes":None}
        return {"schema":PATCH_FORM_SCHEMA,"run_id":run_id,"phase":"patch","revision":revision,"base_patch_plan_sha256":base_sha,"actions":actions}
    def apply_patch_form(self,run_id:str,submission_path:Path)->RunState:
        state=self.store.load(run_id)
        try: raw=submission_path.read_bytes()
        except OSError as exc: return self._error(run_id,"PATCH_FORM_INVALID_YAML",str(exc))
        digest=hashlib.sha256(raw).hexdigest()
        if any(x.kind==ArtifactKind.PATCH_FORM_SUBMISSION and x.sha256==digest for x in state.artifacts+state.artifact_history): return state
        self._active(state)
        now=self._now(); state=state.with_stage(PipelineStage.STEP_5_PATCH_PLAN,StageStatus.RUNNING,now)
        state=self._save(replace(state,status=RunStatus.RUNNING,waiting_reason=None,updated_at=now))
        plan_ref=state.artifact(ArtifactKind.PATCH_PLAN); form_ref=state.artifact(ArtifactKind.PATCH_FORM)
        if not plan_ref or not form_ref: return self._error(run_id,"PATCH_PLAN_INTEGRITY_ERROR","missing plan/form",True)
        try: base=self._load(plan_ref,PATCH_PLAN_SCHEMA); form=self._load(form_ref,PATCH_FORM_SCHEMA,True)
        except Exception as exc: return self._error(run_id,"PATCH_PLAN_INTEGRITY_ERROR",str(exc),True)
        try: submitted=yaml.safe_load(raw)
        except yaml.YAMLError as exc: return self._error(run_id,"PATCH_FORM_INVALID_YAML",str(exc))
        if not isinstance(submitted,Mapping): return self._error(run_id,"PATCH_FORM_INVALID_YAML","mapping required")
        for key,expected,code in (("schema",PATCH_FORM_SCHEMA,"PATCH_FORM_SCHEMA_MISMATCH"),("run_id",run_id,"PATCH_FORM_RUN_MISMATCH"),("phase","patch","PATCH_FORM_PHASE_MISMATCH")):
            if submitted.get(key)!=expected:return self._error(run_id,code,f"{key} mismatch")
        if submitted.get("revision")!=form.get("revision") or submitted.get("base_patch_plan_sha256")!=plan_ref.sha256:
            return self._error(run_id,"STALE_PATCH_FORM","stale Patch Form")
        try: updated=apply_patch_confirmations(patch_plan_from_artifact(base),submitted)
        except (PatchSubmissionError,ValueError,TypeError) as exc:return self._error(run_id,getattr(exc,"code","PATCH_FORM_INVALID"),str(exc))
        rev=int(form["revision"]); snapshot=self.store.output_root/"patch"/"forms"/"submissions"/f"patch_form_submission_{run_id}_r{rev}.yaml"
        try: snap_sha=write_submission_snapshot_immutable(snapshot,raw)
        except Exception as exc:return self._error(run_id,"PATCH_SUBMISSION_WRITE_FAILED",str(exc),True)
        artifact=dict(base); artifact.update(created_at=self._now(),revision=rev,readiness=updated.readiness.value,
            provenance={"previous_patch_plan_sha256":plan_ref.sha256,"patch_form_sha256":form_ref.sha256,"submission_sha256":snap_sha},actions=[x.to_dict() for x in updated.actions])
        form_summary = dict(form_ref.summary)
        if form_summary.get("retry_of"):
            artifact["retry"] = {"attempt": form_summary.get("retry_attempt"),
                                 "retry_of": form_summary.get("retry_of"),
                                 "reason": form_summary.get("retry_reason"),
                                 "mode": "EDIT_PLAN",
                                 "created_at": form_ref.created_at}
        artifact["summary"]={**dict(artifact.get("summary") or {}),"waiting_actions":sum(x.status==PlanningStatus.WAITING_FOR_USER_INPUT for x in updated.actions)}
        path=self.store.output_root/"patch"/"plan"/f"patch_plan_{run_id}_r{rev}.json"
        try: plan_sha=write_patch_plan(path,artifact)
        except Exception as exc:return self._error(run_id,"PATCH_PLAN_WRITE_FAILED",str(exc),True)
        now=self._now(); state=self.store.load(run_id)
        state=state.with_artifact(ArtifactReference(ArtifactKind.PATCH_FORM_SUBMISSION,str(snapshot.resolve()),snap_sha,PATCH_FORM_SCHEMA,now,PipelineStage.STEP_5_PATCH_PLAN,(("revision",rev),)),now)
        state=state.with_artifact(ArtifactReference(ArtifactKind.PATCH_PLAN,str(path.resolve()),plan_sha,PATCH_PLAN_SCHEMA,artifact["created_at"],PipelineStage.STEP_5_PATCH_PLAN,(("revision",rev),("waiting_actions",artifact["summary"]["waiting_actions"]),)),now)
        state=self._save(state)
        if updated.readiness==PlanningStatus.WAITING_FOR_USER_INPUT:
            nxt=rev+1; next_form=self._form(updated,run_id,nxt,plan_sha); fp=self.store.output_root/"patch"/"forms"/f"patch_form_{run_id}_r{nxt}.yaml"
            try: fsha=write_patch_form_immutable(fp,next_form)
            except Exception as exc:return self._error(run_id,"PATCH_FORM_WRITE_FAILED",str(exc),True)
            now=self._now();state=self.store.load(run_id).with_artifact(ArtifactReference(ArtifactKind.PATCH_FORM,str(fp.resolve()),fsha,PATCH_FORM_SCHEMA,now,PipelineStage.STEP_5_PATCH_PLAN,(("revision",nxt),)),now)
            state=state.with_stage(PipelineStage.STEP_5_PATCH_PLAN,StageStatus.WAITING,now)
            return self._save(replace(state,status=RunStatus.WAITING_FOR_USER_INPUT,waiting_reason="PATCH_FORM",updated_at=now))
        now=self._now();state=self.store.load(run_id).with_stage(PipelineStage.STEP_5_PATCH_PLAN,StageStatus.SUCCEEDED,now)
        return self._save(replace(state,status=RunStatus.PAUSED,current_stage=PipelineStage.STEP_5_PATCH_EXECUTION,waiting_reason="PATCH_EXECUTION_NOT_INTEGRATED",updated_at=now))
