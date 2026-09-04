"""Canonical PatchPlan execution to patched-image and after-target evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib,json
import re
from pathlib import Path
from typing import Any,Callable,Mapping

from ..resolution.artifacts import PATCH_PLAN_SCHEMA,PATCH_RESULT_SCHEMA,ArtifactWriteError,write_patch_result_immutable
from ..state.models import ArtifactKind,ArtifactReference,PipelineStage,RunError,RunState,RunStatus,StageStatus,TargetState
from ..state.store import StateStore,utc_text
from .codec import patch_plan_from_artifact,validate_patch_plan
from .execution import PatchBackend
from .models import PatchStrategy,PlanningStatus


def _sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _attempts_on_disk(root:Path,run_id:str):
    pattern=re.compile(rf"^patch_result_\d{{4}}-\d{{2}}-\d{{2}}_{re.escape(run_id)}_attempt_(\d+)\.json$")
    found={}
    directory=root/"patch"/"results"
    if not directory.exists():return found
    for path in sorted(directory.iterdir()):
        match=pattern.fullmatch(path.name)
        if not match:continue
        attempt=int(match.group(1))
        if attempt in found:raise ArtifactWriteError(f"PATCH_RESULT_ATTEMPT_AMBIGUOUS: {attempt}")
        try:
            value=json.loads(path.read_bytes())
        except (OSError,json.JSONDecodeError) as exc:
            raise ArtifactWriteError(f"PATCH_RESULT_INTEGRITY_ERROR: {path}: {exc}") from exc
        if not isinstance(value,Mapping) or value.get("schema")!=PATCH_RESULT_SCHEMA or value.get("run_id")!=run_id or value.get("phase")!="patch" or value.get("attempt")!=attempt:
            raise ArtifactWriteError(f"PATCH_RESULT_INTEGRITY_ERROR: {path}")
        found[attempt]=path
    return found


class PatchExecutionOrchestrator:
    def __init__(self,store:StateStore,backend:PatchBackend,*,clock:Callable[[],datetime]=lambda:datetime.now(timezone.utc),action_timeout:float=300):
        self.store,self.backend,self.clock,self.action_timeout=store,backend,clock,action_timeout
    def _now(self):return utc_text(self.clock())
    def _save(self,s):self.store.save(s);return self.store.load(s.run_id)
    def _fail(self,run_id,code,message):
        s=self.store.load(run_id);n=self._now();s=s.with_stage(PipelineStage.STEP_5_PATCH_EXECUTION,StageStatus.FAILED,n)
        e=RunError(f"E{len(s.errors)+1:04d}",PipelineStage.STEP_5_PATCH_EXECUTION,code,message,n,False)
        return self._save(replace(s,status=RunStatus.FAILED_FATAL,current_stage=PipelineStage.STEP_5_PATCH_EXECUTION,waiting_reason=None,errors=s.errors+(e,),updated_at=n))
    @staticmethod
    def _attempt_from_ref(ref):
        if not ref:
            return 0
        for key,value in ref.summary:
            if key=="attempt":
                try:return int(value)
                except (TypeError,ValueError):return 0
        name=Path(ref.path).name
        marker="_attempt_"
        if marker in name:
            try:return int(name.split(marker,1)[1].split(".",1)[0])
            except ValueError:return 0
        return 1
    def _next_attempt(self,s):
        refs=[x for x in (s.artifacts+s.artifact_history) if x.kind==ArtifactKind.PATCH_RESULT]
        state_attempts=[self._attempt_from_ref(x) for x in refs]
        disk_attempts=list(_attempts_on_disk(self.store.output_root,s.run_id))
        return max(state_attempts+disk_attempts,default=0)+1
    def _eligible(self,s):
        if any(x.run_id!=s.run_id and x.status==RunStatus.RUNNING for x in self.store.discover()):raise RuntimeError("ACTIVE_RUN_CONFLICT")
        if (s.status == RunStatus.PAUSED
                and s.current_stage == PipelineStage.STEP_5_PATCH_PLAN
                and s.waiting_reason == "NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS"):
            return
        if s.status!=RunStatus.PAUSED or s.current_stage!=PipelineStage.STEP_5_PATCH_EXECUTION or s.waiting_reason!="PATCH_EXECUTION_NOT_INTEGRATED" or s.stage(PipelineStage.STEP_5_PATCH_PLAN).status!=StageStatus.SUCCEEDED:raise RuntimeError("INVALID_RUN_STATE")
    def _plan(self,s):
        r=s.artifact(ArtifactKind.PATCH_PLAN)
        if not r:raise ValueError("missing Patch Plan")
        p=Path(r.path)
        if not p.is_file() or _sha(p)!=r.sha256 or r.schema!=PATCH_PLAN_SCHEMA:raise ValueError("Patch Plan integrity")
        a=json.loads(p.read_bytes())
        if a.get("schema")!=PATCH_PLAN_SCHEMA or a.get("run_id")!=s.run_id or a.get("phase")!="patch":raise ValueError("Patch Plan identity")
        if dict(a.get("source_image") or {}).get("image_id")!=dict(s.target.image_identity).get("image_id"):raise ValueError("source image mismatch")
        plan=validate_patch_plan(patch_plan_from_artifact(a))
        if plan.readiness!=PlanningStatus.READY_FOR_PATCH_EXECUTION:raise RuntimeError("PATCH_PLAN_NOT_READY")
        return r,a,plan
    def _publish(self,s,plan_ref,plan_artifact,actions,source,patched=None,after_image=None,after_facts=None,errors=(),attempt=1,lineage=None,failed_at=None,validation_evidence=None,finalize_evidence=None,after_start_evidence=None):
        result={"schema":PATCH_RESULT_SCHEMA,"run_id":s.run_id,"phase":"patch","created_at":self._now(),
            "attempt":attempt,"lineage":dict(lineage or {}),"status":"FAILED" if errors else "SUCCEEDED",
            "failed_at":failed_at,
            "plan":{"path":plan_ref.path,"sha256":plan_ref.sha256,"revision":plan_artifact.get("revision",0)},
            "source_image":dict(source),"actions":actions,"patched_image":dict(patched) if patched else None,
            "after_target":{"image_identity":dict(after_image),"facts":dict(after_facts)} if after_image and after_facts else None,
            "validation_evidence":dict(validation_evidence) if validation_evidence else None,
            "finalize_evidence":dict(finalize_evidence) if finalize_evidence else None,
            "after_start_evidence":dict(after_start_evidence) if after_start_evidence else None,
            "errors":list(errors),"remediation_verified":False}
        path=self.store.output_root/"patch"/"results"/f"patch_result_{s.created_at[:10]}_{s.run_id}_attempt_{attempt}.json"
        sha=write_patch_result_immutable(path,result)
        if _sha(path)!=sha or json.loads(path.read_bytes())!=result:raise ArtifactWriteError("Patch Result verification")
        n=self._now();state=self.store.load(s.run_id).with_artifact(ArtifactReference(ArtifactKind.PATCH_RESULT,str(path.resolve()),sha,PATCH_RESULT_SCHEMA,result["created_at"],PipelineStage.STEP_5_PATCH_EXECUTION,(("actions",len(actions)),("attempt",attempt),("succeeded",sum(x["result"]=="SUCCEEDED" for x in actions)))),n)
        return self._save(state)
    def run(self,run_id:str)->RunState:
        s=self.store.load(run_id);self._eligible(s)
        if (s.current_stage == PipelineStage.STEP_5_PATCH_PLAN
                and s.waiting_reason == "NO_EXPLOIT_CONFIRMED_REMEDIATION_TARGETS"):
            return s
        try:plan_ref,artifact,plan=self._plan(s)
        except RuntimeError:raise
        except Exception as exc:return self._fail(run_id,"PATCH_PLAN_INTEGRITY_ERROR",str(exc))
        attempt=self._next_attempt(s);previous=max((x for x in (s.artifacts+s.artifact_history) if x.kind==ArtifactKind.PATCH_RESULT),key=lambda x:self._attempt_from_ref(x),default=None)
        n=self._now();s=s.with_stage(PipelineStage.STEP_5_PATCH_EXECUTION,StageStatus.RUNNING,n);s=self._save(replace(s,status=RunStatus.RUNNING,waiting_reason=None,updated_at=n))
        if not plan.actions:return s
        lineage=dict(artifact.get("retry") or {})
        if previous and "retry_of" not in lineage:
            lineage={"attempt":attempt,"retry_of":previous.sha256,
                     "reason":s.errors[-1].code if s.errors else None,
                     "mode":"SAME_PLAN","created_at":self._now(),**lineage}
        source={};workspace=None;patched=None;records=[];validation_evidence=None;finalize_evidence=None;after_start_evidence=None
        try:
            source=dict(self.backend.inspect_source(artifact["source_image"]))
            expected_source_id=artifact["source_image"].get("image_id")
            if expected_source_id and source.get("image_id")!=expected_source_id:raise RuntimeError("SOURCE_IMAGE_IDENTITY_MISMATCH")
            prebuilt=all(x.strategy==PatchStrategy.PREBUILT_IMAGE_REPLACEMENT for x in plan.actions)
            workspace=None if prebuilt else dict(self.backend.prepare_workspace(artifact,attempt=attempt))
            failed=False
            for action in plan.actions:
                if failed:
                    records.append({"action_id":action.action_id,"target_cves":list(action.target_cves),"strategy":action.strategy.value,"attempt_number":attempt,"source_image":source,"workspace":workspace,"result":"NOT_EXECUTED"});continue
                start=self._now()
                if action.strategy==PatchStrategy.PREBUILT_IMAGE_REPLACEMENT:
                    evidence=dict(self.backend.resolve_prebuilt_image(action,artifact));ok=bool(evidence.get("success"));
                    if ok:patched=dict(evidence["image_identity"])
                else:
                    evidence=dict(self.backend.execute_action(action,{"workspace":workspace,"source_image":source,"planned_after":artifact["planned_after"]},timeout=self.action_timeout));ok=bool(evidence.get("success"))
                records.append({"action_id":action.action_id,"target_cves":list(action.target_cves),"incidental_cves":list(action.incidental_cves),"strategy":action.strategy.value,"attempt_number":attempt,"source_image":source,"workspace":workspace,"started_at":start,"ended_at":self._now(),"result":"SUCCEEDED" if ok else "FAILED","command_evidence":evidence,"evidence":evidence})
                failed=not ok
            if failed:
                state=self._publish(s,plan_ref,artifact,records,source,errors=("PATCH_ACTION_FAILED",),attempt=attempt,lineage=lineage,failed_at="COMMAND")
                return self._fail(run_id,"PATCH_ACTION_FAILED","a canonical patch action failed")
            if not prebuilt:
                validation_command=str(artifact.get("validation_command") or artifact["planned_after"].get("validation_command") or "")
                if not validation_command:
                    commands=[(x.execution or {}).get("validation_command") for x in plan.actions]
                    validation_command=next((str(x) for x in commands if x), "")
                if validation_command:
                    validation_evidence=dict(self.backend.execute_validation(validation_command,{"workspace":workspace,"source_image":source,"planned_after":artifact["planned_after"]},timeout=self.action_timeout));ok=bool(validation_evidence.get("success"))
                    if not ok:
                        self._publish(s,plan_ref,artifact,records,source,errors=("PATCH_VALIDATION_FAILED",),attempt=attempt,lineage=lineage,failed_at="VALIDATION",validation_evidence=validation_evidence)
                        return self._fail(run_id,"PATCH_VALIDATION_FAILED","canonical patch validation command failed")
            if patched is None:
                patched=dict(self.backend.finalize_image(artifact,workspace))
                finalize_evidence={"status":"IMAGE_COMMITTED","image_identity":dict(patched)}
            if patched.get("reference")!=artifact["planned_after"].get("image_reference") or patched.get("image_id")==source.get("image_id"):raise RuntimeError("PATCHED_IMAGE_IDENTITY_ERROR")
            if not self.backend.verify_source_preserved(source):raise RuntimeError("SOURCE_IMAGE_PRESERVATION_ERROR")
            after_image,after_facts=self.backend.create_after_target(run_id,patched,artifact["planned_after"],s.target.facts)
            after_start_evidence={"status":"AFTER_TARGET_READY","container_name":after_facts.get("container_name"),"image_id":after_image.get("image_id")}
            if after_facts.get("phase")!="after" or after_facts.get("container_name")!=f"victim-after-{run_id}" or after_facts.get("network")!="kalama-net":raise RuntimeError("AFTER_TARGET_IDENTITY_ERROR")
            state=self._publish(s,plan_ref,artifact,records,source,patched,after_image,after_facts,attempt=attempt,lineage=lineage,validation_evidence=validation_evidence,finalize_evidence=finalize_evidence,after_start_evidence=after_start_evidence)
        except ArtifactWriteError as exc:return self._fail(run_id,"PATCH_RESULT_WRITE_FAILED",str(exc))
        except Exception as exc:
            try:self._publish(s,plan_ref,artifact,records,source,patched,errors=(str(exc),),attempt=attempt,lineage=lineage,failed_at="EXECUTION",validation_evidence=validation_evidence,finalize_evidence=finalize_evidence,after_start_evidence=after_start_evidence)
            except Exception:pass
            return self._fail(run_id,str(exc) if str(exc).isupper() else "PATCH_EXECUTION_FAILED",str(exc))
        n=self._now();state=self.store.load(run_id)
        state=replace(state,patched_image=dict(patched),after_target=TargetState(dict(after_image),dict(after_facts)),updated_at=n)
        state=state.with_stage(PipelineStage.STEP_5_PATCH_EXECUTION,StageStatus.SUCCEEDED,n)
        return self._save(replace(state,status=RunStatus.PAUSED,current_stage=PipelineStage.STEP_6_AFTER_SCAN,waiting_reason="AFTER_SCAN_NOT_INTEGRATED",updated_at=n))
