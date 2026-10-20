"""Read-only Step 8 evidence evaluation and canonical run completion."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from ..resolution.artifacts import (
    ATTACK_RESULT_SCHEMA, EXPLOIT_CONFIG_SET_SCHEMA, EVALUATION_DATASET_SCHEMA, EVALUATION_METRICS_SCHEMA,
    PATCH_PLAN_SCHEMA, REMEDIATION_RESULT_SCHEMA,
    REMEDIATION_SCAN_RESULT_SCHEMA, RUN_SUMMARY_SCHEMA, ArtifactWriteError,
    write_evaluation_dataset, write_evaluation_metrics, write_run_summary,
)
from ..state.models import (
    ArtifactKind, ArtifactReference, PipelineStage, RunError, RunNotice, RunState, RunStatus,
    StageStatus,
)
from ..state.store import StateStore, utc_text
from .metrics import TOP_N_ONLY, build_evaluation_records, compute_metrics
from .scoped_evidence import (
    ScopedScannerStatus, classify_scoped_remediation, derive_global_evidence,
    derive_scoped_status,
)


def _patch_disposition_by_cve(patch_plan: Mapping[str, Any] | None) -> dict[str, str | None]:
    """Map CVE to its PatchAction disposition (EXECUTE default, SKIP preserved)."""
    mapping: dict[str, str | None] = {}
    if not isinstance(patch_plan, Mapping):
        return mapping
    actions = patch_plan.get("actions")
    if not isinstance(actions, list):
        return mapping
    for action in actions:
        if not isinstance(action, Mapping):
            continue
        disposition = action.get("disposition") or "EXECUTE"
        for cve in action.get("target_cves") or ():
            key = str(cve)
            # A CVE covered by any EXECUTE action is evaluated; only CVEs
            # covered exclusively by SKIP remain non-evaluated.
            if key not in mapping:
                mapping[key] = str(disposition)
            elif mapping[key] == "SKIP_OUT_OF_SCOPE" and disposition == "EXECUTE":
                mapping[key] = "EXECUTE"
    return mapping


def _scan_entry_by_cve(scan_result: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    mapping: dict[str, Mapping[str, Any]] = {}
    if not isinstance(scan_result, Mapping):
        return mapping
    for item in scan_result.get("intended_targets") or ():
        if isinstance(item, Mapping) and isinstance(item.get("cve_id"), str):
            mapping[str(item["cve_id"])] = item
    return mapping


def enrich_records_with_scoped_evidence(
    records: list[dict[str, Any]],
    remediation: Mapping[str, Any],
    scan_result: Mapping[str, Any] | None,
    patch_plan: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Attach ScopedRemediationEvidence + GlobalAfterEvidence to each record.

    Pure reinterpretation of already-committed Step 6 / Step 7 artifacts.
    Never modifies scanner detection, patch execution, retry, or oracle output.
    """
    remediation_by_cve = {
        str(item.get("cve_id")): item
        for item in remediation.get("cves") or ()
        if isinstance(item, Mapping) and isinstance(item.get("cve_id"), str)
    }
    scan_by_cve = _scan_entry_by_cve(scan_result)
    disposition_by_cve = _patch_disposition_by_cve(patch_plan)
    enriched: list[dict[str, Any]] = []
    for record in records:
        cve_id = str(record.get("cve_id"))
        rem = remediation_by_cve.get(cve_id) or {}
        scan_entry = scan_by_cve.get(cve_id)
        patch_status = (rem.get("patch") or {}).get("action_status")
        before_disposition = (rem.get("before") or {}).get("disposition")
        after_exploit = rem.get("after_exploit") or {}
        after_disposition = after_exploit.get("disposition")
        after_oracle = after_exploit.get("oracle")
        metric_eligible = bool(after_exploit.get("metric_eligible"))
        comparable = bool((rem.get("comparability") or {}).get("same_invariant_config"))
        disposition = disposition_by_cve.get(cve_id) or "EXECUTE"
        scoped_derived = derive_scoped_status(
            scan_entry,
            patch_action_status=patch_status,
            patch_disposition=disposition,
        )
        scoped_status = str(scoped_derived["scoped_status"])
        same_elsewhere = bool(scoped_derived.get("same_cve_found_elsewhere", False))
        global_evidence = derive_global_evidence(scan_entry)
        global_status = str(global_evidence["global_status"])
        # same_cve_found_elsewhere is true when the scoped target is clean
        # while the image-wide scan still reports the CVE.
        if scoped_status == ScopedScannerStatus.SCOPED_NOT_FOUND.value and global_status == "FOUND":
            same_elsewhere = True
        judged = classify_scoped_remediation(
            cve_id=cve_id,
            before_disposition=before_disposition,
            patch_status=patch_status,
            patch_disposition=disposition,
            scoped_status=scoped_status,
            global_status=global_status,
            same_cve_found_elsewhere=same_elsewhere,
            after_disposition=after_disposition,
            after_oracle=after_oracle,
            metric_eligible=metric_eligible,
            comparable=comparable,
        )
        # Preserve global evidence separately; scoped judges the PatchAction.
        scoped_block = {
            "scoped_status": scoped_status,
            "scoped_reason": scoped_derived.get("reason"),
            "global_status": global_status,
            "same_cve_found_elsewhere": same_elsewhere,
            "global_residual_risk": bool(global_evidence.get("residual_risk", False)),
            "patch_disposition": disposition,
            "scoped_final_status": judged["final_status"],
            "remediation_validated": bool(judged["remediation_validated"]),
            "residual_risk": bool(judged["residual_risk"]),
            "evaluation_reason": judged["reason"],
        }
        enriched.append({**record, "scoped_remediation": scoped_block})
    return enriched


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EvaluationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class EvaluationOrchestrator:
    def __init__(self, store: StateStore, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store, self.clock = store, clock

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _write_validated_knowledge(self, state: RunState, top: Mapping[str, Any], attack: Mapping[str, Any],
                                   config: Mapping[str, Any], remediation: Mapping[str, Any],
                                   patch_plan: Mapping[str, Any], patch_ref: ArtifactReference) -> int:
        """Persist only attributable successful BEFORE evidence after final evaluation.

        The final remediation artifact has already passed lineage checks when this
        is called.  No LLM proposal or transient network/container identity is
        written as reusable knowledge.
        """
        from ..knowledge import KnowledgeStore
        from ..knowledge.writer import validated_attack_record
        from ..knowledge.writer import validated_remediation_record
        attacks = {str(x.get("cve_id")): x for x in attack.get("cves") or () if isinstance(x, Mapping)}
        configs = {str(x.get("cve_id")): x for x in config.get("cves") or () if isinstance(x, Mapping)}
        count = 0
        store = KnowledgeStore(self.store.output_root)
        for ranked in top.get("ranked_cves") or ():
            if not isinstance(ranked, Mapping):
                continue
            cve = str(ranked.get("cve_id"))
            if attacks.get(cve, {}).get("disposition") != "EXPLOIT_SUCCEEDED":
                continue
            raw = configs.get(cve, {}).get("exploit_config")
            if isinstance(raw, Mapping):
                invariant, environment = raw.get("invariant") or {}, raw.get("environment") or {}
                fields = {"module": ((invariant.get("module_selection") or {}).get("module") or {}).get("value"),
                          "targeturi": (invariant.get("targeturi") or {}).get("value"),
                          "payload": ((invariant.get("payload") or {}).get("payload") or {}).get("value"),
                          "rport": (environment.get("rport") or {}).get("value")}
                for occurrence in ranked.get("occurrences") or ():
                    if isinstance(occurrence, Mapping):
                        record = validated_attack_record(cve_id=cve, occurrence=occurrence, config=fields,
                            run_id=state.run_id, evidence={"attack_before": state.artifact(ArtifactKind.ATTACK_BEFORE).to_dict(),
                            "remediation_result": state.artifact(ArtifactKind.REMEDIATION_RESULT).to_dict()})
                        if record:
                            store.upsert(record); count += 1
            # Remediation is reusable only after the final classifier says it
            # was verified; scanner success alone is intentionally insufficient.
            final = next((x for x in remediation.get("cves") or ()
                          if isinstance(x, Mapping) and x.get("cve_id") == cve), {})
            status = ((final.get("final") or {}).get("status") if isinstance(final, Mapping) else None)
            if status != "VERIFIED":
                continue
            # The committed Patch Plan is authoritative.  The final result only
            # references it, so never mine duplicate fields from downstream data.
            for action in patch_plan.get("actions") or ():
                if not isinstance(action, Mapping) or cve not in (action.get("target_cves") or ()):
                    continue
                for occurrence in ranked.get("occurrences") or ():
                    if not isinstance(occurrence, Mapping):
                        continue
                    patch_record = validated_remediation_record(cve_id=cve, occurrence=occurrence,
                        action=action, run_id=state.run_id, evidence={
                            "patch_plan": patch_ref.to_dict(), "patch_action_id": action.get("action_id"),
                            "remediation_result": state.artifact(ArtifactKind.REMEDIATION_RESULT).to_dict(),
                            "attack_before": state.artifact(ArtifactKind.ATTACK_BEFORE).to_dict()})
                    if patch_record:
                        store.upsert(patch_record); count += 1
        return count

    def _fail(self, run_id: str, code: str, message: str) -> RunState:
        state, now = self.store.load(run_id), self._now()
        state = state.with_stage(PipelineStage.STEP_8_EVALUATION, StageStatus.FAILED, now)
        error = RunError(f"E{len(state.errors)+1:04d}", PipelineStage.STEP_8_EVALUATION,
                         code, message, now, False)
        return self._save(replace(state, status=RunStatus.FAILED_FATAL,
            current_stage=PipelineStage.STEP_8_EVALUATION, waiting_reason=None,
            errors=state.errors + (error,), updated_at=now))

    def _eligible(self, state: RunState) -> None:
        if any(item.run_id != state.run_id and item.status == RunStatus.RUNNING
               for item in self.store.discover()):
            raise EvaluationError("ACTIVE_RUN_CONFLICT", "another run is active")
        if (state.status != RunStatus.PAUSED
                or state.current_stage != PipelineStage.STEP_8_EVALUATION
                or state.waiting_reason != "EVALUATION_NOT_INTEGRATED"
                or state.stage(PipelineStage.STEP_7_REEXPLOIT).status != StageStatus.SUCCEEDED):
            raise EvaluationError("INVALID_RUN_STATE", "run is not at the Step 8 boundary")

    @staticmethod
    def _load(state: RunState, kind: ArtifactKind, schema: str) -> tuple[ArtifactReference, Mapping[str, Any]]:
        ref = state.artifact(kind)
        if ref is None:
            raise EvaluationError("EVALUATION_INPUT_INTEGRITY_ERROR", f"missing {kind.value}")
        try:
            path = Path(ref.path)
            if not path.is_file() or _sha(path) != ref.sha256 or ref.schema != schema:
                raise ValueError("path, SHA-256, or schema reference mismatch")
            value = json.loads(path.read_bytes())
            if not isinstance(value, Mapping) or value.get("schema") != schema:
                raise ValueError("artifact schema mismatch")
            return ref, value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise EvaluationError("EVALUATION_INPUT_INTEGRITY_ERROR",
                                  f"{kind.value}: {exc}") from exc

    def run(self, run_id: str) -> RunState:
        state = self.store.load(run_id)
        self._eligible(state)
        try:
            top_ref, top = self._load(state, ArtifactKind.TOP30_BEFORE,
                                      "kalama.prioritization/v1")
            attack_ref, attack = self._load(state, ArtifactKind.ATTACK_BEFORE,
                                            ATTACK_RESULT_SCHEMA)
            remediation_ref, remediation = self._load(state, ArtifactKind.REMEDIATION_RESULT,
                                                       REMEDIATION_RESULT_SCHEMA)
            # Scoped evaluation reuses already-committed Step 6 artifacts.
            # It never reruns scans; it only reinterprets them per PatchAction.
            scan_ref, scan_result = self._load(state, ArtifactKind.REMEDIATION_SCAN_RESULT,
                                               REMEDIATION_SCAN_RESULT_SCHEMA)
            plan_ref, patch_plan = self._load(state, ArtifactKind.PATCH_PLAN,
                                              PATCH_PLAN_SCHEMA)
            meta = top.get("artifact") or {}
            if (meta.get("run_id") != run_id
                    or (attack.get("artifact") or {}).get("run_id") != run_id
                    or remediation.get("run_id") != run_id
                    or scan_result.get("run_id") != run_id):
                raise ValueError("run identity mismatch")
            remediation_inputs = remediation.get("inputs") or {}
            if remediation_inputs.get("attack_before", {}).get("sha256") != attack_ref.sha256:
                raise ValueError("REMEDIATION_RESULT attack lineage mismatch")
            records = build_evaluation_records(top, attack, remediation)
            records = enrich_records_with_scoped_evidence(
                records, remediation, scan_result, patch_plan)
            config_ref, config = self._load(state, ArtifactKind.EXPLOIT_CONFIG_BEFORE,
                                             EXPLOIT_CONFIG_SET_SCHEMA)
        except EvaluationError as exc:
            return self._fail(run_id, exc.code, str(exc))
        except Exception as exc:
            return self._fail(run_id, "EVALUATION_EVIDENCE_INCONSISTENT", str(exc))

        now = self._now()
        state = state.with_stage(PipelineStage.STEP_8_EVALUATION, StageStatus.RUNNING, now)
        state = self._save(replace(state, status=RunStatus.RUNNING,
                                   waiting_reason=None, updated_at=now))
        dataset = {"schema": EVALUATION_DATASET_SCHEMA, "run_id": run_id,
            "created_at": self._now(), "evaluation_universe": {
                "scope": TOP_N_ONLY, "candidate_universe_available": False,
                "candidate_universe_total": None,
                "predicted_negatives_empirically_evaluated": False},
            "prediction": {"definition": "SELECTED_TOP_N",
                "top_n_requested": meta.get("top_n_requested"),
                "top_n_returned": meta.get("top_n_returned"),
                "score_model": (top.get("score_model") or {}).get("id")},
            "inputs": {"top30_before": top_ref.to_dict(),
                       "attack_before": attack_ref.to_dict(),
                       "remediation_result": remediation_ref.to_dict(),
                       "remediation_scan_result": scan_ref.to_dict(),
                       "patch_plan": plan_ref.to_dict()},
            "records": records}
        date = state.created_at[:10]
        dataset_path = self.store.output_root / "evaluation" / f"evaluation_dataset_{date}_{run_id}.json"
        try:
            dataset_sha = write_evaluation_dataset(dataset_path, dataset)
            if _sha(dataset_path) != dataset_sha or json.loads(dataset_path.read_bytes()) != dataset:
                raise ArtifactWriteError("evaluation dataset verification failed")
        except Exception as exc:
            return self._fail(run_id, "EVALUATION_DATASET_WRITE_FAILED", str(exc))
        now = self._now()
        dataset_ref = ArtifactReference(ArtifactKind.EVALUATION_DATASET,
            str(dataset_path.resolve()), dataset_sha, EVALUATION_DATASET_SCHEMA,
            dataset["created_at"], PipelineStage.STEP_8_EVALUATION,
            (("records", len(records)), ("scope", TOP_N_ONLY)))
        state = self._save(self.store.load(run_id).with_artifact(dataset_ref, now))

        # Metrics deliberately reload their only analytical input from the committed artifact.
        try:
            dataset_ref, canonical_dataset = self._load(
                state, ArtifactKind.EVALUATION_DATASET, EVALUATION_DATASET_SCHEMA)
            values = compute_metrics(canonical_dataset)
            metrics = {"schema": EVALUATION_METRICS_SCHEMA, "run_id": run_id,
                       "created_at": self._now(),
                       "input_dataset": dataset_ref.to_dict(), **values}
            metrics_path = self.store.output_root / "evaluation" / f"metrics_{date}_{run_id}.json"
            metrics_sha = write_evaluation_metrics(metrics_path, metrics)
            if _sha(metrics_path) != metrics_sha or json.loads(metrics_path.read_bytes()) != metrics:
                raise ArtifactWriteError("metrics verification failed")
        except Exception as exc:
            return self._fail(run_id, "EVALUATION_METRICS_WRITE_FAILED", str(exc))
        now = self._now()
        metrics_ref = ArtifactReference(ArtifactKind.EVALUATION_METRICS,
            str(metrics_path.resolve()), metrics_sha, EVALUATION_METRICS_SCHEMA,
            metrics["created_at"], PipelineStage.STEP_8_EVALUATION,
            (("precision_available", metrics["prioritization"]["precision"]["available"]),
             ("scope", TOP_N_ONLY)))
        state = self._save(self.store.load(run_id).with_artifact(metrics_ref, now))

        completed_at = self._now()
        try:
            attack_after_ref, attack_after = self._load(state, ArtifactKind.ATTACK_AFTER,
                                                        ATTACK_RESULT_SCHEMA)
            patch_ref = state.artifact(ArtifactKind.PATCH_RESULT)
            scan_ref = state.artifact(ArtifactKind.REMEDIATION_SCAN_RESULT)
            if patch_ref is None or scan_ref is None:
                raise ValueError("run summary prerequisites are absent")
            artifact_index = {item.kind.value: item.to_dict() for item in state.artifacts}
            conflict_count = sum(item["final"].get("evidence_conflict", False)
                                 for item in remediation.get("cves") or ())
            warnings = sorted({notice.code for notice in state.warnings}
                | ({"RECALL_UNAVAILABLE", "F1_UNAVAILABLE"})
                | ({"EVIDENCE_CONFLICT_PRESENT"} if conflict_count else set()))
            stage_statuses = {item.stage.value: (
                "SUCCEEDED" if item.stage == PipelineStage.STEP_8_EVALUATION
                else item.status.value) for item in state.stages}
            summary = {"schema": RUN_SUMMARY_SCHEMA, "run_id": run_id,
                "created_at": state.created_at, "completed_at": completed_at,
                "images": {"source": dict(state.target.image_identity if state.target else {}),
                           "patched": dict(state.patched_image or {})},
                "stages": stage_statuses,
                "prioritization": {"top_n_requested": meta.get("top_n_requested"),
                    "top_n_returned": meta.get("top_n_returned"),
                    "score_model": (top.get("score_model") or {}).get("id")},
                "before_exploit": attack.get("summary") or {},
                "patch": dict(patch_ref.summary),
                "after_scan": dict(scan_ref.summary),
                "after_exploit": attack_after.get("summary") or {},
                "remediation": metrics["remediation"],
                "scoped_remediation": metrics.get("scoped_remediation") or {},
                "metrics": {"precision": metrics["prioritization"]["precision"],
                    "recall": metrics["prioritization"]["recall"],
                    "f1": metrics["prioritization"]["f1"],
                    "coverage": metrics["coverage"]},
                "warnings": warnings, "artifact_index": artifact_index}
            summary_path = self.store.output_root / "evaluation" / f"run_summary_{date}_{run_id}.json"
            summary_sha = write_run_summary(summary_path, summary)
            if _sha(summary_path) != summary_sha or json.loads(summary_path.read_bytes()) != summary:
                raise ArtifactWriteError("run summary verification failed")
        except Exception as exc:
            return self._fail(run_id, "RUN_SUMMARY_WRITE_FAILED", str(exc))
        now = self._now()
        summary_ref = ArtifactReference(ArtifactKind.RUN_SUMMARY, str(summary_path.resolve()),
            summary_sha, RUN_SUMMARY_SCHEMA, completed_at, PipelineStage.STEP_8_EVALUATION,
            (("completed_at", completed_at), ("warnings", len(summary["warnings"]))))
        state = self._save(self.store.load(run_id).with_artifact(summary_ref, now))
        # Feedback is intentionally after every result artifact is committed.
        # Failure here is non-fatal: a completed run remains an auditable run.
        try:
            self._write_validated_knowledge(state, top, attack, config, remediation,
                                            patch_plan, plan_ref)
        except Exception as exc:
            feedback_now = self._now()
            state = replace(state, warnings=state.warnings + (RunNotice(
                "KNOWLEDGE_FEEDBACK_FAILED",
                f"knowledge feedback failed for run {run_id}: {type(exc).__name__}: {str(exc)[:500]}",
                feedback_now),), updated_at=feedback_now)
        state = state.with_stage(PipelineStage.STEP_8_EVALUATION, StageStatus.SUCCEEDED, now)
        return self._save(replace(state, status=RunStatus.COMPLETED,
                                  current_stage=PipelineStage.STEP_8_EVALUATION,
                                  waiting_reason=None, updated_at=now))
