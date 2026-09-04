"""Read-only Step 8 evidence evaluation and canonical run completion."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from ..resolution.artifacts import (
    ATTACK_RESULT_SCHEMA, EVALUATION_DATASET_SCHEMA, EVALUATION_METRICS_SCHEMA,
    REMEDIATION_RESULT_SCHEMA, RUN_SUMMARY_SCHEMA, ArtifactWriteError,
    write_evaluation_dataset, write_evaluation_metrics, write_run_summary,
)
from ..state.models import (
    ArtifactKind, ArtifactReference, PipelineStage, RunError, RunState, RunStatus,
    StageStatus,
)
from ..state.store import StateStore, utc_text
from .metrics import TOP_N_ONLY, build_evaluation_records, compute_metrics


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
            meta = top.get("artifact") or {}
            if (meta.get("run_id") != run_id
                    or (attack.get("artifact") or {}).get("run_id") != run_id
                    or remediation.get("run_id") != run_id):
                raise ValueError("run identity mismatch")
            remediation_inputs = remediation.get("inputs") or {}
            if remediation_inputs.get("attack_before", {}).get("sha256") != attack_ref.sha256:
                raise ValueError("REMEDIATION_RESULT attack lineage mismatch")
            records = build_evaluation_records(top, attack, remediation)
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
                       "remediation_result": remediation_ref.to_dict()},
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
        state = state.with_stage(PipelineStage.STEP_8_EVALUATION, StageStatus.SUCCEEDED, now)
        return self._save(replace(state, status=RunStatus.COMPLETED,
                                  current_stage=PipelineStage.STEP_8_EVALUATION,
                                  waiting_reason=None, updated_at=now))
