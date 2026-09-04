"""Canonical Step 2 -> Step 3 orchestration through persisted run state."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .prioritizer.enrichment import CVSSProvider, EPSSProvider, KEVProvider
from .prioritizer.models import PrioritizationResult
from .prioritizer.pipeline import prioritize_file
from .state.models import (
    ArtifactKind, ArtifactReference, IntegrationFailureCode, PipelineStage,
    RunError, RunNotice, RunState, RunStatus, StageStatus, TargetState,
)
from .state.store import StateStore, StateStoreError, default_run_id, utc_text
from .target.models import Step2Request, Step2Result


class Step2Executor(Protocol):
    def __call__(self, request: Step2Request) -> Step2Result: ...


@dataclass(frozen=True)
class Step3Invocation:
    input_path: Path
    output_path: Path
    run_id: str
    created_at: str
    epss_data_date: date
    trivy_sha256: str
    state_path: Path
    target_facts: Mapping[str, Any] | None


class Step3Executor(Protocol):
    def __call__(self, invocation: Step3Invocation) -> PrioritizationResult: ...


class OrchestrationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def production_step3_executor(*, epss_provider: EPSSProvider, kev_provider: KEVProvider,
                              cvss_provider: CVSSProvider | None = None) -> Step3Executor:
    def execute(invocation: Step3Invocation) -> PrioritizationResult:
        target_reference = {"source": "canonical_run_state", "path": str(invocation.state_path),
                            "run_id": invocation.run_id}
        return prioritize_file(
            invocation.input_path, invocation.output_path,
            run_id=invocation.run_id, created_at=invocation.created_at,
            epss_data_date=invocation.epss_data_date,
            epss_provider=epss_provider, kev_provider=kev_provider,
            cvss_provider=cvss_provider, phase="before",
            target_facts_reference=target_reference,
        )
    return execute


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(reference: ArtifactReference, *, expected_schema: str | int) -> Mapping[str, Any]:
    path = Path(reference.path)
    try:
        actual = _sha256(path)
        if actual != reference.sha256:
            raise ValueError(f"SHA-256 mismatch: state={reference.sha256}, actual={actual}")
        data = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise OrchestrationError(IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                                 f"artifact integrity verification failed for {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise OrchestrationError(IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                                 f"artifact {path} is not a JSON object")
    actual_schema = data.get("SchemaVersion") if isinstance(expected_schema, int) else data.get("schema")
    if actual_schema != expected_schema:
        raise OrchestrationError(IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                                 f"artifact {path} schema mismatch: {actual_schema!r}")
    return data


class PrioritizationOrchestrator:
    def __init__(self, store: StateStore, step2: Step2Executor, step3: Step3Executor,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 run_id_generator: Callable[[], str] = default_run_id,
                 network: str = "kalama-net"):
        self.store, self.step2, self.step3 = store, step2, step3
        self.clock, self.run_id_generator, self.network = clock, run_id_generator, network

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save_transition(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _fail(self, run_id: str, stage: PipelineStage, code: str, message: str,
              *, retryable: bool = False, details: Mapping[str, Any] | None = None) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        state = state.with_stage(stage, StageStatus.FAILED, timestamp)
        error = RunError(f"E{len(state.errors) + 1:04d}", stage, code, message,
                         timestamp, retryable, tuple(sorted((details or {}).items())))
        state = replace(state, status=RunStatus.FAILED_FATAL, current_stage=stage,
                        errors=state.errors + (error,), updated_at=timestamp)
        return self._save_transition(state)

    def run(self, victim_image: str, *, step2_options: Mapping[str, Any] | None = None) -> RunState:
        try:
            state = self.store.create(victim_image, now=self.clock(),
                                      run_id_generator=self.run_id_generator)
        except StateStoreError as exc:
            raise OrchestrationError(exc.code, str(exc)) from exc
        run_id = state.run_id
        date_text = state.created_at[:10]
        trivy_path = (self.store.output_root / "trivy" / "before" /
                      f"scan_{date_text}_{run_id}.json")
        top30_path = (self.store.output_root / "scoring" / "before" /
                      f"top30_{date_text}_{run_id}.json")

        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_2_TARGET_SCAN, StageStatus.RUNNING, timestamp)
        state = replace(state, status=RunStatus.RUNNING,
                        current_stage=PipelineStage.STEP_2_TARGET_SCAN, updated_at=timestamp)
        state = self._save_transition(state)

        options = dict(step2_options or {})
        for reserved in ("run_id", "image_reference", "output_path", "network", "phase"):
            if reserved in options:
                return self._fail(run_id, PipelineStage.STEP_2_TARGET_SCAN,
                                  IntegrationFailureCode.STEP_RESULT_INVALID.value,
                                  f"step2_options may not override {reserved}")
        request = Step2Request(run_id, victim_image, str(trivy_path), self.network,
                               "before", **options)
        try:
            step2_result = self.step2(request)
        except Exception as exc:
            return self._fail(run_id, PipelineStage.STEP_2_TARGET_SCAN,
                              IntegrationFailureCode.STEP_2_FAILED.value,
                              f"Step 2 executor raised {type(exc).__name__}: {exc}")
        if (not step2_result.success or step2_result.image_identity is None
                or step2_result.trivy_artifact is None):
            failure = step2_result.failure
            return self._fail(
                run_id, PipelineStage.STEP_2_TARGET_SCAN,
                failure.code.value if failure else IntegrationFailureCode.STEP_RESULT_INVALID.value,
                failure.message if failure else "Step 2 returned an incomplete success result",
                retryable=failure.retryable if failure else False,
                details={"exit_code": failure.exit_code, "stderr": failure.stderr,
                         "command": list(failure.command) if failure and failure.command else None}
                if failure else None,
            )
        returned_path = Path(step2_result.trivy_artifact.artifact_path).resolve()
        if returned_path != trivy_path.resolve():
            return self._fail(run_id, PipelineStage.STEP_2_TARGET_SCAN,
                              IntegrationFailureCode.STEP_RESULT_INVALID.value,
                              "Step 2 returned an artifact outside its assigned canonical path")
        trivy_reference = ArtifactReference(
            ArtifactKind.TRIVY_BEFORE, str(returned_path),
            step2_result.trivy_artifact.artifact_sha256,
            step2_result.trivy_artifact.schema_version,
            step2_result.trivy_artifact.created_at,
            PipelineStage.STEP_2_TARGET_SCAN,
            (("scanner", step2_result.trivy_artifact.scanner),
             ("scan_subject", step2_result.trivy_artifact.scan_subject)),
        )
        try:
            verify_artifact(trivy_reference, expected_schema=2)
        except OrchestrationError as exc:
            return self._fail(run_id, PipelineStage.STEP_2_TARGET_SCAN, exc.code, str(exc))

        timestamp = self._now()
        state = self.store.load(run_id)
        state = replace(state, target=TargetState(
            step2_result.image_identity.to_dict(),
            step2_result.target_facts.to_dict() if step2_result.target_facts else None),
            updated_at=timestamp)
        state = state.with_artifact(trivy_reference, timestamp)
        state = state.with_stage(PipelineStage.STEP_2_TARGET_SCAN, StageStatus.SUCCEEDED, timestamp)
        state = self._save_transition(state)

        # The next stage deliberately reloads and consumes only the committed reference.
        timestamp = self._now()
        state = self.store.load(run_id)
        state = state.with_stage(PipelineStage.STEP_3_PRIORITIZATION, StageStatus.RUNNING, timestamp)
        state = replace(state, current_stage=PipelineStage.STEP_3_PRIORITIZATION,
                        status=RunStatus.RUNNING, updated_at=timestamp)
        state = self._save_transition(state)
        committed_trivy = state.artifact(ArtifactKind.TRIVY_BEFORE)
        if committed_trivy is None:
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                              "committed state has no TRIVY_BEFORE reference")
        try:
            verify_artifact(committed_trivy, expected_schema=2)
        except OrchestrationError as exc:
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION, exc.code, str(exc))

        invocation = Step3Invocation(
            Path(committed_trivy.path), top30_path, run_id, timestamp,
            date.fromisoformat(state.epss_data_date), committed_trivy.sha256,
            self.store.path_for(run_id), state.target.facts if state.target else None,
        )
        try:
            step3_result = self.step3(invocation)
        except Exception as exc:
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.STEP_3_FAILED.value,
                              f"Step 3 executor raised {type(exc).__name__}: {exc}")
        if not step3_result.success or step3_result.artifact is None:
            issue = step3_result.issues[-1] if step3_result.issues else None
            return self._fail(
                run_id, PipelineStage.STEP_3_PRIORITIZATION,
                issue.code.value if issue else IntegrationFailureCode.STEP_RESULT_INVALID.value,
                issue.message if issue else "Step 3 returned an incomplete success result",
                retryable=issue.retryable if issue else False,
                details={"provider": issue.provider} if issue and issue.provider else None,
            )
        if not top30_path.is_file():
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.STEP_RESULT_INVALID.value,
                              "Step 3 reported success before publishing its canonical artifact")
        try:
            top_digest = _sha256(top30_path)
            disk_artifact = json.loads(top30_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                              f"published Top30 artifact cannot be validated: {exc}")
        if disk_artifact != step3_result.artifact:
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                              "Step 3 result does not match the published Top30 artifact")
        meta = disk_artifact.get("artifact") if isinstance(disk_artifact, Mapping) else None
        score_model = disk_artifact.get("score_model") if isinstance(disk_artifact, Mapping) else None
        if (disk_artifact.get("schema") != "kalama.prioritization/v1"
                or not isinstance(meta, Mapping) or not isinstance(score_model, Mapping)):
            return self._fail(run_id, PipelineStage.STEP_3_PRIORITIZATION,
                              IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                              "published Top30 artifact has an incompatible schema")
        top_reference = ArtifactReference(
            ArtifactKind.TOP30_BEFORE, str(top30_path.resolve()), top_digest,
            "kalama.prioritization/v1", meta.get("created_at"),
            PipelineStage.STEP_3_PRIORITIZATION,
            (("score_model", score_model.get("id")),
             ("top_n_requested", meta.get("top_n_requested")),
             ("top_n_returned", meta.get("top_n_returned"))),
        )

        timestamp = self._now()
        state = self.store.load(run_id)
        state = state.with_artifact(top_reference, timestamp)
        state = state.with_stage(PipelineStage.STEP_3_PRIORITIZATION, StageStatus.SUCCEEDED, timestamp)
        returned = meta.get("top_n_returned")
        notice_code = (IntegrationFailureCode.NO_RANKABLE_CVES.value if returned == 0
                       else IntegrationFailureCode.NEXT_STAGE_NOT_INTEGRATED.value)
        notice_message = ("prioritization completed with no rankable CVEs" if returned == 0
                          else "Step 4 Resolver is not integrated yet")
        notice = RunNotice(notice_code, notice_message, timestamp)
        state = replace(state, status=RunStatus.PAUSED,
                        current_stage=PipelineStage.STEP_4_RESOLVER,
                        warnings=state.warnings + (notice,), updated_at=timestamp)
        return self._save_transition(state)
