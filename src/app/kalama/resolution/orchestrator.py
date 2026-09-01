"""Canonical Step 4 continuation through a persisted Step 2/3 run state."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence

import yaml

from resolver_core import DiscoveryBackend

from ..state.models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, IntegrationFailureCode,
    PipelineStage, RunError, RunNotice, RunState, RunStatus, StageStatus,
)
from ..state.store import StateStore, StateStoreError, utc_text
from .artifacts import (
    ATTACK_FORM_SCHEMA, LLM_GUIDANCE_SCHEMA, RESOLVER_SCHEMA, ArtifactWriteError, attack_form,
    resolver_artifact, write_attack_form, write_llm_guidance, write_resolver_artifact,
)
from .models import RankedCVEInput, ResolverCVEStatus, Step4Analysis
from .resolver_stage import analyze_cves, parse_ranked_inputs, target_facts_from_state


class Step4Processor(Protocol):
    def __call__(self, inputs: Sequence[RankedCVEInput], target_facts: object) -> Step4Analysis: ...


class Step4OrchestrationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def production_step4_processor(backend: DiscoveryBackend, *, msf_container: str) -> Step4Processor:
    def execute(inputs: Sequence[RankedCVEInput], target_facts: object) -> Step4Analysis:
        return analyze_cves(inputs, target_facts, backend, msf_container)  # type: ignore[arg-type]
    return execute


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ResolverOrchestrator:
    def __init__(self, store: StateStore, processor: Step4Processor, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 guidance_service=None):
        self.store, self.processor, self.clock = store, processor, clock
        self.guidance_service = guidance_service

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _fail(self, run_id: str, code: str, message: str,
              details: Mapping[str, object] | None = None) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.FAILED, timestamp)
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_4_RESOLVER,
                         code, message, timestamp, False,
                         tuple(sorted((details or {}).items())))
        state = replace(state, status=RunStatus.FAILED_FATAL,
                        current_stage=PipelineStage.STEP_4_RESOLVER,
                        waiting_reason=None, errors=state.errors + (error,),
                        updated_at=timestamp)
        return self._save(state)

    def _verify_top30(self, state: RunState) -> tuple[Mapping[str, object], tuple[RankedCVEInput, ...]]:
        reference = state.artifact(ArtifactKind.TOP30_BEFORE)
        if reference is None:
            raise Step4OrchestrationError(IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                                          "canonical state has no TOP30_BEFORE artifact")
        path = Path(reference.path)
        try:
            if not path.is_file() or _sha256(path) != reference.sha256:
                raise ValueError("file missing or SHA-256 does not match state")
            document = json.loads(path.read_bytes())
            if not isinstance(document, Mapping):
                raise ValueError("artifact is not a JSON object")
            meta = document.get("artifact")
            if (document.get("schema") != "kalama.prioritization/v1"
                    or reference.schema != "kalama.prioritization/v1"
                    or not isinstance(meta, Mapping)
                    or meta.get("run_id") != state.run_id or meta.get("phase") != "before"):
                raise ValueError("schema, run_id, or phase is incompatible")
            inputs = parse_ranked_inputs(document)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise Step4OrchestrationError(
                IntegrationFailureCode.ARTIFACT_INTEGRITY_ERROR.value,
                f"Top 30 artifact integrity verification failed: {exc}") from exc
        return document, inputs

    def _assert_startable(self, state: RunState) -> None:
        active = [x.run_id for x in self.store.discover()
                  if x.run_id != state.run_id and x.status == RunStatus.RUNNING]
        if active:
            raise Step4OrchestrationError(IntegrationFailureCode.ACTIVE_RUN_CONFLICT.value,
                                          f"another run is active: {', '.join(sorted(active))}")
        if (state.current_stage != PipelineStage.STEP_4_RESOLVER
                or state.status != RunStatus.PAUSED
                or state.stage(PipelineStage.STEP_2_TARGET_SCAN).status != StageStatus.SUCCEEDED
                or state.stage(PipelineStage.STEP_3_PRIORITIZATION).status != StageStatus.SUCCEEDED
                or state.stage(PipelineStage.STEP_4_RESOLVER).status != StageStatus.NOT_STARTED
                or state.target is None or state.target.facts is None):
            raise Step4OrchestrationError("INVALID_RUN_STATE",
                                          "run is not at the Step 4 continuation boundary")

    def run(self, run_id: str) -> RunState:
        try:
            state = self.store.load(run_id)
            self._assert_startable(state)
        except StateStoreError as exc:
            raise Step4OrchestrationError(exc.code, str(exc)) from exc

        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.RUNNING, timestamp)
        state = replace(state, status=RunStatus.RUNNING, waiting_reason=None, updated_at=timestamp)
        state = self._save(state)

        try:
            _, inputs = self._verify_top30(state)
        except Step4OrchestrationError as exc:
            return self._fail(run_id, exc.code, str(exc))

        reference = state.artifact(ArtifactKind.TOP30_BEFORE)
        assert reference is not None and state.target is not None and state.target.facts is not None
        target_facts = target_facts_from_state(run_id, state.target.facts)
        try:
            analysis = self.processor(inputs, target_facts)
        except Exception as exc:
            return self._fail(run_id, IntegrationFailureCode.RESOLVER_BACKEND_ERROR.value,
                              f"Resolver processor raised {type(exc).__name__}: {exc}")
        if (len(analysis.cves) != len(inputs)
                or [(x.input.rank, x.input.cve_id) for x in analysis.cves]
                != [(x.rank, x.cve_id) for x in inputs]):
            return self._fail(run_id, "STEP_RESULT_INVALID",
                              "Resolver result does not correspond exactly to ranked Top 30 inputs")

        guidance_outcomes = ()
        if self.guidance_service is not None:
            guidance_outcomes = self.guidance_service.guide(
                run_id, analysis, state.target.facts)
        guidance_by_cve = {x.cve_id: x.to_dict() for x in guidance_outcomes}

        date_text = state.created_at[:10]
        resolver_path = (self.store.output_root / "resolver" /
                         f"resolver_{date_text}_{run_id}.json")
        artifact = resolver_artifact(analysis, run_id=run_id, created_at=self._now(),
                                     top30_path=reference.path, top30_sha256=reference.sha256)
        try:
            resolver_sha = write_resolver_artifact(resolver_path, artifact)
            disk = json.loads(resolver_path.read_bytes())
            if disk != artifact or _sha256(resolver_path) != resolver_sha:
                raise ArtifactWriteError("published Resolver artifact failed verification")
        except (ArtifactWriteError, OSError, json.JSONDecodeError) as exc:
            return self._fail(run_id, IntegrationFailureCode.RESOLVER_ARTIFACT_WRITE_FAILED.value,
                              f"Resolver artifact publication failed: {exc}")

        guidance_path = None
        guidance_sha = None
        if guidance_outcomes:
            guidance_path = (self.store.output_root / "resolver" / "guidance" /
                             f"llm_guidance_{date_text}_{run_id}.json")
            guidance_artifact = {
                "schema": LLM_GUIDANCE_SCHEMA,
                "artifact": {"run_id": run_id, "phase": "before", "created_at": self._now(),
                             "resolver_sha256": resolver_sha},
                "cves": [x.to_dict() for x in guidance_outcomes]}
            try:
                guidance_sha = write_llm_guidance(guidance_path, guidance_artifact)
            except (ArtifactWriteError, OSError):
                # Guidance is optional. Resolver and the normal Human form remain usable.
                guidance_path = guidance_sha = None
                guidance_by_cve = {}

        timestamp = self._now()
        state = self.store.load(run_id)
        state = state.with_artifact(ArtifactReference(
            ArtifactKind.RESOLVER_BEFORE, str(resolver_path.resolve()), resolver_sha,
            RESOLVER_SCHEMA, artifact["artifact"]["created_at"],
            PipelineStage.STEP_4_RESOLVER, tuple(sorted(analysis.summary().items()))), timestamp)
        if guidance_path is not None and guidance_sha is not None:
            state = state.with_artifact(ArtifactReference(
                ArtifactKind.LLM_GUIDANCE, str(guidance_path.resolve()), guidance_sha,
                LLM_GUIDANCE_SCHEMA, timestamp, PipelineStage.STEP_4_RESOLVER,
                (("cve_count", len(guidance_outcomes)),
                 ("accepted_count", sum(bool(x.accepted) for x in guidance_outcomes)))), timestamp)
        state = replace(state, cves=tuple(CVEStateSummary(
            x.input.cve_id, x.input.rank, x.status.value) for x in analysis.cves),
            updated_at=timestamp)
        state = self._save(state)

        if analysis.needs_form:
            form_path = self.store.output_root / "resolver" / "forms" / f"attack_form_{run_id}_r1.yaml"
            form = attack_form(analysis, run_id=run_id, revision=1,
                               base_resolver_sha256=resolver_sha,
                               guidance_by_cve=guidance_by_cve)
            try:
                form_sha = write_attack_form(form_path, form)
                disk_form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
                if disk_form != form or _sha256(form_path) != form_sha:
                    raise ArtifactWriteError("published Attack Form failed verification")
            except (ArtifactWriteError, OSError, yaml.YAMLError) as exc:
                return self._fail(run_id, IntegrationFailureCode.ATTACK_FORM_WRITE_FAILED.value,
                                  f"Attack Form publication failed: {exc}")
            timestamp = self._now()
            state = self.store.load(run_id).with_artifact(ArtifactReference(
                ArtifactKind.ATTACK_FORM, str(form_path.resolve()), form_sha,
                ATTACK_FORM_SCHEMA, timestamp, PipelineStage.STEP_4_RESOLVER,
                (("base_config_sha256", None), ("base_resolver_sha256", resolver_sha),
                 ("cve_count", sum(x.status == ResolverCVEStatus.WAITING_FOR_USER_INPUT
                                   for x in analysis.cves)), ("revision", 1))), timestamp)
            state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.WAITING, timestamp)
            notice = RunNotice(IntegrationFailureCode.ATTACK_FORM_REQUIRED.value,
                               "human confirmation is required in the Attack Form", timestamp)
            state = replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                            waiting_reason="ATTACK_FORM",
                            warnings=state.warnings + (notice,), updated_at=timestamp)
            return self._save(state)

        counts = analysis.summary()
        systemic = (counts[ResolverCVEStatus.ENVIRONMENT_ERROR.value.lower()]
                    + counts[ResolverCVEStatus.UNRESOLVED_CONFIG.value.lower()])
        if systemic == len(analysis.cves) and analysis.cves:
            return self._fail(run_id, IntegrationFailureCode.RESOLVER_BACKEND_ERROR.value,
                              "Resolver infrastructure/configuration failed for every selected CVE")
        timestamp = self._now()
        state = self.store.load(run_id).with_stage(
            PipelineStage.STEP_4_RESOLVER, StageStatus.SUCCEEDED, timestamp)
        no_candidate = not analysis.cves or all(
            x.status == ResolverCVEStatus.NO_MSF_MODULE for x in analysis.cves)
        code = (IntegrationFailureCode.NO_EXECUTABLE_MSF_CANDIDATE.value if no_candidate
                else IntegrationFailureCode.BEFORE_EXPLOIT_NOT_INTEGRATED.value)
        message = ("no executable Metasploit candidate was resolved" if no_candidate
                   else "before-patch exploit execution is not integrated yet")
        state = replace(state, status=RunStatus.PAUSED, waiting_reason=code,
                        warnings=state.warnings + (RunNotice(code, message, timestamp),),
                        updated_at=timestamp)
        return self._save(state)
