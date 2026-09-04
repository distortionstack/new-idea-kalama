"""Attack Form continuation to a canonical before-exploit configuration boundary."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from kalama.resolver.config import validate_exploit_config
from kalama.resolver.models import DiscoveryStatus

from ..state.models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, IntegrationFailureCode,
    PipelineStage, RunError, RunNotice, RunState, RunStatus, StageStatus,
)
from ..state.store import StateStore, StateStoreError, utc_text
from .artifacts import (
    ATTACK_FORM_SCHEMA, EXPLOIT_CONFIG_SET_SCHEMA, RESOLVER_SCHEMA, ArtifactWriteError,
    attack_form, write_attack_form, write_config_set, write_submission_snapshot,
)
from .config_codec import exploit_config_from_dict
from .models import RankedCVEInput, ResolverCVEResult, ResolverCVEStatus, Step4Analysis
from .submission import SubmissionValidationError, apply_human_confirmation


class AttackFormContinuationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _summary(reference: ArtifactReference) -> dict[str, Any]:
    return dict(reference.summary)


class AttackFormOrchestrator:
    def __init__(self, store: StateStore, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 payload_introspector: Callable[[str, str], Any] | None = None):
        self.store, self.clock = store, clock
        self.payload_introspector = payload_introspector

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _input_error(self, run_id: str, code: str, message: str) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_4_RESOLVER,
                         code, message, timestamp, True)
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.WAITING, timestamp)
        state = replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                        current_stage=PipelineStage.STEP_4_RESOLVER,
                        waiting_reason="ATTACK_FORM", errors=state.errors + (error,),
                        updated_at=timestamp)
        return self._save(state)

    def _fatal(self, run_id: str, code: str, message: str) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_4_RESOLVER,
                         code, message, timestamp, False)
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.FAILED, timestamp)
        state = replace(state, status=RunStatus.FAILED_FATAL, waiting_reason=None,
                        errors=state.errors + (error,), updated_at=timestamp)
        return self._save(state)

    def _assert_eligible(self, state: RunState) -> None:
        active = [x.run_id for x in self.store.discover()
                  if x.run_id != state.run_id and x.status == RunStatus.RUNNING]
        if active:
            raise AttackFormContinuationError("ACTIVE_RUN_CONFLICT",
                                              f"another run is active: {', '.join(sorted(active))}")
        if (state.status != RunStatus.WAITING_FOR_USER_INPUT
                or state.current_stage != PipelineStage.STEP_4_RESOLVER
                or state.stage(PipelineStage.STEP_4_RESOLVER).status != StageStatus.WAITING
                or state.waiting_reason != "ATTACK_FORM"):
            raise AttackFormContinuationError("INVALID_RUN_STATE",
                                              "run is not waiting for a Step 4 Attack Form")

    def _verify_json(self, reference: ArtifactReference, schema: str, run_id: str) -> Mapping[str, Any]:
        try:
            path = Path(reference.path)
            if not path.is_file() or _sha(path) != reference.sha256 or reference.schema != schema:
                raise ValueError("file, digest, or reference schema mismatch")
            value = json.loads(path.read_bytes())
            metadata = value.get("artifact") if isinstance(value, Mapping) else None
            if (not isinstance(value, Mapping) or value.get("schema") != schema
                    or not isinstance(metadata, Mapping) or metadata.get("run_id") != run_id
                    or metadata.get("phase") != "before"):
                raise ValueError("artifact identity mismatch")
            return value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise AttackFormContinuationError("CONFIG_BASE_INTEGRITY_ERROR", str(exc)) from exc

    def _verify_form(self, reference: ArtifactReference, run_id: str) -> Mapping[str, Any]:
        try:
            path = Path(reference.path)
            if not path.is_file() or _sha(path) != reference.sha256 or reference.schema != ATTACK_FORM_SCHEMA:
                raise ValueError("form file, digest, or reference schema mismatch")
            value = yaml.safe_load(path.read_bytes())
            if (not isinstance(value, Mapping) or value.get("schema") != ATTACK_FORM_SCHEMA
                    or value.get("run_id") != run_id or value.get("phase") != "before"):
                raise ValueError("form identity mismatch")
            return value
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise AttackFormContinuationError("CONFIG_BASE_INTEGRITY_ERROR", str(exc)) from exc

    def _base_entries(self, state: RunState, resolver: Mapping[str, Any]) -> list[dict[str, Any]]:
        current = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        source = self._verify_json(current, EXPLOIT_CONFIG_SET_SCHEMA, state.run_id) if current else resolver
        raw = source.get("cves")
        if not isinstance(raw, list):
            raise AttackFormContinuationError("CONFIG_BASE_INTEGRITY_ERROR",
                                              "canonical config set has no CVE array")
        return [dict(x) for x in raw if isinstance(x, Mapping)]

    def apply_attack_form(self, run_id: str, submission_path: Path) -> RunState:
        try:
            state = self.store.load(run_id)
        except StateStoreError as exc:
            raise AttackFormContinuationError(exc.code, str(exc)) from exc
        try:
            raw_bytes = submission_path.read_bytes()
        except OSError as exc:
            return self._input_error(run_id, "ATTACK_FORM_INVALID_YAML",
                                     f"cannot read submission: {exc}")
        submitted_sha = hashlib.sha256(raw_bytes).hexdigest()
        evidence = tuple(state.artifact_history) + tuple(state.artifacts)
        if any(x.kind == ArtifactKind.ATTACK_FORM_SUBMISSION and x.sha256 == submitted_sha
               for x in evidence):
            return state
        self._assert_eligible(state)

        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.RUNNING, timestamp)
        state = replace(state, status=RunStatus.RUNNING, waiting_reason=None, updated_at=timestamp)
        state = self._save(state)
        resolver_ref = state.artifact(ArtifactKind.RESOLVER_BEFORE)
        form_ref = state.artifact(ArtifactKind.ATTACK_FORM)
        if resolver_ref is None or form_ref is None:
            return self._fatal(run_id, "CONFIG_BASE_INTEGRITY_ERROR",
                               "state lacks Resolver or current Attack Form evidence")
        try:
            resolver = self._verify_json(resolver_ref, RESOLVER_SCHEMA, run_id)
            generated_form = self._verify_form(form_ref, run_id)
            entries = self._base_entries(state, resolver)
        except AttackFormContinuationError as exc:
            return self._fatal(run_id, exc.code, str(exc))

        try:
            submission = yaml.safe_load(raw_bytes)
        except yaml.YAMLError as exc:
            return self._input_error(run_id, "ATTACK_FORM_INVALID_YAML", str(exc))
        if not isinstance(submission, Mapping):
            return self._input_error(run_id, "ATTACK_FORM_INVALID_YAML",
                                     "submission must be a YAML mapping")
        identity_checks = (("schema", ATTACK_FORM_SCHEMA, "ATTACK_FORM_SCHEMA_MISMATCH"),
                           ("run_id", run_id, "ATTACK_FORM_RUN_MISMATCH"),
                           ("phase", "before", "ATTACK_FORM_PHASE_MISMATCH"))
        for key, expected, code in identity_checks:
            if submission.get(key) != expected:
                return self._input_error(run_id, code, f"submission {key} mismatch")
        current_revision = int(generated_form.get("revision", _summary(form_ref).get("revision", 1)))
        current_config = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        expected_resolver = generated_form.get("base_resolver_sha256")
        expected_config = generated_form.get("base_config_sha256")
        if (submission.get("revision", 1) != current_revision
                or submission.get("base_resolver_sha256") != expected_resolver
                or submission.get("base_config_sha256") != expected_config
                or (expected_resolver is not None and expected_resolver != resolver_ref.sha256)
                or expected_config != (current_config.sha256 if current_config else None)):
            return self._input_error(run_id, "ATTACK_FORM_STALE",
                                     "submission was generated from an older canonical configuration")
        submitted_cves = submission.get("cves")
        if not isinstance(submitted_cves, Mapping):
            return self._input_error(run_id, "ATTACK_FORM_UNKNOWN_FIELD", "cves must be an object")
        generated_cves = generated_form.get("cves")
        if not isinstance(generated_cves, Mapping):
            return self._fatal(run_id, "CONFIG_BASE_INTEGRITY_ERROR", "generated form has invalid CVEs")
        known = {x.get("cve_id"): x for x in entries}
        unknown = set(submitted_cves) - set(known)
        if unknown:
            return self._input_error(run_id, "ATTACK_FORM_UNKNOWN_CVE",
                                     f"unknown CVE(s): {', '.join(sorted(unknown))}")
        not_editable = set(submitted_cves) - set(generated_cves)
        if not_editable:
            return self._input_error(run_id, "ATTACK_FORM_CVE_NOT_EDITABLE",
                                     f"CVE(s) are not editable: {', '.join(sorted(not_editable))}")

        updated_entries = []
        analysis_items = []
        try:
            for raw in entries:
                cve_id, rank = raw.get("cve_id"), raw.get("rank")
                config_raw = raw.get("exploit_config")
                if config_raw is None:
                    updated_entries.append(raw)
                    continue
                config = exploit_config_from_dict(config_raw)
                if cve_id in submitted_cves:
                    human = submitted_cves[cve_id]
                    if not isinstance(human, Mapping):
                        raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD",
                                                        f"{cve_id} must be an object")
                    generated = generated_cves[cve_id]
                    if (human.get("rank", generated.get("rank")) != generated.get("rank")
                            or human.get("guidance", generated.get("guidance")) != generated.get("guidance")
                            or ("candidates" in human.get("module", {})
                                and human["module"]["candidates"] != generated["module"]["candidates"])):
                        raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD",
                                                        f"read-only identity/evidence changed for {cve_id}")
                    applied = apply_human_confirmation(
                        config, human, payload_introspector=self.payload_introspector)
                    config, validation = applied.config, applied.validation
                else:
                    validation = validate_exploit_config(config)
                    config = replace(config, readiness=validation.readiness)
                discovery_status = config.invariant.module_selection.discovery_status
                if discovery_status == DiscoveryStatus.NO_MSF_MODULE:
                    status = ResolverCVEStatus.NO_MSF_MODULE
                elif discovery_status == DiscoveryStatus.ENVIRONMENT_ERROR:
                    status = ResolverCVEStatus.ENVIRONMENT_ERROR
                else:
                    status = (ResolverCVEStatus.READY_TO_EXECUTE if validation.ready
                              else ResolverCVEStatus.WAITING_FOR_USER_INPUT)
                updated = dict(raw)
                updated.update(status=status.value, exploit_config=config.to_dict(),
                               validation=validation.to_dict())
                updated_entries.append(updated)
                analysis_items.append(ResolverCVEResult(
                    RankedCVEInput(int(rank), str(cve_id), tuple()), status,
                    None, config.invariant.module_selection.ranking, config, validation))
        except (KeyError, TypeError, ValueError, SubmissionValidationError) as exc:
            code = exc.code if isinstance(exc, SubmissionValidationError) else "CONFIG_APPLICATION_ERROR"
            return self._input_error(run_id, code, str(exc))

        revision = current_revision
        submission_snapshot = (self.store.output_root / "resolver" / "forms" / "submissions" /
                               f"attack_form_submission_{run_id}_r{revision}.yaml")
        try:
            snapshot_sha = write_submission_snapshot(submission_snapshot, raw_bytes)
        except (OSError, ArtifactWriteError) as exc:
            return self._fatal(run_id, "SUBMISSION_SNAPSHOT_WRITE_FAILED", str(exc))
        previous_sha = current_config.sha256 if current_config else None
        config_artifact = {
            "schema": EXPLOIT_CONFIG_SET_SCHEMA,
            "artifact": {"run_id": run_id, "phase": "before", "revision": revision,
                         "created_at": self._now()},
            "provenance": {"resolver_sha256": resolver_ref.sha256,
                           "form_sha256": form_ref.sha256,
                           "submission_sha256": snapshot_sha,
                           "previous_config_sha256": previous_sha},
            "cves": updated_entries,
        }
        config_path = (self.store.output_root / "resolver" / "config" /
                       f"exploit_config_before_{run_id}_r{revision}.json")
        try:
            config_sha = write_config_set(config_path, config_artifact)
            if _sha(config_path) != config_sha or json.loads(config_path.read_bytes()) != config_artifact:
                raise ArtifactWriteError("confirmed config verification failed")
        except (OSError, json.JSONDecodeError, ArtifactWriteError) as exc:
            return self._fatal(run_id, "CONFIG_ARTIFACT_WRITE_FAILED", str(exc))

        timestamp = self._now()
        state = self.store.load(run_id)
        state = state.with_artifact(ArtifactReference(
            ArtifactKind.ATTACK_FORM_SUBMISSION, str(submission_snapshot.resolve()), snapshot_sha,
            ATTACK_FORM_SCHEMA, timestamp, PipelineStage.STEP_4_RESOLVER,
            (("form_revision", revision),)), timestamp)
        state = state.with_artifact(ArtifactReference(
            ArtifactKind.EXPLOIT_CONFIG_BEFORE, str(config_path.resolve()), config_sha,
            EXPLOIT_CONFIG_SET_SCHEMA, config_artifact["artifact"]["created_at"],
            PipelineStage.STEP_4_RESOLVER, (("revision", revision),)), timestamp)
        state = replace(state, cves=tuple(CVEStateSummary(
            str(x["cve_id"]), int(x["rank"]), str(x["status"])) for x in updated_entries),
            updated_at=timestamp)
        state = self._save(state)

        waiting = [x for x in analysis_items if x.status == ResolverCVEStatus.WAITING_FOR_USER_INPUT]
        if waiting:
            next_revision = revision + 1
            next_analysis = Step4Analysis(tuple(waiting))
            next_form = attack_form(next_analysis, run_id=run_id, revision=next_revision,
                                    base_resolver_sha256=resolver_ref.sha256,
                                    base_config_sha256=config_sha)
            next_path = (self.store.output_root / "resolver" / "forms" /
                         f"attack_form_{run_id}_r{next_revision}.yaml")
            try:
                next_sha = write_attack_form(next_path, next_form)
            except (OSError, ArtifactWriteError) as exc:
                return self._fatal(run_id, "ATTACK_FORM_WRITE_FAILED", str(exc))
            timestamp = self._now()
            state = self.store.load(run_id).with_artifact(ArtifactReference(
                ArtifactKind.ATTACK_FORM, str(next_path.resolve()), next_sha, ATTACK_FORM_SCHEMA,
                timestamp, PipelineStage.STEP_4_RESOLVER,
                (("base_config_sha256", config_sha),
                 ("base_resolver_sha256", resolver_ref.sha256),
                 ("cve_count", len(waiting)), ("revision", next_revision))), timestamp)
            state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.WAITING, timestamp)
            state = replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                            waiting_reason="ATTACK_FORM", updated_at=timestamp)
            return self._save(state)

        timestamp = self._now()
        state = self.store.load(run_id).with_stage(
            PipelineStage.STEP_4_RESOLVER, StageStatus.SUCCEEDED, timestamp)
        ready = any(x.get("status") == ResolverCVEStatus.READY_TO_EXECUTE.value
                    for x in updated_entries)
        reason = (IntegrationFailureCode.BEFORE_EXPLOIT_NOT_INTEGRATED.value if ready
                  else IntegrationFailureCode.NO_EXECUTABLE_MSF_CANDIDATE.value)
        state = replace(state, status=RunStatus.PAUSED, waiting_reason=reason,
                        warnings=state.warnings + (RunNotice(reason,
                            "canonical configuration reached the before-exploit boundary"
                            if ready else "no executable Metasploit configuration remains",
                            timestamp),), updated_at=timestamp)
        return self._save(state)


def apply_attack_form(store: StateStore, run_id: str, submission_path: Path, *,
                      clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> RunState:
    return AttackFormOrchestrator(store, clock=clock).apply_attack_form(run_id, submission_path)
