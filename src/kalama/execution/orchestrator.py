"""Before-exploit orchestration from canonical config to immutable attack evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from kalama.resolver.config import validate_exploit_config

from ..resolution.artifacts import (
    ATTACK_RESULT_SCHEMA, EXPLOIT_CONFIG_SET_SCHEMA, ArtifactWriteError, write_attack_result,
)
from ..resolution.config_codec import exploit_config_from_dict
from ..state.models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, IntegrationFailureCode,
    PipelineStage, RunError, RunNotice, RunState, RunStatus, StageStatus,
)
from ..state.store import StateStore, StateStoreError, utc_text
from .executor import (
    EnvironmentValidator, LabCommandExecutor, MetasploitExecutor, build_execution_plan,
    validate_committed_environment,
)
from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, EnvironmentValidation,
    OperationState, OracleVerdict, SessionCollectionStatus, SessionEvidence,
)
from .oracle import classify_oracle
from .attempt import execute_attempt


class BeforeExploitError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BeforeExploitOrchestrator:
    def __init__(self, store: StateStore, environment_validator: EnvironmentValidator,
                 metasploit: MetasploitExecutor, lab_commands: LabCommandExecutor, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 operation_timeout: float = 120.0, command_timeout: float = 30.0,
                 session_timeout: float = 30.0):
        self.store, self.environment_validator = store, environment_validator
        self.metasploit, self.lab_commands = metasploit, lab_commands
        self.clock = clock
        self.operation_timeout, self.command_timeout = operation_timeout, command_timeout
        self.session_timeout = session_timeout

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _fail(self, run_id: str, code: str, message: str) -> RunState:
        state = self.store.load(run_id)
        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_4_BEFORE_EXPLOIT, StageStatus.FAILED, timestamp)
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_4_BEFORE_EXPLOIT,
                         code, message, timestamp, False)
        state = replace(state, status=RunStatus.FAILED_FATAL,
                        current_stage=PipelineStage.STEP_4_BEFORE_EXPLOIT,
                        waiting_reason=None, errors=state.errors + (error,), updated_at=timestamp)
        return self._save(state)

    def _eligible(self, state: RunState) -> None:
        active = [x.run_id for x in self.store.discover()
                  if x.run_id != state.run_id and x.status == RunStatus.RUNNING]
        if active:
            raise BeforeExploitError("ACTIVE_RUN_CONFLICT",
                                     f"another run is active: {', '.join(sorted(active))}")
        if (state.status != RunStatus.PAUSED
                or state.waiting_reason != IntegrationFailureCode.BEFORE_EXPLOIT_NOT_INTEGRATED.value
                or state.current_stage != PipelineStage.STEP_4_RESOLVER
                or state.stage(PipelineStage.STEP_4_RESOLVER).status != StageStatus.SUCCEEDED
                or state.stage(PipelineStage.STEP_4_BEFORE_EXPLOIT).status != StageStatus.NOT_STARTED
                or state.target is None or state.target.facts is None):
            raise BeforeExploitError("INVALID_RUN_STATE", "run is not at the before-exploit boundary")

    def _config_artifact(self, state: RunState) -> tuple[ArtifactReference, Mapping[str, Any]]:
        reference = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        if reference is None:
            raise BeforeExploitError("CONFIG_ARTIFACT_INTEGRITY_ERROR",
                                     "state has no EXPLOIT_CONFIG_BEFORE")
        try:
            path = Path(reference.path)
            if (not path.is_file() or _sha(path) != reference.sha256
                    or reference.schema != EXPLOIT_CONFIG_SET_SCHEMA):
                raise ValueError("file, SHA-256, or schema reference mismatch")
            artifact = json.loads(path.read_bytes())
            meta = artifact.get("artifact") if isinstance(artifact, Mapping) else None
            provenance = artifact.get("provenance") if isinstance(artifact, Mapping) else None
            if (not isinstance(artifact, Mapping)
                    or artifact.get("schema") != EXPLOIT_CONFIG_SET_SCHEMA
                    or not isinstance(meta, Mapping) or meta.get("run_id") != state.run_id
                    or meta.get("phase") != "before" or not isinstance(meta.get("revision"), int)
                    or not isinstance(provenance, Mapping)
                    or not all(isinstance(provenance.get(x), (str, type(None))) for x in (
                        "resolver_sha256", "form_sha256", "submission_sha256",
                        "previous_config_sha256"))
                    or not isinstance(artifact.get("cves"), list)):
                raise ValueError("config artifact identity or lineage is invalid")
            return reference, artifact
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise BeforeExploitError("CONFIG_ARTIFACT_INTEGRITY_ERROR", str(exc)) from exc

    def _attempt(self, run_id: str, rank: int, config, config_ref, revision: int,
                 target_facts: Mapping[str, Any]) -> tuple[dict[str, Any], str, bool]:
        return execute_attempt(
            run_id=run_id, phase="before", rank=rank, config=config,
            config_reference={"path": config_ref.path, "sha256": config_ref.sha256,
                              "revision": revision},
            target_facts=target_facts, environment_validator=self.environment_validator,
            metasploit=self.metasploit, lab_commands=self.lab_commands, now=self._now,
            operation_timeout=self.operation_timeout, command_timeout=self.command_timeout,
            session_timeout=self.session_timeout)

    def run(self, run_id: str) -> RunState:
        try:
            state = self.store.load(run_id)
            self._eligible(state)
            config_ref, artifact = self._config_artifact(state)
        except StateStoreError as exc:
            raise BeforeExploitError(exc.code, str(exc)) from exc
        except BeforeExploitError as exc:
            if exc.code == "ACTIVE_RUN_CONFLICT" or exc.code == "INVALID_RUN_STATE":
                raise
            return self._fail(run_id, exc.code, str(exc))

        timestamp = self._now()
        state = state.with_stage(PipelineStage.STEP_4_BEFORE_EXPLOIT, StageStatus.RUNNING, timestamp)
        state = replace(state, status=RunStatus.RUNNING,
                        current_stage=PipelineStage.STEP_4_BEFORE_EXPLOIT,
                        waiting_reason=None, updated_at=timestamp)
        state = self._save(state)
        entries = sorted(artifact["cves"], key=lambda x: x.get("rank", 10**9))
        revision = artifact["artifact"]["revision"]
        results, summaries = [], []
        backend_available = self.metasploit.backend_available()
        systemic = not backend_available
        target_facts = state.target.facts
        for raw in entries:
            rank, cve_id, status = int(raw["rank"]), str(raw["cve_id"]), str(raw["status"])
            if status != "READY_TO_EXECUTE" or raw.get("exploit_config") is None:
                results.append({"rank": rank, "cve_id": cve_id, "config_status": status,
                                "disposition": status,
                                "attempt": None, "oracle": {"verdict": "NOT_EVALUATED"},
                                "metric_eligibility": {"eligible": False,
                                                       "exclusion_reason": status}})
                summaries.append(CVEStateSummary(cve_id, rank, status))
                continue
            if systemic:
                results.append({"rank": rank, "cve_id": cve_id, "config_status": status,
                                "disposition": "NOT_EXECUTED",
                                "attempt": None, "oracle": {"verdict": "NOT_EVALUATED"},
                                "metric_eligibility": {"eligible": False,
                                                       "exclusion_reason": "MSF_BACKEND_UNAVAILABLE"}})
                summaries.append(CVEStateSummary(cve_id, rank, "NOT_EXECUTED"))
                continue
            try:
                config = exploit_config_from_dict(raw["exploit_config"])
                attempt, disposition, backend_lost = self._attempt(
                    run_id, rank, config, config_ref, revision, target_facts)
                results.append({"rank": rank, "cve_id": cve_id, "config_status": status,
                                "disposition": disposition,
                                "attempt": attempt, "oracle": attempt["oracle"],
                                "metric_eligibility": attempt["metric_eligibility"]})
                summaries.append(CVEStateSummary(cve_id, rank, disposition))
                systemic = systemic or backend_lost
            except Exception as exc:
                results.append({"rank": rank, "cve_id": cve_id, "config_status": status,
                                "disposition": "INCONCLUSIVE",
                                "attempt": None, "oracle": {"verdict": "INCONCLUSIVE"},
                                "metric_eligibility": {"eligible": False,
                                                       "exclusion_reason": "EXECUTION_ERROR"},
                                "issues": [f"{type(exc).__name__}: {exc}"]})
                summaries.append(CVEStateSummary(cve_id, rank, "INCONCLUSIVE"))

        counts = {name: sum(x.resolver_status == name for x in summaries) for name in (
            "EXPLOIT_SUCCEEDED", "EXPLOIT_FAILED", "CHECK_ONLY", "INCONCLUSIVE",
            "NOT_EXECUTED", "NO_MSF_MODULE", "ENVIRONMENT_ERROR")}
        attack = {"schema": ATTACK_RESULT_SCHEMA,
                  "artifact": {"run_id": run_id, "phase": "before",
                               "created_at": self._now(),
                               "input_config": {"path": config_ref.path,
                                                "sha256": config_ref.sha256,
                                                "revision": revision}},
                  "summary": {"selected": len(results), "attempted": sum(
                      x.get("attempt") is not None for x in results),
                      "metric_eligible": sum(x["metric_eligibility"].get("eligible", False)
                                             for x in results), **counts},
                  "cves": results}
        path = self.store.output_root / "msf" / "before" / f"attack_res_{state.created_at[:10]}_{run_id}.json"
        try:
            attack_sha = write_attack_result(path, attack)
            if _sha(path) != attack_sha or json.loads(path.read_bytes()) != attack:
                raise ArtifactWriteError("published attack result failed verification")
        except (OSError, json.JSONDecodeError, ArtifactWriteError) as exc:
            return self._fail(run_id, "ATTACK_ARTIFACT_WRITE_FAILED", str(exc))
        timestamp = self._now()
        state = self.store.load(run_id).with_artifact(ArtifactReference(
            ArtifactKind.ATTACK_BEFORE, str(path.resolve()), attack_sha, ATTACK_RESULT_SCHEMA,
            attack["artifact"]["created_at"], PipelineStage.STEP_4_BEFORE_EXPLOIT,
            tuple(sorted(attack["summary"].items()))), timestamp)
        state = replace(state, cves=tuple(summaries), updated_at=timestamp)
        state = self._save(state)
        if systemic:
            return self._fail(run_id, "MSF_BACKEND_UNAVAILABLE",
                              "Metasploit backend was unavailable during before-exploit execution")
        timestamp = self._now()
        state = self.store.load(run_id).with_stage(
            PipelineStage.STEP_4_BEFORE_EXPLOIT, StageStatus.SUCCEEDED, timestamp)
        notice = RunNotice("PATCH_NOT_INTEGRATED", "Step 5 patching is not integrated yet", timestamp)
        state = replace(state, status=RunStatus.PAUSED, current_stage=PipelineStage.STEP_5_PATCH,
                        waiting_reason="PATCH_NOT_INTEGRATED",
                        warnings=state.warnings + (notice,), updated_at=timestamp)
        return self._save(state)
