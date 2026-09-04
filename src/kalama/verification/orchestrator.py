"""Canonical patched-image after scan and scanner-level remediation verification."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from ..prioritizer.trivy_parser import TrivyArtifactError, parse_trivy_report
from ..remediation.codec import patch_plan_from_artifact
from ..resolution.artifacts import (
    PATCH_PLAN_SCHEMA, PATCH_RESULT_SCHEMA, REMEDIATION_SCAN_RESULT_SCHEMA,
    ArtifactWriteError, write_remediation_scan_result,
)
from ..state.models import (
    ArtifactKind, ArtifactReference, CVEStateSummary, PipelineStage, RunError,
    RunNotice, RunState, RunStatus, StageStatus,
)
from ..state.store import StateStore, utc_text
from ..target.models import ImageIdentity, ImageSourceKind, TrivyArtifact
from ..target.victim_manager import CommandRunner, Step2OperationError
from ..target.trivy_scanner import scan_image
from .comparison import compare_remediation_targets


class AfterScanner(Protocol):
    def __call__(self, image: ImageIdentity, output_path: Path) -> TrivyArtifact: ...


class ImageInspector(Protocol):
    def __call__(self, immutable_subject: str) -> Mapping[str, Any]: ...


def docker_image_inspector(runner: CommandRunner) -> ImageInspector:
    def inspect(subject: str) -> Mapping[str, Any]:
        result = runner.run(("docker", "image", "inspect", subject))
        if result.exit_code != 0:
            raise RuntimeError("patched image inspect failed")
        value = json.loads(result.stdout)
        if not isinstance(value, list) or not value or not isinstance(value[0], Mapping):
            raise RuntimeError("patched image inspect returned invalid JSON")
        data = value[0]
        digests = tuple(sorted(x for x in data.get("RepoDigests", []) if isinstance(x, str)))
        return {"image_id": data.get("Id"), "repo_digests": digests}
    return inspect


def production_after_scanner(runner: CommandRunner, *, timeout: float | None = None) -> AfterScanner:
    """Reuse the Step 2 command, validation, fsync, and atomic publication path."""
    return lambda image, output_path: scan_image(image, output_path, runner, timeout=timeout)


def _db_provenance(artifact: Mapping[str, Any]) -> Mapping[str, Any] | None:
    metadata = artifact.get("Metadata")
    if isinstance(metadata, Mapping):
        for key in ("DB", "VulnerabilityDB", "VulnerabilityDatabase"):
            value = metadata.get(key)
            if isinstance(value, Mapping):
                return dict(value)
    trivy = artifact.get("Trivy")
    if isinstance(trivy, Mapping):
        for key in ("DB", "VulnerabilityDB"):
            value = trivy.get(key)
            if isinstance(value, Mapping):
                return dict(value)
    return None


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AfterScanError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AfterScanOrchestrator:
    def __init__(self, store: StateStore, scanner: AfterScanner, inspector: ImageInspector,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.store, self.scanner, self.inspector, self.clock = store, scanner, inspector, clock

    def _now(self) -> str:
        return utc_text(self.clock())

    def _save(self, state: RunState) -> RunState:
        self.store.save(state)
        return self.store.load(state.run_id)

    def _fail(self, run_id: str, code: str, message: str) -> RunState:
        state, now = self.store.load(run_id), self._now()
        state = state.with_stage(PipelineStage.STEP_6_AFTER_SCAN, StageStatus.FAILED, now)
        error = RunError(f"E{len(state.errors) + 1:04d}", PipelineStage.STEP_6_AFTER_SCAN,
                         code, message, now, False)
        return self._save(replace(state, status=RunStatus.FAILED_FATAL,
                                  current_stage=PipelineStage.STEP_6_AFTER_SCAN,
                                  waiting_reason=None, errors=state.errors + (error,), updated_at=now))

    def _eligible(self, state: RunState) -> None:
        if any(item.run_id != state.run_id and item.status == RunStatus.RUNNING
               for item in self.store.discover()):
            raise AfterScanError("ACTIVE_RUN_CONFLICT", "another run is active")
        if (state.status != RunStatus.PAUSED
                or state.current_stage != PipelineStage.STEP_6_AFTER_SCAN
                or state.waiting_reason != "AFTER_SCAN_NOT_INTEGRATED"
                or state.stage(PipelineStage.STEP_5_PATCH_EXECUTION).status != StageStatus.SUCCEEDED):
            raise AfterScanError("INVALID_RUN_STATE", "run is not at the Step 6 boundary")
        if state.patched_image is None or state.after_target is None:
            raise AfterScanError("NO_AFTER_TARGET", "patched image and after target are required")

    @staticmethod
    def _load(reference: ArtifactReference | None, schema: str | int,
              code: str) -> tuple[ArtifactReference, Mapping[str, Any]]:
        if reference is None:
            raise AfterScanError(code, "required canonical artifact is absent")
        try:
            path = Path(reference.path)
            if not path.is_file() or _sha(path) != reference.sha256 or reference.schema != schema:
                raise ValueError("path, SHA-256, or reference schema mismatch")
            value = json.loads(path.read_bytes())
            if not isinstance(value, Mapping):
                raise ValueError("artifact must be an object")
            actual = value.get("SchemaVersion") if isinstance(schema, int) else value.get("schema")
            if actual != schema:
                raise ValueError("artifact schema mismatch")
            return reference, value
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise AfterScanError(code, str(exc)) from exc

    @staticmethod
    def _identity(state: RunState, patch_result: Mapping[str, Any]) -> ImageIdentity:
        patched = dict(state.patched_image or {})
        after_image = dict(state.after_target.image_identity if state.after_target else {})
        result_image = dict(patch_result.get("patched_image") or {})
        if result_image.get("image_id") != patched.get("image_id"):
            raise AfterScanError("PATCH_RESULT_INTEGRITY_ERROR", "Patch Result patched image differs from state")
        if after_image.get("image_id") != patched.get("image_id"):
            raise AfterScanError("AFTER_TARGET_IMAGE_MISMATCH", "after target does not use patched image")
        before_id = (state.target.image_identity.get("image_id") if state.target else None)
        if before_id and before_id == patched.get("image_id"):
            raise AfterScanError("PATCHED_IMAGE_IDENTITY_MISMATCH",
                                 "patched image equals the canonical before image")
        result_after = dict(patch_result.get("after_target") or {})
        result_after_image = dict(result_after.get("image_identity") or {})
        result_after_facts = dict(result_after.get("facts") or {})
        state_after_facts = dict(state.after_target.facts or {}) if state.after_target else {}
        if (result_after_image.get("image_id") != after_image.get("image_id")
                or any(result_after_facts.get(key) != state_after_facts.get(key)
                       for key in ("container_name", "container_id", "network", "ip_address"))):
            raise AfterScanError("PATCH_RESULT_INTEGRITY_ERROR",
                                 "Patch Result after target differs from state")
        digest = patched.get("selected_digest")
        image_id = patched.get("image_id")
        if not image_id:
            raise AfterScanError("PATCHED_IMAGE_IDENTITY_MISMATCH", "patched image ID is absent")
        reference = str(patched.get("reference") or patched.get("requested_reference") or image_id)
        return ImageIdentity(reference, str(image_id), tuple(patched.get("repo_digests") or ()),
                             str(digest) if digest else None,
                             tuple(patched.get("repo_tags") or ()), patched.get("platform"),
                             ImageSourceKind.LOCAL_BUILT)

    def run(self, run_id: str) -> RunState:
        state = self.store.load(run_id)
        self._eligible(state)
        try:
            patch_ref, patch_result = self._load(
                state.artifact(ArtifactKind.PATCH_RESULT), PATCH_RESULT_SCHEMA,
                "PATCH_RESULT_INTEGRITY_ERROR")
            plan_ref, plan_artifact = self._load(
                state.artifact(ArtifactKind.PATCH_PLAN), PATCH_PLAN_SCHEMA,
                "PATCH_RESULT_INTEGRITY_ERROR")
            before_ref, before_artifact = self._load(
                state.artifact(ArtifactKind.TRIVY_BEFORE), 2, "ARTIFACT_INTEGRITY_ERROR")
            if (patch_result.get("run_id") != run_id
                    or patch_result.get("remediation_verified") is not False
                    or plan_artifact.get("run_id") != run_id):
                raise AfterScanError("PATCH_RESULT_INTEGRITY_ERROR", "run or verification identity mismatch")
            patch_plan_input = dict(patch_result.get("plan") or {})
            plan_trivy_input = dict((plan_artifact.get("inputs") or {}).get("trivy_before") or {})
            if (patch_plan_input.get("sha256") != plan_ref.sha256
                    or patch_plan_input.get("path") != plan_ref.path
                    or plan_trivy_input.get("sha256") != before_ref.sha256
                    or plan_trivy_input.get("path") != before_ref.path):
                raise AfterScanError("PATCH_RESULT_INTEGRITY_ERROR",
                                     "Patch Result/Plan input lineage differs from state")
            image = self._identity(state, patch_result)
            current = self.inspector(image.canonical_identity)
            if (current.get("image_id") != image.image_id
                    or (image.selected_digest
                        and image.selected_digest not in tuple(current.get("repo_digests") or ()))):
                raise AfterScanError("PATCHED_IMAGE_IDENTITY_MISMATCH",
                                     "current Docker identity differs from canonical state")
        except AfterScanError as exc:
            if exc.code in {"ACTIVE_RUN_CONFLICT", "INVALID_RUN_STATE"}:
                raise
            return self._fail(run_id, exc.code, str(exc))
        except Exception as exc:
            return self._fail(run_id, "PATCHED_IMAGE_IDENTITY_MISMATCH", str(exc))

        now = self._now()
        state = state.with_stage(PipelineStage.STEP_6_AFTER_SCAN, StageStatus.RUNNING, now)
        state = self._save(replace(state, status=RunStatus.RUNNING,
                                   waiting_reason=None, updated_at=now))
        after_path = (self.store.output_root / "trivy" / "after" /
                      f"scan_{state.created_at[:10]}_{run_id}.json")
        try:
            scan = self.scanner(image, after_path)
            if (Path(scan.artifact_path).resolve() != after_path.resolve()
                    or not after_path.is_file() or _sha(after_path) != scan.artifact_sha256
                    or scan.image_id != image.image_id or scan.scan_subject != image.canonical_identity
                    or scan.schema_version != 2):
                raise ValueError("after scanner result or publication does not match invocation")
            after_artifact = json.loads(after_path.read_bytes())
            parse_after = parse_trivy_report(after_artifact)
        except (OSError, ValueError, json.JSONDecodeError, Step2OperationError,
                TrivyArtifactError) as exc:
            return self._fail(run_id, "TRIVY_AFTER_FAILED", str(exc))
        except Exception as exc:
            return self._fail(run_id, "TRIVY_AFTER_FAILED", str(exc))

        now = self._now()
        after_ref = ArtifactReference(
            ArtifactKind.TRIVY_AFTER, str(after_path.resolve()), scan.artifact_sha256, 2,
            scan.created_at or now, PipelineStage.STEP_6_AFTER_SCAN,
            (("image_id", image.image_id), ("scan_subject", image.canonical_identity),
             ("trivy_version", scan.trivy_version)))
        state = self._save(self.store.load(run_id).with_artifact(after_ref, now))
        try:
            parsed_before = parse_trivy_report(before_artifact)
            plan = patch_plan_from_artifact(plan_artifact)
            intended = {cve for action in plan.actions for cve in action.target_cves}
            incidental = {cve for action in plan.actions for cve in action.incidental_cves}
            action_results = {}
            for action in patch_result.get("actions") or ():
                if isinstance(action, Mapping):
                    for cve in action.get("target_cves") or ():
                        action_results[str(cve)] = str(action.get("result"))
            comparison = compare_remediation_targets(
                intended, incidental, parsed_before, parse_after,
                action_results=action_results)
            before_version = parsed_before.trivy_version
            after_version = parse_after.trivy_version or scan.trivy_version
            warnings = []
            if before_version != after_version:
                warnings.append("TRIVY_VERSION_CHANGED")
            before_db = _db_provenance(before_artifact)
            after_db = _db_provenance(after_artifact)
            if not before_db or not after_db:
                warnings.append("DB_PROVENANCE_UNAVAILABLE")
            result = {"schema": REMEDIATION_SCAN_RESULT_SCHEMA, "run_id": run_id,
                      "created_at": self._now(),
                      "inputs": {"trivy_before": before_ref.to_dict(),
                                 "trivy_after": after_ref.to_dict(),
                                 "patch_plan": plan_ref.to_dict(),
                                 "patch_result": patch_ref.to_dict()},
                      "images": {"before": dict(state.target.image_identity if state.target else {}),
                                 "patched": dict(state.patched_image or {})},
                      "scanner_context": {"before_trivy_version": before_version,
                                          "after_trivy_version": after_version,
                                          "before_created_at": parsed_before.created_at,
                                          "after_created_at": parse_after.created_at or scan.created_at,
                                          "before_db_metadata": before_db,
                                          "after_db_metadata": after_db},
                      **comparison, "warnings": warnings,
                      "empirical_remediation_verified": False}
            verification_path = (self.store.output_root / "trivy" / "after" /
                                 f"verification_{state.created_at[:10]}_{run_id}.json")
            result_sha = write_remediation_scan_result(verification_path, result)
            if _sha(verification_path) != result_sha or json.loads(
                    verification_path.read_bytes()) != result:
                raise ArtifactWriteError("remediation scan result verification failed")
        except (OSError, ValueError, TrivyArtifactError, ArtifactWriteError) as exc:
            return self._fail(run_id, "REMEDIATION_SCAN_RESULT_WRITE_FAILED", str(exc))

        now = self._now()
        result_ref = ArtifactReference(
            ArtifactKind.REMEDIATION_SCAN_RESULT, str(verification_path.resolve()), result_sha,
            REMEDIATION_SCAN_RESULT_SCHEMA, result["created_at"], PipelineStage.STEP_6_AFTER_SCAN,
            tuple(sorted(result["summary"].items())))
        state = self.store.load(run_id).with_artifact(result_ref, now)
        by_cve = {item["cve_id"]: item for item in result["intended_targets"]}
        summaries = []
        for existing in state.cves:
            evidence = by_cve.get(existing.cve_id)
            summaries.append(replace(existing,
                patch_action_status=(evidence or {}).get("patch_action_status")
                                    or existing.patch_action_status,
                after_scan_status=(evidence or {}).get("scanner_status")
                                  or existing.after_scan_status))
        notices = tuple(RunNotice(code, code.replace("_", " ").lower(), now)
                        for code in result["warnings"])
        state = replace(state, cves=tuple(summaries), warnings=state.warnings + notices,
                        updated_at=now)
        state = state.with_stage(PipelineStage.STEP_6_AFTER_SCAN, StageStatus.SUCCEEDED, now)
        return self._save(replace(state, status=RunStatus.PAUSED,
                                  current_stage=PipelineStage.STEP_7_REEXPLOIT,
                                  waiting_reason="REEXPLOIT_NOT_INTEGRATED", updated_at=now))
