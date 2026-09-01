from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.app.kalama.orchestrator import (
    OrchestrationError, PrioritizationOrchestrator,
)
from src.app.kalama.prioritizer.models import (
    FailureCode, PrioritizationResult, StageIssue,
)
from src.app.kalama.state.models import (
    ArtifactKind, PipelineStage, RunStatus, StageStatus,
)
from src.app.kalama.state.store import (
    StateStore, StateStoreError, run_state_from_dict, serialize_run_state,
)
from src.app.kalama.target.models import (
    ImageIdentity, ImageSourceKind, ObservationStatus, Step2FailureCode,
    Step2Issue, Step2Result, Step2Status, TargetFacts, TrivyArtifact,
)


NOW = datetime(2026, 8, 31, 9, 30, tzinfo=timezone.utc)


def fixed_clock():
    return NOW


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def image_identity(image="repo:test"):
    return ImageIdentity(image, "sha256:image", ("repo@sha256:digest",),
                         "repo@sha256:digest", (image,), "linux/amd64",
                         ImageSourceKind.LOCAL_EXISTING)


def target_facts(run_id="aB3x9", image="repo:test"):
    return TargetFacts(run_id, "before", f"victim-{run_id}", "container-id", "running",
                       image, "sha256:image", "repo@sha256:digest", "kalama-net",
                       "172.18.0.3", ("A=1",), ("serve",), ("/entry",), (), (),
                       ObservationStatus.AVAILABLE, ())


class FakeStep2:
    def __init__(self, store=None, *, fail=False, wrong_digest=False, observe=None):
        self.store, self.fail, self.wrong_digest, self.observe = store, fail, wrong_digest, observe
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        if self.observe:
            self.observe(request)
        if self.fail:
            return Step2Result(Step2Status.FAILED, failure=Step2Issue(
                Step2FailureCode.TRIVY_EXECUTION_FAILED, "trivy_execution", "scan failed",
                True, ("trivy", "image"), 2, "scanner error"))
        path = Path(request.output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"SchemaVersion": 2, "Trivy": {"Version": "0.72.0"},
                   "ArtifactName": request.image_reference, "Results": []}
        path.write_text(json.dumps(payload))
        sha = "0" * 64 if self.wrong_digest else digest(path)
        artifact = TrivyArtifact("trivy", "0.72.0", "repo@sha256:digest",
                                 request.image_reference, "sha256:image", "repo@sha256:digest",
                                 str(path), sha, 2, "2026-08-31T09:30:00Z")
        return Step2Result(Step2Status.SUCCEEDED, image_identity(request.image_reference),
                           target_facts(request.run_id, request.image_reference), artifact)


class FakeStep3:
    def __init__(self, *, returned=1, fail=False, publish=True, observe=None):
        self.returned, self.fail, self.publish, self.observe = returned, fail, publish, observe
        self.calls = []

    def __call__(self, invocation):
        self.calls.append(invocation)
        if self.observe:
            self.observe(invocation)
        if self.fail:
            return PrioritizationResult(False, issues=(StageIssue(
                FailureCode.ENRICHMENT_INCOMPLETE, "enrichment", "incomplete"),))
        artifact = {
            "schema": "kalama.prioritization/v1",
            "artifact": {"kind": "before_top_cves", "run_id": invocation.run_id,
                         "phase": "before", "created_at": invocation.created_at,
                         "top_n_requested": 30, "top_n_returned": self.returned},
            "inputs": {"trivy": {"path": str(invocation.input_path),
                                   "sha256": invocation.trivy_sha256}},
            "score_model": {"id": "kalama-priority-v1"},
            "ranked_cves": [] if self.returned == 0 else [
                {"rank": i, "cve_id": f"CVE-2026-{i:04d}"} for i in range(1, self.returned + 1)],
        }
        if self.publish:
            invocation.output_path.parent.mkdir(parents=True, exist_ok=True)
            invocation.output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
        return PrioritizationResult(True, artifact=artifact)


class StateStoreTests(unittest.TestCase):
    def test_creation_collision_date_path_and_initial_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "output")
            first = store.create("repo:first", now=NOW, run_id_generator=lambda: "aB3x9")
            ids = iter(["aB3x9", "K8mP2"])
            second = store.create("repo:second", now=NOW, run_id_generator=lambda: next(ids))
            self.assertEqual(first.status, RunStatus.INITIALIZING)
            self.assertEqual(first.epss_data_date, "2026-08-31")
            self.assertEqual(second.run_id, "K8mP2")
            self.assertEqual(store.path_for("K8mP2"), Path(tmp).resolve() / "output/state/run_K8mP2.json")

    def test_round_trip_enums_schema_timestamps_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            state = store.create("repo:test", now=NOW, run_id_generator=lambda: "aB3x9")
            first = serialize_run_state(state)
            second = serialize_run_state(store.load("aB3x9"))
            self.assertEqual(first, second)
            self.assertIn(b'"schema": "kalama.run-state/v1"', first)
            self.assertIn(b'"status": "INITIALIZING"', first)
            self.assertIn(b'"created_at": "2026-08-31T09:30:00Z"', first)

    def test_corrupt_unsupported_and_filename_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            state = store.create("repo:test", now=NOW, run_id_generator=lambda: "aB3x9")
            state_path = store.path_for("aB3x9")
            state_path.write_text("{")
            with self.assertRaises(StateStoreError): store.load(state_path)
            data = state.to_dict(); data["schema"] = "future/v99"
            state_path.write_text(json.dumps(data))
            with self.assertRaises(StateStoreError): store.load(state_path)
            mismatch = store.state_dir / "run_K8mP2.json"
            mismatch.write_text(json.dumps(state.to_dict()))
            with self.assertRaises(StateStoreError): store.load(mismatch)

    def test_only_running_blocks_new_run_and_malformed_is_not_ignored(self):
        nonactive = [RunStatus.PAUSED, RunStatus.WAITING_FOR_USER_INPUT,
                     RunStatus.RETRY_REQUIRED, RunStatus.COMPLETED,
                     RunStatus.FAILED_FATAL, RunStatus.ABORTED]
        for status in nonactive:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                store = StateStore(Path(tmp))
                state = store.create("repo:one", now=NOW, run_id_generator=lambda: "aB3x9")
                store.save(replace(state, status=status))
                store.create("repo:two", now=NOW, run_id_generator=lambda: "K8mP2")
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            state = store.create("repo:one", now=NOW, run_id_generator=lambda: "aB3x9")
            store.save(replace(state, status=RunStatus.RUNNING))
            with self.assertRaises(StateStoreError) as caught:
                store.create("repo:two", now=NOW, run_id_generator=lambda: "K8mP2")
            self.assertEqual(caught.exception.code, "ACTIVE_RUN_CONFLICT")
            store.path_for("aB3x9").write_text("bad")
            with self.assertRaises(StateStoreError): store.assert_no_active_run()

    def test_atomic_replace_failure_preserves_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            state = store.create("repo:test", now=NOW, run_id_generator=lambda: "aB3x9")
            path = store.path_for(state.run_id)
            before = path.read_bytes()
            with patch("src.app.kalama.state.store.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(StateStoreError):
                    store.save(replace(state, status=RunStatus.RUNNING))
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(store.state_dir.glob(".run_aB3x9.json.*")), [])

    def test_serialization_failure_preserves_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp))
            state = store.create("repo:test", now=NOW, run_id_generator=lambda: "aB3x9")
            path = store.path_for(state.run_id)
            before = path.read_bytes()
            with patch("src.app.kalama.state.store.json.dumps", side_effect=TypeError("bad value")):
                with self.assertRaises(StateStoreError):
                    store.save(replace(state, status=RunStatus.RUNNING))
            self.assertEqual(path.read_bytes(), before)


class OrchestrationTests(unittest.TestCase):
    def setup(self, tmp, step2=None, step3=None, store_class=StateStore):
        store = store_class(Path(tmp) / "output")
        s2, s3 = step2 or FakeStep2(), step3 or FakeStep3()
        orchestrator = PrioritizationOrchestrator(
            store, s2, s3, clock=fixed_clock, run_id_generator=lambda: "aB3x9")
        return store, s2, s3, orchestrator

    def test_full_fake_flow_commit_order_and_final_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            observations = []
            store = StateStore(Path(tmp) / "output")
            def observe_step2(request):
                state = store.load(request.run_id)
                observations.append((state.stage(PipelineStage.STEP_2_TARGET_SCAN).status,
                                     state.artifact(ArtifactKind.TRIVY_BEFORE)))
            def observe_step3(invocation):
                state = store.load(invocation.run_id)
                observations.append((state.stage(PipelineStage.STEP_3_PRIORITIZATION).status,
                                     state.artifact(ArtifactKind.TRIVY_BEFORE) is not None,
                                     state.artifact(ArtifactKind.TOP30_BEFORE)))
            s2, s3 = FakeStep2(observe=observe_step2), FakeStep3(observe=observe_step3)
            orchestrator = PrioritizationOrchestrator(store, s2, s3, clock=fixed_clock,
                                                       run_id_generator=lambda: "aB3x9")
            state = orchestrator.run("repo:test")
            self.assertEqual(observations[0], (StageStatus.RUNNING, None))
            self.assertEqual(observations[1], (StageStatus.RUNNING, True, None))
            self.assertEqual(state.stage(PipelineStage.STEP_2_TARGET_SCAN).status, StageStatus.SUCCEEDED)
            self.assertEqual(state.stage(PipelineStage.STEP_3_PRIORITIZATION).status, StageStatus.SUCCEEDED)
            self.assertIsNotNone(state.artifact(ArtifactKind.TRIVY_BEFORE))
            self.assertIsNotNone(state.artifact(ArtifactKind.TOP30_BEFORE))
            self.assertEqual(state.target.facts["ip_address"], "172.18.0.3")
            self.assertEqual(state.status, RunStatus.PAUSED)
            self.assertEqual(state.current_stage, PipelineStage.STEP_4_RESOLVER)

    def test_step2_failure_stops_and_never_calls_step3(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, FakeStep2(fail=True))
            state = orchestrator.run("repo:test")
            self.assertEqual(state.status, RunStatus.FAILED_FATAL)
            self.assertEqual(state.stage(PipelineStage.STEP_2_TARGET_SCAN).status, StageStatus.FAILED)
            self.assertEqual(s3.calls, [])
            self.assertIsNone(state.artifact(ArtifactKind.TRIVY_BEFORE))

    def test_step2_bad_digest_prevents_commit_and_step3(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, FakeStep2(wrong_digest=True))
            state = orchestrator.run("repo:test")
            self.assertEqual(state.errors[-1].code, "ARTIFACT_INTEGRITY_ERROR")
            self.assertIsNone(state.artifact(ArtifactKind.TRIVY_BEFORE))
            self.assertEqual(s3.calls, [])

    def test_digest_change_after_step2_state_commit_prevents_step3(self):
        class CorruptingStore(StateStore):
            corrupted = False
            def save(self, state):
                path = super().save(state)
                reference = state.artifact(ArtifactKind.TRIVY_BEFORE)
                if (reference is not None and not self.corrupted
                        and state.stage(PipelineStage.STEP_2_TARGET_SCAN).status == StageStatus.SUCCEEDED):
                    Path(reference.path).write_text("changed after state commit")
                    self.corrupted = True
                return path
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, store_class=CorruptingStore)
            state = orchestrator.run("repo:test")
            self.assertEqual(state.errors[-1].code, "ARTIFACT_INTEGRITY_ERROR")
            self.assertEqual(state.stage(PipelineStage.STEP_3_PRIORITIZATION).status, StageStatus.FAILED)
            self.assertEqual(s3.calls, [])

    def test_step3_receives_state_path_not_newer_directory_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp)
            newer_dir = store.output_root / "trivy/before"
            newer_dir.mkdir(parents=True)
            newer = newer_dir / "scan_2099-01-01_Z9z9Z.json"
            newer.write_text(json.dumps({"SchemaVersion": 2, "Results": []}))
            state = orchestrator.run("repo:test")
            committed = state.artifact(ArtifactKind.TRIVY_BEFORE)
            self.assertEqual(s3.calls[0].input_path, Path(committed.path))
            self.assertNotEqual(s3.calls[0].input_path, newer)
            self.assertEqual(s3.calls[0].epss_data_date.isoformat(), "2026-08-31")

    def test_step3_failure_does_not_commit_top30(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, step3=FakeStep3(fail=True))
            state = orchestrator.run("repo:test")
            self.assertEqual(state.status, RunStatus.FAILED_FATAL)
            self.assertEqual(state.stage(PipelineStage.STEP_3_PRIORITIZATION).status, StageStatus.FAILED)
            self.assertIsNone(state.artifact(ArtifactKind.TOP30_BEFORE))
            self.assertEqual(state.errors[-1].code, "ENRICHMENT_INCOMPLETE")

    def test_step3_success_without_publication_is_not_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, step3=FakeStep3(publish=False))
            state = orchestrator.run("repo:test")
            self.assertEqual(state.status, RunStatus.FAILED_FATAL)
            self.assertIsNone(state.artifact(ArtifactKind.TOP30_BEFORE))

    def test_zero_cves_is_success_with_explicit_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, s2, s3, orchestrator = self.setup(tmp, step3=FakeStep3(returned=0))
            state = orchestrator.run("repo:test")
            self.assertEqual(state.stage(PipelineStage.STEP_3_PRIORITIZATION).status, StageStatus.SUCCEEDED)
            self.assertEqual(state.artifact(ArtifactKind.TOP30_BEFORE).to_dict()["summary"]["top_n_returned"], 0)
            self.assertEqual(state.warnings[-1].code, "NO_RANKABLE_CVES")
            self.assertEqual(state.status, RunStatus.PAUSED)

    def test_active_run_is_rejected_before_new_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "output")
            active = store.create("repo:active", now=NOW, run_id_generator=lambda: "K8mP2")
            store.save(replace(active, status=RunStatus.RUNNING))
            orchestrator = PrioritizationOrchestrator(store, FakeStep2(), FakeStep3(),
                                                       clock=fixed_clock, run_id_generator=lambda: "aB3x9")
            with self.assertRaises(OrchestrationError) as caught:
                orchestrator.run("repo:new")
            self.assertEqual(caught.exception.code, "ACTIVE_RUN_CONFLICT")
            self.assertFalse(store.path_for("aB3x9").exists())


if __name__ == "__main__":
    unittest.main()
