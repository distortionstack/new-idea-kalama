import json
import hashlib
from pathlib import Path
import unittest

import yaml

import test_patch_planning as planning_helpers
from src.app.kalama.resolution.artifacts import (
    ImmutableArtifactConflict, PATCH_RESULT_SCHEMA, write_patch_result_immutable,
)
from src.app.kalama.remediation.confirmation_orchestrator import PatchConfirmationOrchestrator
from src.app.kalama.remediation.codec import patch_plan_from_artifact
from src.app.kalama.remediation.docker_backend import DockerPatchBackend
from src.app.kalama.remediation.execution_orchestrator import PatchExecutionOrchestrator
from src.app.kalama.remediation.retry_orchestrator import PatchRetryOrchestrator
from src.app.kalama.remediation.models import FixType, PatchStrategy, RemediationCandidate
from src.app.kalama.state.models import ArtifactKind, ArtifactReference, PipelineStage, RunStatus, StageStatus
from src.app.kalama.target.models import CommandResult


NOW = planning_helpers.task4_helpers.NOW


class FakePatchBackend:
    def __init__(self, *, action_success=True, validation_success=True, preserve=True):
        self.action_success = action_success
        self.validation_success = validation_success
        self.preserve = preserve
        self.calls = []

    def inspect_source(self, source_image):
        self.calls.append(("inspect_source", dict(source_image)))
        return {"image_id": source_image.get("image_id"),
                "selected_digest": source_image.get("selected_digest")}

    def prepare_workspace(self, plan_artifact, *, attempt=1):
        value = {"container_name": plan_artifact["planned_after"]["patch_workspace"],
                 "labels": {"kalama.managed": "true", "kalama.run_id": plan_artifact["run_id"],
                            "kalama.phase": "patch", "kalama.role": "patch-workspace",
                            "kalama.attempt": str(attempt)},
                 "attempt": attempt}
        self.calls.append(("prepare_workspace", value))
        return value

    def execute_action(self, action, context, *, timeout):
        self.calls.append(("execute_action", action.action_id, action.strategy.value,
                           dict(context["workspace"]), timeout))
        return {"success": self.action_success, "exit_code": 0 if self.action_success else 1,
                "operations": [{"kind": action.strategy.value, "target": "patch-workspace"}]}

    def execute_validation(self, command, context, *, timeout):
        self.calls.append(("execute_validation", command, dict(context["workspace"]), timeout))
        return {"success": self.validation_success,
                "exit_code": 0 if self.validation_success else 42,
                "stdout": "ok" if self.validation_success else "bad",
                "stderr": None if self.validation_success else "nope"}

    def finalize_image(self, plan_artifact, workspace):
        self.calls.append(("finalize_image", dict(workspace)))
        return {"reference": plan_artifact["planned_after"]["image_reference"],
                "image_id": "sha256:patched", "selected_digest": None}

    def resolve_prebuilt_image(self, action, plan_artifact):
        self.calls.append(("resolve_prebuilt_image", action.action_id))
        return {"success": True, "image_identity": {
            "reference": plan_artifact["planned_after"]["image_reference"],
            "image_id": "sha256:prebuilt", "selected_digest": "repo@sha256:prebuilt"}}

    def verify_source_preserved(self, source_identity):
        self.calls.append(("verify_source_preserved", dict(source_identity)))
        return self.preserve

    def create_after_target(self, run_id, patched_image, planned_after, before_facts):
        self.calls.append(("create_after_target", run_id, dict(patched_image)))
        return ({"requested_reference": patched_image["reference"],
                 "image_id": patched_image["image_id"]},
                {"run_id": run_id, "phase": "after",
                 "container_name": f"victim-after-{run_id}", "container_id": "after-id",
                 "container_state": "running", "network": "kalama-net",
                 "ip_address": "172.18.0.9", "environment": [], "command": [],
                 "entrypoint": [], "exposed_ports": [], "published_ports": [],
                 "listening_ports_status": "UNKNOWN", "listening_ports": [],
                 "reachable_ports_status": "UNKNOWN", "reachable_ports": []})


class RecordingRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout=None):
        self.calls.append((tuple(argv), timeout))
        return CommandResult(tuple(argv), 0, "", "")


class WorkspaceRunner:
    def __init__(self, *, exists=False, labels=None):
        self.calls = []
        self.exists = exists
        self.labels = labels or {}

    def run(self, argv, *, timeout=None):
        self.calls.append((tuple(argv), timeout))
        argv = tuple(argv)
        if argv[:3] == ("docker", "container", "inspect"):
            if not self.exists:
                return CommandResult(argv, 1, "", "No such container")
            payload = [{"Id": "container-id", "Image": "sha256:source",
                        "Config": {"Labels": self.labels},
                        "State": {"Running": True}}]
            return CommandResult(argv, 0, json.dumps(payload), "")
        if argv[:2] == ("docker", "create"):
            self.exists = True
            self.labels = {
                "kalama.managed": "true",
                "kalama.run_id": "aB3x9",
                "kalama.phase": "patch",
                "kalama.role": "patch-workspace",
                "kalama.attempt": "2",
                "kalama.source_image_id": "sha256:source",
            }
            return CommandResult(argv, 0, "", "")
        return CommandResult(argv, 0, "", "")


class FinalizeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout=None):
        argv = tuple(argv)
        self.calls.append((argv, timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            if argv[3] == "kalama/example:patched":
                if not any(x[0][:2] == ("docker", "commit") for x in self.calls):
                    return CommandResult(argv, 1, "", "No such image")
                return CommandResult(argv, 0, json.dumps([{
                    "Id": "sha256:patched", "RepoTags": ["kalama/example:patched"],
                    "RepoDigests": [], "Os": "linux", "Architecture": "amd64",
                }]), "")
            if argv[3] == "sha256:source":
                return CommandResult(argv, 0, json.dumps([{
                    "Id": "sha256:source", "Config": {
                        "Entrypoint": None, "Cmd": ["catalina.sh", "run"]},
                }]), "")
        return CommandResult(argv, 0, "", "")


class PatchTask5BTests(unittest.TestCase):
    def setUp(self):
        self.fixture = planning_helpers.PatchPlanningIntegrationTests()
        self.fixture.setUp()
        self.store = self.fixture.store

    def tearDown(self):
        self.fixture.tearDown()

    def ready(self):
        candidate = RemediationCandidate(
            "1.1", FixType.C, PatchStrategy.PACKAGE_MANAGER,
            "official_repository", "debian-security", trusted=True, same_branch=True)
        return self.fixture.run_plan(planning_helpers.FakeProvider(candidate))

    def add_validation(self, state, command="test -f /patched"):
        ref = state.artifact(ArtifactKind.PATCH_PLAN)
        artifact = json.loads(Path(ref.path).read_bytes())
        artifact["actions"][0]["execution"] = {
            **dict(artifact["actions"][0].get("execution") or {}),
            "validation_command": command,
            "execution_target": "patch-workspace",
        }
        Path(ref.path).write_text(json.dumps(artifact), encoding="utf-8")
        from dataclasses import replace
        ref = replace(ref, sha256=__import__("hashlib").sha256(Path(ref.path).read_bytes()).hexdigest())
        state = self.store.load("aB3x9").with_artifact(ref, state.updated_at)
        self.store.save(state)
        return self.store.load("aB3x9")

    def test_complete_confirmation_revises_canonical_plan_then_executes_without_form(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form_ref = waiting.artifact(ArtifactKind.PATCH_FORM)
        submission = yaml.safe_load(Path(form_ref.path).read_bytes())
        action = next(iter(submission["actions"].values()))
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "install-approved-package"
        action["execution_target"] = "patch-workspace"
        submitted = self.fixture.root / "submission.yaml"
        submitted.write_text(yaml.safe_dump(submission), encoding="utf-8")

        confirmed = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        self.assertEqual(confirmed.status, RunStatus.PAUSED)
        self.assertEqual(confirmed.current_stage, PipelineStage.STEP_5_PATCH_EXECUTION)
        self.assertIsNotNone(confirmed.artifact(ArtifactKind.PATCH_FORM_SUBMISSION))
        plan = json.loads(Path(confirmed.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        self.assertEqual(plan["revision"], 1)
        self.assertEqual(plan["readiness"], "READY_FOR_PATCH_EXECUTION")

        # Execution consumes only the state-referenced plan. Human artifacts can move away.
        Path(form_ref.path).rename(Path(form_ref.path).with_suffix(".moved"))
        Path(confirmed.artifact(ArtifactKind.PATCH_FORM_SUBMISSION).path).rename(
            Path(confirmed.artifact(ArtifactKind.PATCH_FORM_SUBMISSION).path).with_suffix(".moved"))
        backend = FakePatchBackend()
        state = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.stage(PipelineStage.STEP_5_PATCH_EXECUTION).status,
                         StageStatus.SUCCEEDED)
        self.assertEqual(state.current_stage, PipelineStage.STEP_6_AFTER_SCAN)
        self.assertEqual(state.waiting_reason, "AFTER_SCAN_NOT_INTEGRATED")
        self.assertEqual(state.after_target.facts["phase"], "after")
        result = json.loads(Path(state.artifact(ArtifactKind.PATCH_RESULT).path).read_bytes())
        self.assertFalse(result["remediation_verified"])
        self.assertEqual(result["actions"][0]["result"], "SUCCEEDED")

    def test_partial_confirmation_preserves_waiting_and_advances_revision(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form = yaml.safe_load(Path(waiting.artifact(ArtifactKind.PATCH_FORM).path).read_bytes())
        next(iter(form["actions"].values()))["target_version"]["confirmed"] = "1.1"
        submitted = self.fixture.root / "partial.yaml"
        submitted.write_text(yaml.safe_dump(form), encoding="utf-8")
        state = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.waiting_reason, "PATCH_FORM")
        next_form = yaml.safe_load(Path(state.artifact(ArtifactKind.PATCH_FORM).path).read_bytes())
        self.assertEqual(next_form["revision"], 2)
        self.assertEqual(next_form["base_patch_plan_sha256"],
                         state.artifact(ArtifactKind.PATCH_PLAN).sha256)

    def test_unsafe_yaml_and_read_only_tampering_are_nonfatal_input_errors(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        unsafe = self.fixture.root / "unsafe.yaml"
        unsafe.write_text("!!python/object/apply:os.system ['false']", encoding="utf-8")
        state = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", unsafe)
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.errors[-1].code, "PATCH_FORM_INVALID_YAML")

        form = yaml.safe_load(Path(waiting.artifact(ArtifactKind.PATCH_FORM).path).read_bytes())
        next(iter(form["actions"].values()))["target_cves"] = ["CVE-2099-9999"]
        tampered = self.fixture.root / "tampered.yaml"
        tampered.write_text(yaml.safe_dump(form), encoding="utf-8")
        state = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", tampered)
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.errors[-1].code, "PATCH_FORM_TAMPERED")

    def test_action_failure_stops_before_image_and_after_target(self):
        self.ready()
        backend = FakePatchBackend(action_success=False)
        state = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_RESULT))
        self.assertIsNone(state.patched_image)
        self.assertIsNone(state.after_target)
        self.assertFalse(any(call[0] == "finalize_image" for call in backend.calls))
        self.assertFalse(any(call[0] == "create_after_target" for call in backend.calls))
        result = json.loads(Path(state.artifact(ArtifactKind.PATCH_RESULT).path).read_bytes())
        self.assertEqual(result["attempt"], 1)
        self.assertEqual(result["failed_at"], "COMMAND")
        self.assertIn("_attempt_1.json", state.artifact(ArtifactKind.PATCH_RESULT).path)

    def test_validation_runs_before_finalize_and_failure_preserves_evidence(self):
        state = self.add_validation(self.ready(), "validate-patch")
        backend = FakePatchBackend(validation_success=False)
        failed = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(failed.status, RunStatus.FAILED_FATAL)
        self.assertEqual(failed.errors[-1].code, "PATCH_VALIDATION_FAILED")
        self.assertFalse(any(call[0] == "finalize_image" for call in backend.calls))
        self.assertEqual(sum(call[0] == "execute_validation" for call in backend.calls), 1)
        result = json.loads(Path(failed.artifact(ArtifactKind.PATCH_RESULT).path).read_bytes())
        self.assertEqual(result["failed_at"], "VALIDATION")
        self.assertEqual(result["validation_evidence"]["exit_code"], 42)
        self.assertEqual(result["validation_evidence"]["stdout"], "bad")
        self.assertEqual(result["validation_evidence"]["stderr"], "nope")

    def test_validation_success_allows_finalize(self):
        self.add_validation(self.ready(), "validate-patch")
        backend = FakePatchBackend(validation_success=True)
        state = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.stage(PipelineStage.STEP_5_PATCH_EXECUTION).status,
                         StageStatus.SUCCEEDED)
        names = [call[0] for call in backend.calls]
        self.assertLess(names.index("execute_validation"), names.index("finalize_image"))

    def test_source_preservation_failure_never_commits_after_identity(self):
        self.ready()
        backend = FakePatchBackend(preserve=False)
        state = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNone(state.patched_image)
        self.assertIsNone(state.after_target)
        self.assertFalse(any(call[0] == "create_after_target" for call in backend.calls))

    def test_empty_plan_is_a_backend_free_noop(self):
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.ATTACK_BEFORE)
        artifact = json.loads(Path(ref.path).read_bytes())
        artifact["cves"][0]["disposition"] = "EXPLOIT_FAILED"
        Path(ref.path).write_text(json.dumps(artifact), encoding="utf-8")
        import hashlib
        from dataclasses import replace
        ref = replace(ref, sha256=hashlib.sha256(Path(ref.path).read_bytes()).hexdigest())
        self.store.save(state.with_artifact(ref, state.updated_at))
        planned = self.fixture.run_plan(planning_helpers.FakeProvider())
        backend = FakePatchBackend()
        result = PatchExecutionOrchestrator(
            self.store, backend, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(result, planned)
        self.assertEqual(backend.calls, [])
        self.assertIsNone(result.artifact(ArtifactKind.PATCH_RESULT))

    def test_package_manager_is_container_isolated_and_unsupported_has_no_fallback(self):
        state = self.ready()
        plan = patch_plan_from_artifact(json.loads(
            Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes()))
        action = plan.actions[0]
        runner = RecordingRunner()
        backend = DockerPatchBackend(runner)
        result = backend.execute_action(
            action, {"workspace": {"container_name": "patch-workspace-aB3x9"}}, timeout=19)
        self.assertTrue(result["success"])
        argv, timeout = runner.calls[0]
        self.assertEqual(argv[:3], ("docker", "exec", "patch-workspace-aB3x9"))
        self.assertIn("apt-get install", argv[-1])
        self.assertEqual(timeout, 19)
        self.assertNotIn("sudo", argv)

        from dataclasses import replace
        unsupported = replace(action, strategy=PatchStrategy.COPACETIC)
        result = backend.execute_action(
            unsupported, {"workspace": {"container_name": "patch-workspace-aB3x9"}}, timeout=19)
        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "COPACETIC_EXECUTOR_NOT_CONFIGURED")
        self.assertEqual(len(runner.calls), 1)

    def test_workspace_attempt_name_labels_and_conflict_safety(self):
        state = self.ready()
        artifact = json.loads(Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        artifact["source_image"]["image_id"] = "sha256:source"
        runner = WorkspaceRunner()
        workspace = DockerPatchBackend(runner).prepare_workspace(artifact, attempt=2)
        self.assertEqual(workspace["container_name"], "patch-workspace-aB3x9-a2")
        self.assertEqual(workspace["labels"]["kalama.attempt"], "2")
        create_call = next(argv for argv, _ in runner.calls if argv[:2] == ("docker", "create"))
        self.assertIn("--label", create_call)
        self.assertIn("kalama.attempt=2", create_call)

        bad = WorkspaceRunner(exists=True, labels={
            "kalama.managed": "true",
            "kalama.run_id": "aB3x9",
            "kalama.phase": "patch",
            "kalama.role": "patch-workspace",
        })
        with self.assertRaisesRegex(Exception, "PATCH_WORKSPACE_CONFLICT"):
            DockerPatchBackend(bad).prepare_workspace(artifact, attempt=2)

    def test_finalize_restores_source_entrypoint_and_command(self):
        runner = FinalizeRunner()
        artifact = {
            "run_id": "aB3x9",
            "planned_after": {"image_reference": "kalama/example:patched"},
        }
        result = DockerPatchBackend(runner).finalize_image(artifact, {
            "container_name": "patch-workspace-aB3x9-a1",
            "source_image_id": "sha256:source",
        })
        self.assertEqual(result["image_id"], "sha256:patched")
        commit = next(argv for argv, _ in runner.calls if argv[:2] == ("docker", "commit"))
        changes = [commit[i + 1] for i, value in enumerate(commit[:-1]) if value == "--change"]
        self.assertIn("ENTRYPOINT []", changes)
        self.assertIn('CMD ["catalina.sh","run"]', changes)

    def test_retry_eligibility_and_edit_plan_revision_are_immutable(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form_r1 = waiting.artifact(ArtifactKind.PATCH_FORM)
        submission = yaml.safe_load(Path(form_r1.path).read_bytes())
        action = next(iter(submission["actions"].values()))
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "bad-command"
        action["validation_command"]["confirmed"] = "validate"
        action["execution_target"] = "patch-workspace"
        submitted = self.fixture.root / "submission.yaml"
        submitted.write_text(yaml.safe_dump(submission), encoding="utf-8")
        PatchConfirmationOrchestrator(self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        attempt1_ref = failed.artifact(ArtifactKind.PATCH_RESULT)
        state = PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry(
            "aB3x9", edit_plan=True)
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.waiting_reason, "PATCH_FORM")
        self.assertTrue(Path(attempt1_ref.path).is_file())
        self.assertTrue(Path(form_r1.path).is_file())
        self.assertEqual(state.artifact(ArtifactKind.PATCH_RESULT), attempt1_ref)
        form_r2 = yaml.safe_load(Path(state.artifact(ArtifactKind.PATCH_FORM).path).read_bytes())
        self.assertEqual(form_r2["revision"], 2)
        self.assertEqual(next(iter(form_r2["actions"].values()))["command"]["confirmed"], "bad-command")
        next(iter(form_r2["actions"].values()))["command"]["confirmed"] = "fixed-command"
        r2_path = self.fixture.root / "r2.yaml"
        r2_path.write_text(yaml.safe_dump(form_r2), encoding="utf-8")
        confirmed = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", r2_path)
        self.assertEqual(confirmed.status, RunStatus.PAUSED)
        self.assertEqual(confirmed.current_stage, PipelineStage.STEP_5_PATCH_EXECUTION)
        self.assertEqual(confirmed.waiting_reason, "PATCH_EXECUTION_NOT_INTEGRATED")

    def test_retry_rejects_integrity_wrong_stage_and_non_failed(self):
        state = self.ready()
        with self.assertRaisesRegex(Exception, "run is not FAILED_FATAL"):
            PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        from dataclasses import replace
        wrong = replace(failed, current_stage=PipelineStage.STEP_6_AFTER_SCAN)
        self.store.save(wrong)
        with self.assertRaisesRegex(Exception, "Patch Execution"):
            PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)
        integrity = replace(failed, errors=failed.errors[:-1] + (
            replace(failed.errors[-1], code="PATCH_PLAN_INTEGRITY_ERROR"),))
        self.store.save(integrity)
        with self.assertRaisesRegex(Exception, "PATCH_PLAN_INTEGRITY_ERROR"):
            PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)

    def test_same_plan_retry_creates_second_attempt_result(self):
        self.ready()
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        attempt1 = failed.artifact(ArtifactKind.PATCH_RESULT)
        PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=False)
        state = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=True), clock=lambda: NOW).run("aB3x9")
        attempt2 = state.artifact(ArtifactKind.PATCH_RESULT)
        self.assertNotEqual(attempt1.path, attempt2.path)
        self.assertTrue(Path(attempt1.path).is_file())
        result2 = json.loads(Path(attempt2.path).read_bytes())
        self.assertEqual(result2["attempt"], 2)
        self.assertEqual(result2["lineage"]["retry_of"], attempt1.sha256)

    def test_retry_does_not_rerun_earlier_stages(self):
        self.ready()
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        before = {x.stage: x for x in failed.stages if x.stage != PipelineStage.STEP_5_PATCH_EXECUTION}
        state = PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry(
            "aB3x9", edit_plan=False)
        after = {x.stage: x for x in state.stages if x.stage != PipelineStage.STEP_5_PATCH_EXECUTION}
        self.assertEqual(before, after)

    def test_immutable_patch_result_writer_refuses_collision(self):
        path = self.fixture.root / "patch" / "results" / "patch_result_2026-08-31_aB3x9_attempt_7.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        sentinel = b"sentinel\n"
        path.write_bytes(sentinel)
        artifact = {"schema": PATCH_RESULT_SCHEMA, "run_id": "aB3x9", "phase": "patch",
                    "created_at": "2026-08-31T09:30:00Z", "attempt": 7,
                    "actions": [], "errors": [], "remediation_verified": False}
        with self.assertRaises(ImmutableArtifactConflict):
            write_patch_result_immutable(path, artifact)
        self.assertEqual(path.read_bytes(), sentinel)
        self.assertEqual(list(path.parent.glob(f".{path.name}.*")), [])

    def test_orphaned_patch_result_advances_attempt_without_overwrite(self):
        self.ready()
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=False)
        orphan = self.store.output_root / "patch" / "results" / "patch_result_2026-08-31_aB3x9_attempt_2.json"
        orphan_payload = {"schema": PATCH_RESULT_SCHEMA, "run_id": "aB3x9", "phase": "patch",
                          "created_at": "2026-08-31T09:30:00Z", "attempt": 2,
                          "status": "FAILED", "failed_at": "COMMAND",
                          "lineage": {"retry_of": failed.artifact(ArtifactKind.PATCH_RESULT).sha256},
                          "actions": [], "errors": ["PATCH_ACTION_FAILED"],
                          "remediation_verified": False}
        orphan.write_text(json.dumps(orphan_payload, sort_keys=True), encoding="utf-8")
        before = orphan.read_bytes()
        state = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=True), clock=lambda: NOW).run("aB3x9")
        self.assertIn("_attempt_3.json", state.artifact(ArtifactKind.PATCH_RESULT).path)
        self.assertEqual(orphan.read_bytes(), before)

    def test_orphaned_patch_form_revision_is_not_overwritten(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form_r1 = waiting.artifact(ArtifactKind.PATCH_FORM)
        submission = yaml.safe_load(Path(form_r1.path).read_bytes())
        action = next(iter(submission["actions"].values()))
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "bad-command"
        action["execution_target"] = "patch-workspace"
        submitted = self.fixture.root / "submission.yaml"
        submitted.write_text(yaml.safe_dump(submission), encoding="utf-8")
        PatchConfirmationOrchestrator(self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        orphan = self.store.output_root / "patch" / "forms" / "patch_form_aB3x9_r2.yaml"
        orphan.write_text("sentinel\n", encoding="utf-8")
        before = orphan.read_bytes()
        state = PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)
        self.assertEqual(orphan.read_bytes(), before)
        self.assertIn("_r3.yaml", state.artifact(ArtifactKind.PATCH_FORM).path)

    def test_retry_rejects_corrupted_active_patch_form_before_mutation(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form_r1 = waiting.artifact(ArtifactKind.PATCH_FORM)
        submission = yaml.safe_load(Path(form_r1.path).read_bytes())
        action = next(iter(submission["actions"].values()))
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "bad-command"
        action["execution_target"] = "patch-workspace"
        submitted = self.fixture.root / "submission.yaml"
        submitted.write_text(yaml.safe_dump(submission), encoding="utf-8")
        PatchConfirmationOrchestrator(self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        state_bytes = self.store.path_for("aB3x9").read_bytes()
        Path(failed.artifact(ArtifactKind.PATCH_FORM).path).write_text("corrupt: [", encoding="utf-8")
        with self.assertRaisesRegex(Exception, "PATCH_FORM_INTEGRITY_ERROR"):
            PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)
        self.assertEqual(self.store.path_for("aB3x9").read_bytes(), state_bytes)
        self.assertFalse((self.store.output_root / "patch" / "forms" / "patch_form_aB3x9_r2.yaml").exists())

    def test_retry_rejects_corrupted_active_patch_submission_before_mutation(self):
        waiting = self.fixture.run_plan(planning_helpers.FakeProvider())
        form_r1 = waiting.artifact(ArtifactKind.PATCH_FORM)
        submission = yaml.safe_load(Path(form_r1.path).read_bytes())
        action = next(iter(submission["actions"].values()))
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "bad-command"
        action["execution_target"] = "patch-workspace"
        submitted = self.fixture.root / "submission.yaml"
        submitted.write_text(yaml.safe_dump(submission), encoding="utf-8")
        confirmed = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form("aB3x9", submitted)
        failed = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        state_bytes = self.store.path_for("aB3x9").read_bytes()
        Path(confirmed.artifact(ArtifactKind.PATCH_FORM_SUBMISSION).path).write_text("corrupt: [", encoding="utf-8")
        with self.assertRaisesRegex(Exception, "PATCH_FORM_SUBMISSION_INTEGRITY_ERROR"):
            PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=True)
        self.assertEqual(self.store.path_for("aB3x9").read_bytes(), state_bytes)
        self.assertFalse((self.store.output_root / "patch" / "forms" / "patch_form_aB3x9_r2.yaml").exists())

    def test_repeated_same_plan_retry_reaches_attempt_three_with_lineage(self):
        self.ready()
        state1 = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        result1 = state1.artifact(ArtifactKind.PATCH_RESULT)
        PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=False)
        state2 = PatchExecutionOrchestrator(
            self.store, FakePatchBackend(action_success=False), clock=lambda: NOW).run("aB3x9")
        result2 = state2.artifact(ArtifactKind.PATCH_RESULT)
        PatchRetryOrchestrator(self.store, clock=lambda: NOW).retry("aB3x9", edit_plan=False)
        backend3 = FakePatchBackend(action_success=True)
        state3 = PatchExecutionOrchestrator(
            self.store, backend3, clock=lambda: NOW).run("aB3x9")
        result3 = state3.artifact(ArtifactKind.PATCH_RESULT)
        self.assertTrue(Path(result1.path).is_file())
        self.assertTrue(Path(result2.path).is_file())
        self.assertNotEqual(result1.path, result2.path)
        self.assertNotEqual(result2.path, result3.path)
        payload2 = json.loads(Path(result2.path).read_bytes())
        payload3 = json.loads(Path(result3.path).read_bytes())
        self.assertEqual(payload2["attempt"], 2)
        self.assertEqual(payload3["attempt"], 3)
        self.assertEqual(payload2["lineage"]["retry_of"], result1.sha256)
        self.assertEqual(payload3["lineage"]["retry_of"], result2.sha256)
        self.assertEqual(state3.run_id, "aB3x9")
        self.assertEqual(state3.artifact(ArtifactKind.PATCH_RESULT), result3)
        workspaces = [call[1]["attempt"] for call in backend3.calls if call[0] == "prepare_workspace"]
        self.assertEqual(workspaces, [3])


if __name__ == "__main__":
    unittest.main()
