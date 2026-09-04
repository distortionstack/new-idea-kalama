from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from kalama.cli import build_parser, main
from kalama.dispatcher import dispatch_stage
from kalama.state import PipelineStage, RunStatus, StageStatus, StateStore


NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


def boundary(store: StateStore, stage: PipelineStage, *, resolver_succeeded=False):
    state = store.create("example/image:1", now=NOW, run_id_generator=lambda: "aB3x9")
    if resolver_succeeded:
        state = state.with_stage(PipelineStage.STEP_4_RESOLVER, StageStatus.SUCCEEDED,
                                 "2026-09-01T00:00:01Z")
    state = replace(state, status=RunStatus.PAUSED, current_stage=stage,
                    waiting_reason="TEST_BOUNDARY")
    store.save(state)
    return state


class FakeRuntime:
    def __init__(self, store):
        self.store = store
        self.calls = []

    def start(self, image):
        self.calls.append(("start", image))
        return self.store.load("aB3x9")

    def continue_once(self, run_id):
        self.calls.append(("continue", run_id))
        state = self.store.load(run_id)
        # Deliberately transition to another executable boundary. The CLI must
        # still make only this one call.
        state = replace(state, current_stage=PipelineStage.STEP_6_AFTER_SCAN)
        self.store.save(state)
        return state

    def submit_attack_form(self, run_id, path):
        self.calls.append(("attack", run_id, path))
        return self.store.load(run_id)

    def submit_patch_form(self, run_id, path):
        self.calls.append(("patch", run_id, path))
        return self.store.load(run_id)

    def retry_patch_execution(self, run_id, *, edit_plan):
        self.calls.append(("retry", run_id, edit_plan))
        return self.store.load(run_id)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name) / "output")

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, argv, runtime):
        out, err = StringIO(), StringIO()
        code = main(argv, runtime_factory=lambda _: runtime, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_help_lists_required_commands(self):
        help_text = build_parser().format_help()
        for command in ("run", "continue", "status", "submit-attack-form",
                        "submit-patch-form", "retry"):
            self.assertIn(command, help_text)

    def test_dispatch_all_real_boundaries(self):
        cases = (
            (PipelineStage.STEP_4_RESOLVER, False, "resolver"),
            (PipelineStage.STEP_4_RESOLVER, True, "before_exploit"),
            (PipelineStage.STEP_4_BEFORE_EXPLOIT, True, "before_exploit"),
            (PipelineStage.STEP_5_PATCH, False, "patch_plan"),
            (PipelineStage.STEP_5_PATCH_PLAN, False, "patch_plan"),
            (PipelineStage.STEP_5_PATCH_EXECUTION, False, "patch_execution"),
            (PipelineStage.STEP_6_AFTER_SCAN, False, "after_scan"),
            (PipelineStage.STEP_7_REEXPLOIT, False, "reexploit"),
            (PipelineStage.STEP_8_EVALUATION, False, "evaluation"),
        )
        for index, (stage, resolver_done, expected) in enumerate(cases):
            with self.subTest(stage=stage, resolver_done=resolver_done):
                with tempfile.TemporaryDirectory() as root:
                    store = StateStore(Path(root) / "output")
                    state = store.create("image", now=NOW,
                                         run_id_generator=lambda i=index: f"A{i:04d}"[-5:])
                    if resolver_done:
                        state = state.with_stage(PipelineStage.STEP_4_RESOLVER,
                                                 StageStatus.SUCCEEDED,
                                                 "2026-09-01T00:00:01Z")
                    state = replace(state, status=RunStatus.PAUSED, current_stage=stage)
                    self.assertEqual(dispatch_stage(state), expected)

    def test_continue_calls_runtime_once(self):
        boundary(self.store, PipelineStage.STEP_4_RESOLVER)
        runtime = FakeRuntime(self.store)
        code, _, _ = self.invoke(["--output-root", str(self.store.output_root),
                                  "continue", "aB3x9"], runtime)
        self.assertEqual(code, 0)
        self.assertEqual(runtime.calls, [("continue", "aB3x9")])

    def test_waiting_form_does_not_dispatch(self):
        state = boundary(self.store, PipelineStage.STEP_4_RESOLVER)
        state = replace(state, status=RunStatus.WAITING_FOR_USER_INPUT,
                        waiting_reason="ATTACK_FORM")
        self.store.save(state)
        runtime = FakeRuntime(self.store)
        code, out, _ = self.invoke(["continue", "aB3x9"], runtime)
        self.assertEqual(code, 0)
        self.assertEqual(runtime.calls, [])
        self.assertIn("submit-attack-form aB3x9 FILE", out)

    def test_submissions_pass_exact_paths(self):
        boundary(self.store, PipelineStage.STEP_4_RESOLVER)
        runtime = FakeRuntime(self.store)
        self.invoke(["submit-attack-form", "aB3x9", "attack.yaml"], runtime)
        self.invoke(["submit-patch-form", "aB3x9", "patch.yaml"], runtime)
        self.assertEqual(runtime.calls, [
            ("attack", "aB3x9", Path("attack.yaml")),
            ("patch", "aB3x9", Path("patch.yaml")),
        ])

    def test_retry_calls_runtime_with_explicit_mode(self):
        boundary(self.store, PipelineStage.STEP_5_PATCH_EXECUTION)
        runtime = FakeRuntime(self.store)
        self.invoke(["retry", "aB3x9", "--edit-plan"], runtime)
        self.invoke(["retry", "aB3x9", "--same-plan"], runtime)
        self.assertEqual(runtime.calls, [
            ("retry", "aB3x9", True),
            ("retry", "aB3x9", False),
        ])

    def test_completed_and_failed_do_not_dispatch(self):
        state = boundary(self.store, PipelineStage.STEP_8_EVALUATION)
        for status, expected_code in ((RunStatus.COMPLETED, 0), (RunStatus.FAILED_FATAL, 1)):
            with self.subTest(status=status):
                self.store.save(replace(state, status=status))
                runtime = FakeRuntime(self.store)
                code, _, _ = self.invoke(["continue", "aB3x9"], runtime)
                self.assertEqual(code, expected_code)
                self.assertEqual(runtime.calls, [])

    def test_unknown_run_is_clean_and_exact(self):
        runtime = FakeRuntime(self.store)
        code, _, err = self.invoke(["status", "aB3x9"], runtime)
        self.assertEqual(code, 1)
        self.assertEqual(err.strip(), "RUN_NOT_FOUND: aB3x9")

    def test_status_loads_requested_run(self):
        boundary(self.store, PipelineStage.STEP_4_RESOLVER)
        other = self.store.create("newer", now=NOW, run_id_generator=lambda: "Z9z9Z")
        self.store.save(replace(other, status=RunStatus.PAUSED))
        runtime = FakeRuntime(self.store)
        code, out, _ = self.invoke(["status", "aB3x9"], runtime)
        self.assertEqual(code, 0)
        self.assertIn("Run ID: aB3x9", out)
        self.assertNotIn("Run ID: Z9z9Z", out)


if __name__ == "__main__":
    unittest.main()
