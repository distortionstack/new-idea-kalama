"""Core Kalama/VIPER end-to-end regression test (safe, no live infrastructure).

This is the primary regression test for the core pipeline. It drives the
REAL production orchestrators and the REAL persisted state machine
(:func:`kalama.dispatcher.dispatch_stage` + ``continue`` semantics) from
run creation through final evaluation:

    prepare -> scan BEFORE -> prioritize -> resolve/confirm attack
    -> exploit BEFORE -> patch plan/confirm -> patch execution
    -> scan AFTER -> re-exploit -> evaluate/report

Fake adapters are used ONLY at external boundaries (target scanner,
prioritizer inputs, resolver backend, Metasploit, patch backend, image
inspector). Both human-confirmation gates (Attack Form, Patch Form) are
exercised explicitly: the driver pauses at WAITING_FOR_USER_INPUT exactly
as production does and only proceeds after submitting a confirmation.

No Docker, Metasploit, Trivy, or network access is required.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import yaml

from kalama.dispatcher import dispatch_stage
from kalama.evaluation.orchestrator import EvaluationOrchestrator
from kalama.execution.models import EnvironmentValidation
from kalama.execution.orchestrator import BeforeExploitOrchestrator
from kalama.orchestrator import PrioritizationOrchestrator
from kalama.prioritizer.models import PrioritizationResult
from kalama.reexploit.orchestrator import ReexploitOrchestrator
from kalama.remediation.confirmation_orchestrator import PatchConfirmationOrchestrator
from kalama.remediation.execution_orchestrator import PatchExecutionOrchestrator
from kalama.remediation.orchestrator import PatchPlanningOrchestrator
from kalama.resolution.confirmation_orchestrator import AttackFormOrchestrator
from kalama.resolution.orchestrator import ResolverOrchestrator, production_step4_processor
from kalama.resolver.config import validate_exploit_config
from kalama.resolver.config_models import ConfirmationStatus, ExploitValue, FieldSource
from kalama.resolver.models import PayloadEvidence
from kalama.state.models import ArtifactKind, PipelineStage, RunStatus, StageStatus
from kalama.state.store import StateStore
from kalama.target.models import (
    ImageIdentity, ImageSourceKind, Step2Result, Step2Status, TargetFacts, TrivyArtifact,
)
from kalama.target.models import ObservationStatus
from kalama.verification.orchestrator import AfterScanOrchestrator

from tests.integration import test_step4_orchestrator as step4_helpers
from tests.integration.test_after_scan import FakeScanner, report
from tests.integration.test_before_exploit import FakeCommands, FakeMsf
from tests.integration.test_orchestrator import image_identity, target_facts
from tests.integration.test_patch_execution import FakePatchBackend
from tests.integration.test_patch_planning import FakeProvider, occurrence


NOW = datetime(2026, 8, 31, 9, 30, tzinfo=timezone.utc)
RUN_ID = "aB3x9"
CVE_ID = "CVE-2099-0001"

EXPECTED_DISPATCH_SEQUENCE = (
    "resolver",
    "before_exploit",
    "patch_plan",
    "patch_execution",
    "after_scan",
    "reexploit",
    "evaluation",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class E2EStep2:
    """Fake target scanner publishing a BEFORE report containing the CVE."""

    def __init__(self, cve: str = CVE_ID):
        self.cve, self.calls = cve, []

    def __call__(self, request):
        self.calls.append(request)
        path = Path(request.output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.72.0"},
            "ArtifactName": request.image_reference,
            "Metadata": {
                "OS": {"Family": "debian"},
                "DB": {"UpdatedAt": "2026-08-31T00:00:00Z"},
            },
            "Results": [
                {
                    "Target": "rootfs",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": self.cve,
                            "PkgName": "openssl",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                            "PkgIdentifier": {"PURL": "pkg:deb/openssl"},
                        }
                    ],
                }
            ],
        }
        path.write_text(json.dumps(payload))
        artifact = TrivyArtifact(
            "trivy", "0.72.0", "repo@sha256:digest", request.image_reference,
            "sha256:image", "repo@sha256:digest", str(path),
            _digest(path), 2, "2026-08-31T09:30:00Z",
        )
        return Step2Result(
            Step2Status.SUCCEEDED, image_identity(request.image_reference),
            target_facts(request.run_id, request.image_reference), artifact)


class E2EStep3:
    """Fake prioritizer selecting the CVE with patch-planning occurrences."""

    def __init__(self, cve: str = CVE_ID):
        self.cve, self.calls = cve, []

    def __call__(self, invocation):
        self.calls.append(invocation)
        artifact = {
            "schema": "kalama.prioritization/v1",
            "artifact": {
                "kind": "before_top_cves",
                "run_id": invocation.run_id,
                "phase": "before",
                "created_at": invocation.created_at,
                "top_n_requested": 30,
                "top_n_returned": 1,
            },
            "inputs": {
                "trivy": {
                    "path": str(invocation.input_path),
                    "sha256": invocation.trivy_sha256,
                }
            },
            "score_model": {"id": "kalama-priority-v1"},
            "ranked_cves": [
                {"rank": 1, "cve_id": self.cve,
                 "occurrences": [occurrence(self.cve)]},
            ],
        }
        invocation.output_path.parent.mkdir(parents=True, exist_ok=True)
        invocation.output_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n")
        return PrioritizationResult(True, artifact=artifact)


def resolver_processor():
    candidates = {"exploit/a": {"rank": "excellent", "check_supported": True}}
    live = {"exploit/a": {"options": [], "status": "UNAVAILABLE", "payloads": []}}
    return production_step4_processor(
        step4_helpers.backend(candidates=candidates, live=live),
        msf_container="msf")


def payload_introspector(module: str, payload: str):
    return PayloadEvidence(payload, ())


def confirm_attack_form(store: StateStore, root: Path) -> Path:
    """Human confirmation: lock module + execution protocol for every CVE."""
    state = store.load(RUN_ID)
    form = yaml.safe_load(Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_bytes())
    for entry in form["cves"].values():
        entry["module"]["confirmed"] = "exploit/a"
        entry["execution_protocol"]["confirmed"] = True
    path = root / "attack_submission.yaml"
    path.write_text(yaml.safe_dump(form, sort_keys=False), encoding="utf-8")
    return path


def force_ready_exploit_protocol(store: StateStore) -> None:
    """Mark the confirmed config READY_TO_EXECUTE (mirrors operator tooling).

    The submitted Attack Form confirms module + protocol; the payload and
    readiness projection applied here is exactly what the existing
    before-exploit fixtures apply. It never changes module identity.
    """
    from kalama.resolution.config_codec import exploit_config_from_dict

    state = store.load(RUN_ID)
    ref = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
    artifact = json.loads(Path(ref.path).read_bytes())
    config = exploit_config_from_dict(artifact["cves"][0]["exploit_config"])
    protocol = replace(
        config.invariant.execution_protocol, run_check=False, run_exploit=True,
        confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED)
    payload = replace(
        config.invariant.payload,
        payload=ExploitValue("cmd/unix/generic", None, FieldSource.HUMAN_ATTACK_FORM,
                             ConfirmationStatus.HUMAN_CONFIRMED, required=True))
    config = replace(
        config, invariant=replace(config.invariant, execution_protocol=protocol,
                                  payload=payload))
    validation = validate_exploit_config(config)
    config = replace(config, readiness=validation.readiness)
    artifact["cves"][0].update(exploit_config=config.to_dict(),
                               validation=validation.to_dict(),
                               status="READY_TO_EXECUTE")
    Path(ref.path).write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")
    store.save(state.with_artifact(
        replace(ref, sha256=_digest(Path(ref.path))), state.updated_at))


def confirm_patch_form(store: StateStore, root: Path, name: str = "patch_submission.yaml") -> Path:
    """Human confirmation: approve every waiting patch action."""
    state = store.load(RUN_ID)
    form = yaml.safe_load(Path(state.artifact(ArtifactKind.PATCH_FORM).path).read_bytes())
    for action in form["actions"].values():
        action["fix_type"]["confirmed"] = "C"
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["target_version"]["confirmed"] = "1.1"
        action["artifact"]["confirmed_source"] = "human:approved"
        action["command"]["confirmed"] = "install-approved-package"
        action["execution_target"] = "patch-workspace"
    path = root / name
    path.write_text(yaml.safe_dump(form, sort_keys=False), encoding="utf-8")
    return path


def successful_before_msf():
    """Fake Metasploit yielding one attributable session on the BEFORE target."""
    return FakeMsf(
        sessions=(("1",), ("1", "2")),
        session_details=({}, {"2": {"tunnel_peer": "172.18.0.3:4444",
                                   "via_exploit": "exploit/a"}}))


def clean_negative_after_msf():
    """Fake Metasploit yielding no new sessions on the AFTER target."""
    return FakeMsf(sessions=(("existing",), ("existing",)))


def compensate_after_facts_for_fake_backend(store: StateStore) -> None:
    """Enrich AFTER facts the fake patch backend omits but Docker provides.

    The production ``DockerPatchBackend.create_after_target`` returns facts
    carrying the patched image identity and exposed ports; the fake backend
    returns a minimal record. This mirrors the compensation already used by
    the step-7 fixtures and touches only fake-adapter data, never lineage.
    """
    state = store.load(RUN_ID)
    assert state.after_target is not None and state.patched_image is not None
    facts = dict(state.after_target.facts or {})
    facts.update(
        image_id=state.patched_image["image_id"],
        image_digest=None,
        requested_image_reference=state.patched_image["reference"],
        exposed_ports=[{"container_port": 8080, "protocol": "tcp"}],
    )
    store.save(replace(
        state, after_target=replace(state.after_target, facts=facts)))


class E2EPipeline:
    """Driver for the full core pipeline using real orchestrators + dispatch."""

    def __init__(self, root: Path):
        self.root = root
        self.store = StateStore(root)
        self.dispatched: list[str] = []

    def _clock(self):
        return NOW

    def start(self):
        orchestrator = PrioritizationOrchestrator(
            self.store, E2EStep2(), E2EStep3(), clock=lambda: NOW,
            run_id_generator=lambda: RUN_ID)
        state = orchestrator.run("victim:test")
        assert state.run_id == RUN_ID
        assert state.status == RunStatus.PAUSED
        assert state.current_stage == PipelineStage.STEP_4_RESOLVER
        return state

    def _dispatch_next(self):
        state = self.store.load(RUN_ID)
        assert state.status == RunStatus.PAUSED, (
            f"expected PAUSED continuation boundary, got {state.status}")
        selected = dispatch_stage(state)
        self.dispatched.append(selected)
        return state, selected

    def run_resolver(self):
        state, selected = self._dispatch_next()
        assert selected == "resolver", selected
        return ResolverOrchestrator(
            self.store, resolver_processor(), clock=lambda: NOW).run(RUN_ID)

    def submit_attack_confirmation(self):
        state = self.store.load(RUN_ID)
        assert state.status == RunStatus.WAITING_FOR_USER_INPUT
        assert state.waiting_reason == "ATTACK_FORM"
        path = confirm_attack_form(self.store, self.root)
        confirmed = AttackFormOrchestrator(
            self.store, clock=lambda: NOW,
            payload_introspector=payload_introspector).apply_attack_form(RUN_ID, path)
        assert confirmed.status == RunStatus.PAUSED
        assert confirmed.waiting_reason == "BEFORE_EXPLOIT_NOT_INTEGRATED"
        force_ready_exploit_protocol(self.store)
        return self.store.load(RUN_ID)

    def run_before_exploit(self, msf=None, env=None):
        state, selected = self._dispatch_next()
        assert selected == "before_exploit", selected
        assert state.waiting_reason == "BEFORE_EXPLOIT_NOT_INTEGRATED"
        return BeforeExploitOrchestrator(
            self.store, env or (lambda *_: EnvironmentValidation(True)),
            msf or successful_before_msf(), FakeCommands(),
            clock=lambda: NOW).run(RUN_ID)

    def run_patch_plan(self, provider=None):
        state, selected = self._dispatch_next()
        assert selected == "patch_plan", selected
        assert state.waiting_reason == "PATCH_NOT_INTEGRATED"
        attack = json.loads(Path(state.artifact(
            ArtifactKind.ATTACK_BEFORE).path).read_bytes())
        assert any(entry.get("disposition") == "EXPLOIT_SUCCEEDED"
                   for entry in attack["cves"]), (
            "patch planning requires valid BEFORE exploit evidence")
        return PatchPlanningOrchestrator(
            self.store, provider or FakeProvider(), clock=lambda: NOW).run(RUN_ID)

    def submit_patch_confirmation(self):
        state = self.store.load(RUN_ID)
        assert state.status == RunStatus.WAITING_FOR_USER_INPUT
        assert state.waiting_reason == "PATCH_FORM"
        path = confirm_patch_form(self.store, self.root)
        confirmed = PatchConfirmationOrchestrator(
            self.store, clock=lambda: NOW).apply_patch_form(RUN_ID, path)
        assert confirmed.status == RunStatus.PAUSED
        assert confirmed.waiting_reason == "PATCH_EXECUTION_NOT_INTEGRATED"
        return confirmed

    def run_patch_execution(self, backend=None):
        state, selected = self._dispatch_next()
        assert selected == "patch_execution", selected
        assert state.waiting_reason == "PATCH_EXECUTION_NOT_INTEGRATED"
        result = PatchExecutionOrchestrator(
            self.store, backend or FakePatchBackend(), clock=lambda: NOW).run(RUN_ID)
        if result.status == RunStatus.PAUSED:
            compensate_after_facts_for_fake_backend(self.store)
            result = self.store.load(RUN_ID)
        return result

    def run_after_scan(self, scanner=None, inspector=None):
        state, selected = self._dispatch_next()
        assert selected == "after_scan", selected
        assert state.waiting_reason == "AFTER_SCAN_NOT_INTEGRATED"
        assert state.patched_image is not None and state.after_target is not None
        before_id = state.target.image_identity.get("image_id") if state.target else None
        assert before_id != state.patched_image.get("image_id"), (
            "AFTER scan must operate on a distinct remediated artifact")

        def _inspector(subject: str):
            current = self.store.load(RUN_ID)
            assert current.patched_image is not None
            return {"image_id": current.patched_image["image_id"], "repo_digests": ()}

        return AfterScanOrchestrator(
            self.store, scanner or FakeScanner(report()),
            inspector or _inspector, clock=lambda: NOW).run(RUN_ID)

    def run_reexploit(self, msf=None, env=None):
        state, selected = self._dispatch_next()
        assert selected == "reexploit", selected
        assert state.waiting_reason == "REEXPLOIT_NOT_INTEGRATED"
        return ReexploitOrchestrator(
            self.store, env or (lambda *_: EnvironmentValidation(True)),
            msf or clean_negative_after_msf(), FakeCommands(),
            clock=lambda: NOW).run(RUN_ID)

    def run_evaluation(self):
        state, selected = self._dispatch_next()
        assert selected == "evaluation", selected
        assert state.waiting_reason == "EVALUATION_NOT_INTEGRATED"
        return EvaluationOrchestrator(self.store, clock=lambda: NOW).run(RUN_ID)

    def drive_full(self):
        """Execute the entire happy path through dispatch + confirmations."""
        self.start()
        state = self.run_resolver()
        assert state.status == RunStatus.WAITING_FOR_USER_INPUT
        self.submit_attack_confirmation()
        state = self.run_before_exploit()
        assert state.waiting_reason == "PATCH_NOT_INTEGRATED"
        state = self.run_patch_plan()
        assert state.status == RunStatus.WAITING_FOR_USER_INPUT
        self.submit_patch_confirmation()
        state = self.run_patch_execution()
        assert state.waiting_reason == "AFTER_SCAN_NOT_INTEGRATED"
        state = self.run_after_scan()
        assert state.waiting_reason == "REEXPLOIT_NOT_INTEGRATED"
        state = self.run_reexploit()
        assert state.waiting_reason == "EVALUATION_NOT_INTEGRATED"
        state = self.run_evaluation()
        assert state.status == RunStatus.COMPLETED
        assert tuple(self.dispatched) == EXPECTED_DISPATCH_SEQUENCE
        return state


class CoreEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.pipeline = E2EPipeline(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_full_pipeline_reaches_completed_evaluation(self):
        state = self.pipeline.drive_full()

        # Same run identity throughout every committed artifact.
        # (Trivy reports are scanner-native and carry no run_id; their
        # lineage is pinned by SHA-256 in REMEDIATION_SCAN_RESULT inputs.)
        for kind in (ArtifactKind.TOP30_BEFORE,
                     ArtifactKind.ATTACK_BEFORE, ArtifactKind.EXPLOIT_CONFIG_BEFORE,
                     ArtifactKind.PATCH_PLAN, ArtifactKind.PATCH_RESULT,
                     ArtifactKind.REMEDIATION_SCAN_RESULT,
                     ArtifactKind.EXPLOIT_CONFIG_AFTER, ArtifactKind.ATTACK_AFTER,
                     ArtifactKind.REMEDIATION_RESULT, ArtifactKind.EVALUATION_DATASET,
                     ArtifactKind.EVALUATION_METRICS, ArtifactKind.RUN_SUMMARY):
            reference = state.artifact(kind)
            self.assertIsNotNone(reference, kind.value)
            payload = json.loads(Path(reference.path).read_bytes())
            run_id = (payload.get("run_id") or (payload.get("artifact") or {}).get("run_id"))
            self.assertEqual(run_id, RUN_ID, kind.value)

        # Correct CVE carried through every stage, including the Top-N item.
        top = json.loads(Path(state.artifact(
            ArtifactKind.TOP30_BEFORE).path).read_bytes())
        self.assertEqual(top["ranked_cves"][0]["cve_id"], CVE_ID)
        self.assertEqual(top["ranked_cves"][0]["rank"], 1)
        for kind, key in ((ArtifactKind.ATTACK_BEFORE, "cves"),
                          (ArtifactKind.ATTACK_AFTER, "cves"),
                          (ArtifactKind.EVALUATION_DATASET, "records")):
            payload = json.loads(Path(state.artifact(kind).path).read_bytes())
            self.assertIn(CVE_ID, [entry["cve_id"] for entry in payload[key]], kind.value)
        plan = json.loads(Path(state.artifact(ArtifactKind.PATCH_PLAN).path).read_bytes())
        self.assertIn(CVE_ID, [cve for action in plan["actions"]
                               for cve in action["target_cves"]])
        remediation = json.loads(Path(state.artifact(
            ArtifactKind.REMEDIATION_RESULT).path).read_bytes())
        self.assertEqual(remediation["cves"][0]["cve_id"], CVE_ID)

        # Patched target differs; AFTER stages bind to it, never BEFORE data.
        before_id = state.target.image_identity["image_id"]
        patched_id = state.patched_image["image_id"]
        self.assertNotEqual(before_id, patched_id)
        after_scan_summary = dict(state.artifact(ArtifactKind.TRIVY_AFTER).summary)
        self.assertEqual(after_scan_summary["image_id"], patched_id)
        scan_result = json.loads(Path(state.artifact(
            ArtifactKind.REMEDIATION_SCAN_RESULT).path).read_bytes())
        self.assertEqual(scan_result["images"]["patched"]["image_id"], patched_id)
        self.assertEqual(scan_result["images"]["before"]["image_id"], before_id)
        config_after = json.loads(Path(state.artifact(
            ArtifactKind.EXPLOIT_CONFIG_AFTER).path).read_bytes())
        self.assertEqual(config_after["provenance"]["after_image_id"], patched_id)
        rebound = config_after["cves"][0]["exploit_config"]
        self.assertEqual(rebound["environment"]["ip_address"],
                         state.after_target.facts["ip_address"])
        # Same exploit strategy, refreshed environment: invariant preserved.
        config_before = json.loads(Path(state.artifact(
            ArtifactKind.EXPLOIT_CONFIG_BEFORE).path).read_bytes())
        before_cfg = next(entry["exploit_config"] for entry in config_before["cves"]
                          if entry["cve_id"] == CVE_ID)
        self.assertEqual(rebound["invariant"], before_cfg["invariant"])
        self.assertNotEqual(rebound["environment"]["container_name"],
                            before_cfg["environment"]["container_name"])

        # Human confirmations are preserved in the lineage.
        self.assertIsNotNone(state.artifact(ArtifactKind.ATTACK_FORM_SUBMISSION))
        self.assertIsNotNone(state.artifact(ArtifactKind.PATCH_FORM_SUBMISSION))

        # BEFORE success + patch success + AFTER not reproduced => validated.
        attack_before = json.loads(Path(state.artifact(
            ArtifactKind.ATTACK_BEFORE).path).read_bytes())
        attack_after = json.loads(Path(state.artifact(
            ArtifactKind.ATTACK_AFTER).path).read_bytes())
        self.assertEqual(attack_before["cves"][0]["disposition"], "EXPLOIT_SUCCEEDED")
        self.assertEqual(attack_after["cves"][0]["disposition"], "EXPLOIT_FAILED")
        self.assertEqual(remediation["cves"][0]["final"]["status"], "VERIFIED")
        dataset = json.loads(Path(state.artifact(
            ArtifactKind.EVALUATION_DATASET).path).read_bytes())
        inputs = dataset["inputs"]
        for key, kind in (("top30_before", ArtifactKind.TOP30_BEFORE),
                          ("attack_before", ArtifactKind.ATTACK_BEFORE),
                          ("remediation_result", ArtifactKind.REMEDIATION_RESULT),
                          ("remediation_scan_result",
                           ArtifactKind.REMEDIATION_SCAN_RESULT),
                          ("patch_plan", ArtifactKind.PATCH_PLAN)):
            self.assertEqual(inputs[key]["sha256"], state.artifact(kind).sha256, key)
        # Scanner-native reports are pinned by SHA lineage, not run_id.
        scan_inputs = scan_result["inputs"]
        self.assertEqual(scan_inputs["trivy_before"]["sha256"],
                         state.artifact(ArtifactKind.TRIVY_BEFORE).sha256)
        self.assertEqual(scan_inputs["trivy_after"]["sha256"],
                         state.artifact(ArtifactKind.TRIVY_AFTER).sha256)
        record = next(entry for entry in dataset["records"]
                      if entry["cve_id"] == CVE_ID)
        self.assertEqual(record["remediation"]["final_remediation_status"], "VERIFIED")

        # Final state is completed and the report references all evidence.
        self.assertEqual(state.current_stage, PipelineStage.STEP_8_EVALUATION)
        self.assertEqual(state.stage(PipelineStage.STEP_8_EVALUATION).status,
                         StageStatus.SUCCEEDED)
        self.assertIsNone(state.waiting_reason)
        summary = json.loads(Path(state.artifact(
            ArtifactKind.RUN_SUMMARY).path).read_bytes())
        for key in ("EVALUATION_DATASET", "EVALUATION_METRICS", "ATTACK_BEFORE",
                    "ATTACK_AFTER", "PATCH_RESULT", "REMEDIATION_SCAN_RESULT",
                    "REMEDIATION_RESULT"):
            self.assertIn(key, summary["artifact_index"], key)
        self.assertEqual(summary["run_id"], RUN_ID)

    def test_stages_progress_only_through_canonical_dispatch(self):
        self.pipeline.start()
        seen = []
        state = self.pipeline.run_resolver()
        seen.append("resolver:waiting-attack-form")
        self.pipeline.submit_attack_confirmation()
        state = self.pipeline.run_before_exploit()
        seen.append(f"before-exploit:{state.waiting_reason}")
        state = self.pipeline.run_patch_plan()
        seen.append(f"patch-plan:{state.status.value}")
        self.pipeline.submit_patch_confirmation()
        state = self.pipeline.run_patch_execution()
        seen.append(f"patch-execution:{state.waiting_reason}")
        state = self.pipeline.run_after_scan()
        seen.append(f"after-scan:{state.waiting_reason}")
        state = self.pipeline.run_reexploit()
        seen.append(f"reexploit:{state.waiting_reason}")
        state = self.pipeline.run_evaluation()
        seen.append(f"evaluation:{state.status.value}")
        self.assertEqual(seen, [
            "resolver:waiting-attack-form",
            "before-exploit:PATCH_NOT_INTEGRATED",
            "patch-plan:WAITING_FOR_USER_INPUT",
            "patch-execution:AFTER_SCAN_NOT_INTEGRATED",
            "after-scan:REEXPLOIT_NOT_INTEGRATED",
            "reexploit:EVALUATION_NOT_INTEGRATED",
            "evaluation:COMPLETED",
        ])
        self.assertEqual(state.status, RunStatus.COMPLETED)


if __name__ == "__main__":
    unittest.main()
