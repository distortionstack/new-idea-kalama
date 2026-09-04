import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from kalama.resolver.core import DiscoveryBackend
from kalama.resolver.models import ModuleOption, PayloadEvidence
from kalama.resolution.confirmation_orchestrator import AttackFormOrchestrator
from kalama.resolution.config_codec import exploit_config_from_dict
from kalama.resolution.orchestrator import ResolverOrchestrator, production_step4_processor
from kalama.state.models import ArtifactKind, RunStatus, StageStatus
from kalama.state.store import StateStore
from tests.integration import test_step4_orchestrator as step4_helpers


NOW = step4_helpers.NOW
backend = step4_helpers.backend


class AttackFormSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root)
        helper = step4_helpers.Step4OrchestrationTests()
        helper.root, helper.store = self.root, self.store
        self.helper = helper

    def tearDown(self):
        self.temp.cleanup()

    def waiting_run(self, cves=("CVE-2099-0001",), *, options=(), payloads=(),
                    payload_status="UNAVAILABLE", check_supported=True):
        self.helper.prepare(cves)
        candidates = {"exploit/a": {"rank": "excellent", "check_supported": check_supported},
                      "exploit/b": {"rank": "good", "check_supported": check_supported}}
        live_options = [{"name": name, "type": kind, "required": required, "default": default}
                        for name, kind, required, default in options]
        live = {"exploit/a": {"options": live_options, "status": payload_status,
                               "payloads": list(payloads)},
                "exploit/b": {"options": live_options, "status": payload_status,
                               "payloads": list(payloads)}}
        self.payload_schemas = {
            item["name"]: tuple(ModuleOption(option["name"], option.get("type"),
                                             bool(option.get("required")), option.get("default"))
                                for option in item.get("options", ()))
            for item in payloads}
        self.payload_calls = []
        processor = production_step4_processor(backend(candidates=candidates, live=live),
                                               msf_container="msf")
        return ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")

    def submission(self, state, mutate=None, name="submission.yaml"):
        form = yaml.safe_load(Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_bytes())
        if mutate:
            mutate(form)
        path = self.root / name
        path.write_text(yaml.safe_dump(form, sort_keys=False), encoding="utf-8")
        return path

    def apply(self, path):
        def introspect(module, payload):
            self.payload_calls.append((module, payload))
            return PayloadEvidence(payload, self.payload_schemas[payload])
        return AttackFormOrchestrator(
            self.store, clock=lambda: NOW,
            payload_introspector=introspect).apply_attack_form("aB3x9", path)

    def test_malicious_yaml_and_wrong_run_preserve_waiting_state(self):
        state = self.waiting_run()
        original_form = state.artifact(ArtifactKind.ATTACK_FORM).sha256
        malicious = self.root / "malicious.yaml"
        malicious.write_text("!!python/object/apply:os.system ['echo unsafe']", encoding="utf-8")
        result = self.apply(malicious)
        self.assertEqual(result.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(result.errors[-1].code, "ATTACK_FORM_INVALID_YAML")
        self.assertEqual(result.artifact(ArtifactKind.ATTACK_FORM).sha256, original_form)

        wrong = self.submission(result, lambda x: x.update(run_id="K8mP2"), "wrong.yaml")
        result = self.apply(wrong)
        self.assertEqual(result.errors[-1].code, "ATTACK_FORM_RUN_MISMATCH")
        self.assertEqual(result.stage(result.current_stage).status, StageStatus.WAITING)

    def test_partial_cve_then_second_revision_preserves_lineage_and_is_idempotent(self):
        state = self.waiting_run(("CVE-2099-0001", "CVE-2099-0002"))

        def first(form):
            del form["cves"]["CVE-2099-0002"]
            form["cves"]["CVE-2099-0001"]["module"]["confirmed"] = "exploit/b"
            form["cves"]["CVE-2099-0001"]["execution_protocol"]["confirmed"] = True

        first_path = self.submission(state, first, "first.yaml")
        state = self.apply(first_path)
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual([x.resolver_status for x in state.cves],
                         ["READY_TO_EXECUTE", "WAITING_FOR_USER_INPUT"])
        self.assertEqual(dict(state.artifact(ArtifactKind.ATTACK_FORM).summary)["revision"], 2)
        config1 = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        snapshot1 = state.artifact(ArtifactKind.ATTACK_FORM_SUBMISSION)
        self.assertTrue(Path(config1.path).exists())
        self.assertEqual(self.apply(first_path).artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE).sha256,
                         config1.sha256)

        def second(form):
            form["cves"]["CVE-2099-0002"]["module"]["confirmed"] = "exploit/a"
            form["cves"]["CVE-2099-0002"]["execution_protocol"]["confirmed"] = True

        second_path = self.submission(state, second, "second.yaml")
        final = self.apply(second_path)
        self.assertEqual(final.status, RunStatus.PAUSED)
        self.assertEqual(final.waiting_reason, "BEFORE_EXPLOIT_NOT_INTEGRATED")
        self.assertEqual(dict(final.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE).summary)["revision"], 2)
        history = final.artifact_history
        self.assertIn(config1.sha256, [x.sha256 for x in history])
        self.assertIn(snapshot1.sha256, [x.sha256 for x in history])
        artifact = json.loads(Path(final.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE).path).read_bytes())
        self.assertEqual(artifact["provenance"]["previous_config_sha256"], config1.sha256)
        self.assertEqual(artifact["provenance"]["submission_sha256"],
                         final.artifact(ArtifactKind.ATTACK_FORM_SUBMISSION).sha256)

    def test_partial_field_human_provenance_and_new_form(self):
        state = self.waiting_run(options=(("TARGETURI", "path", True, "/"),))

        def mutate(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["targeturi"]["confirmed"] = "/showcase"

        state = self.apply(self.submission(state, mutate))
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        artifact = json.loads(Path(state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE).path).read_bytes())
        config = exploit_config_from_dict(artifact["cves"][0]["exploit_config"])
        self.assertEqual(config.invariant.targeturi.value, "/showcase")
        self.assertEqual(config.invariant.targeturi.suggested_value, "/")
        self.assertEqual(config.invariant.targeturi.source.value, "HUMAN_ATTACK_FORM")
        self.assertEqual(config.invariant.module_selection.module.confirmation_status.value,
                         "SUGGESTED")
        next_form = yaml.safe_load(Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_bytes())
        self.assertEqual(next_form["revision"], 2)
        self.assertNotIn("TARGETURI_REQUIRED",
                         next_form["cves"]["CVE-2099-0001"]["input_reasons"])

    def test_invalid_module_unknown_option_and_stale_form_are_input_errors(self):
        state = self.waiting_run()
        original = state.artifact(ArtifactKind.ATTACK_FORM).sha256

        bad_module = self.submission(state, lambda form: form["cves"]["CVE-2099-0001"]
                                     ["module"].update(confirmed="exploit/not-discovered"), "bad-module.yaml")
        result = self.apply(bad_module)
        self.assertEqual(result.errors[-1].code, "ATTACK_FORM_INVALID_MODULE")
        self.assertEqual(result.artifact(ArtifactKind.ATTACK_FORM).sha256, original)

        def unknown(form):
            form["cves"]["CVE-2099-0001"]["module_options"]["FAKE"] = {"confirmed": "x"}
        result = self.apply(self.submission(result, unknown, "bad-option.yaml"))
        self.assertEqual(result.errors[-1].code, "ATTACK_FORM_INVALID_OPTION")

        stale = self.submission(result, lambda form: form.update(revision=0), "stale.yaml")
        result = self.apply(stale)
        self.assertEqual(result.errors[-1].code, "ATTACK_FORM_STALE")
        self.assertIsNone(result.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE))

    def test_payload_requires_positive_compatibility_evidence_and_membership(self):
        payloads = ({"name": "cmd/unix/generic", "options": []},)
        state = self.waiting_run(payloads=payloads, payload_status="FOUND")

        def incompatible(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["module"]["confirmed"] = "exploit/a"
            cve["payload"]["confirmed"] = "cmd/unix/reverse_bash"
        rejected = self.apply(self.submission(state, incompatible, "bad-payload.yaml"))
        self.assertEqual(rejected.errors[-1].code, "ATTACK_FORM_INVALID_PAYLOAD")
        self.assertEqual(self.payload_calls, [])


    def test_unavailable_payload_evidence_is_not_an_unrestricted_allowlist(self):
        state = self.waiting_run(payload_status="UNAVAILABLE")
        def arbitrary(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["module"]["confirmed"] = "exploit/a"
            cve["payload"]["confirmed"] = "cmd/unix/arbitrary"
        rejected = self.apply(self.submission(state, arbitrary, "unavailable-payload.yaml"))
        self.assertEqual(rejected.errors[-1].code, "ATTACK_FORM_INVALID_PAYLOAD")

    def test_selected_payload_materializes_required_option_schema(self):
        payloads = ({"name": "cmd/unix/reverse_bash", "options": [
            {"name": "LHOST", "type": "address", "required": True, "default": None},
            {"name": "LPORT", "type": "port", "required": True, "default": 4444},
        ]},)
        state = self.waiting_run(payloads=payloads, payload_status="FOUND",
                                 check_supported=False)

        def choose(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["module"]["confirmed"] = "exploit/a"
            cve["payload"]["confirmed"] = "cmd/unix/reverse_bash"
            cve["execution_protocol"]["confirmed"] = True
        state = self.apply(self.submission(state, choose, "choose-payload.yaml"))
        self.assertEqual(self.payload_calls,
                         [("exploit/a", "cmd/unix/reverse_bash")])
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        next_form = yaml.safe_load(Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_bytes())
        reasons = next_form["cves"]["CVE-2099-0001"]["input_reasons"]
        self.assertIn("PAYLOAD_OPTION_REQUIRED", reasons)
        self.assertEqual(next_form["cves"]["CVE-2099-0001"]["payload_options"]
                         ["LPORT"]["suggested"], 4444)

    def test_all_resolved_config_is_only_future_executor_input(self):
        state = self.waiting_run()

        def complete(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["module"]["confirmed"] = "exploit/a"
            cve["execution_protocol"]["confirmed"] = True

        final = self.apply(self.submission(state, complete))
        config_ref = final.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        self.assertEqual(final.status, RunStatus.PAUSED)
        self.assertEqual(final.stage(final.current_stage).status, StageStatus.SUCCEEDED)
        config_set = json.loads(Path(config_ref.path).read_bytes())
        config = exploit_config_from_dict(config_set["cves"][0]["exploit_config"])
        self.assertEqual(config.readiness.value, "READY_TO_EXECUTE")
        self.assertEqual(config.invariant.module_selection.module.source.value, "HUMAN_ATTACK_FORM")
        self.assertEqual(config.invariant.execution_protocol.confirmation_status.value,
                         "HUMAN_CONFIRMED")
        serialized = config.to_dict()
        self.assertIn("invariant", serialized)
        self.assertIn("environment", serialized)

    def test_check_then_exploit_protocol_is_human_selectable(self):
        payloads = ({"name": "cmd/unix/generic", "options": []},)
        state = self.waiting_run(payloads=payloads, payload_status="FOUND")

        def complete(form):
            cve = form["cves"]["CVE-2099-0001"]
            cve["module"]["confirmed"] = "exploit/a"
            cve["execution_protocol"]["mode"] = "check-then-exploit"
            cve["execution_protocol"]["confirmed"] = True
            cve["payload"]["confirmed"] = "cmd/unix/generic"

        final = self.apply(self.submission(state, complete))
        self.assertEqual(final.status, RunStatus.PAUSED)
        artifact = json.loads(Path(final.artifact(
            ArtifactKind.EXPLOIT_CONFIG_BEFORE).path).read_bytes())
        config = exploit_config_from_dict(artifact["cves"][0]["exploit_config"])
        self.assertTrue(config.invariant.execution_protocol.run_check)
        self.assertTrue(config.invariant.execution_protocol.run_exploit)

    def test_snapshot_or_config_write_failure_does_not_commit_confirmations(self):
        state = self.waiting_run()
        path = self.submission(state, lambda form: form["cves"]["CVE-2099-0001"]
                               ["module"].update(confirmed="exploit/a"))
        with patch("kalama.resolution.confirmation_orchestrator.write_submission_snapshot",
                   side_effect=OSError("snapshot failed")):
            failed = self.apply(path)
        self.assertEqual(failed.status, RunStatus.FAILED_FATAL)
        self.assertIsNone(failed.artifact(ArtifactKind.ATTACK_FORM_SUBMISSION))
        self.assertIsNone(failed.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE))


if __name__ == "__main__":
    unittest.main()
