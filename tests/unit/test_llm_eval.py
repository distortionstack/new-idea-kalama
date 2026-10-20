"""Task 7 deterministic tests: metrics, artifacts, fixtures, runner plan.

No Ollama, network, Docker, or live model.  Fake transports/providers only.
"""

import io
import json
import unittest
from contextlib import redirect_stdout

from kalama.evaluation.llm_eval import (
    LLM_EVAL_SCHEMA,
    bound_raw_proposal,
    build_eval_artifact,
    compute_llm_eval_metrics,
    scrub_provider_config,
    validate_eval_artifact,
    validate_run_record,
)
from kalama.evaluation.llm_eval_cases import (
    ALL_CASES,
    FIXTURES_VERSION,
    build_attack_legacy_pack,
    build_patch_envelope_fixture,
    collector_fixture,
)
from kalama.evaluation.llm_eval_runner import main as runner_main
from kalama.evaluation.llm_eval_runner import plan_cases, preflight


def record(**over):
    base = {"case_id": "B", "purpose": "attack", "repetition": 1,
            "candidate_digest": "d" * 64,
            "requested_fields": ["target", "payload"],
            "protected_fields": ["rport"],
            "allowed_fields": ["target", "payload"],
            "evidence_pack_sha256": "e" * 64,
            "evidence_refs": ["msf:mod", "runtime:observed"],
            "expected_values": {"target": {"index": 0, "name": "Universal"}},
            "expected_unresolved": ["target", "payload"],
            "sufficient_evidence": True,
            "provider_attempted": True, "parse_ok": True,
            "validation_state": "ACCEPTED_AS_SUGGESTION",
            "accepted": {"target": {"value": {"index": 0, "name": "Universal"},
                                    "evidence_refs": ["msf:mod"]}},
            "emitted_fields": ["target"],
            "issues": []}
    base.update(over)
    return base


class MetricsTests(unittest.TestCase):
    def test_rates_and_counts(self):
        records = [record(),
                   record(case_id="F", purpose="patch", candidate_digest="x" * 64,
                          validation_state="REJECTED", accepted={},
                          emitted_fields=["strategy", "command"],
                          issues=["strategy: unsupported value",
                                  "command: forbidden"]),
                   record(case_id="C", sufficient_evidence=False,
                          expected_unresolved=["target"],
                          validation_state="INSUFFICIENT_EVIDENCE",
                          accepted={}, emitted_fields=[])]
        metrics = compute_llm_eval_metrics(records)
        self.assertEqual(metrics["runs"], 3)
        self.assertEqual(metrics["valid_structured"]["numerator"], 3)
        self.assertEqual(metrics["valid_structured"]["denominator"], 3)
        self.assertEqual(metrics["validator_acceptance"]["numerator"], 1)
        self.assertEqual(metrics["validator_acceptance"]["denominator"], 3)
        # Field accuracy: 1 known (target), correct.
        self.assertEqual((metrics["field_accuracy"]["numerator"],
                          metrics["field_accuracy"]["denominator"]), (1, 1))
        # Coverage: sufficient-evidence expected fields: run1 {target,payload}
        # (target hit, payload missed) + run2 {target,payload} missed.
        self.assertEqual(metrics["field_coverage"]["denominator"], 4)
        self.assertEqual(metrics["field_coverage"]["numerator"], 1)
        # Attribution: 1 accepted evidence-backed suggestion, refs inside pack.
        self.assertEqual((metrics["evidence_attribution"]["numerator"],
                          metrics["evidence_attribution"]["denominator"]), (1, 1))
        # Unsupported: emitted 3 (target + strategy/command), 2 unaccepted.
        self.assertEqual((metrics["unsupported_suggestion_rate"]["numerator"],
                          metrics["unsupported_suggestion_rate"]["denominator"]), (2, 3))
        # Abstention: 1 insufficient case, correctly empty.
        self.assertEqual((metrics["abstention_correctness"]["numerator"],
                          metrics["abstention_correctness"]["denominator"]), (1, 1))

    def test_zero_denominator_handling(self):
        metrics = compute_llm_eval_metrics([])
        for name in ("valid_structured", "validator_acceptance",
                     "field_accuracy", "field_coverage",
                     "evidence_attribution", "unsupported_suggestion_rate",
                     "overwrite_attempt_rate", "abstention_correctness",
                     "binding_safety"):
            self.assertIsNone(metrics[name]["rate"], name)
            self.assertEqual(metrics[name]["denominator"], 0, name)

    def test_partial_acceptance_and_overwrite_and_binding(self):
        records = [record(validation_state="PARTIALLY_ACCEPTED",
                          accepted={"payload": {"value": "cmd/unix/reverse_bash",
                                                "evidence_refs": ["msf:mod"]}},
                          emitted_fields=["payload", "rport"],
                          expected_values={"payload": ["cmd/unix/reverse_bash",
                                                       "cmd/unix/generic"]}),
                   record(case_id="K", purpose="patch", binding_test=True,
                          binding_rejected=True),
                   record(case_id="K", purpose="patch", repetition=2,
                          binding_test=True, binding_rejected=False)]
        metrics = compute_llm_eval_metrics(records)
        self.assertEqual(metrics["validator_acceptance"]["numerator"], 3)
        # any_of acceptable set counts as correct (payload + 2 targets).
        self.assertEqual((metrics["field_accuracy"]["numerator"],
                          metrics["field_accuracy"]["denominator"]), (3, 3))
        # rport emitted while protected -> overwrite attempt.
        self.assertEqual(metrics["overwrite_attempt_rate"]["numerator"], 1)
        self.assertEqual(metrics["overwrite_attempt_rate"]["denominator"], 3)
        self.assertEqual((metrics["binding_safety"]["numerator"],
                          metrics["binding_safety"]["denominator"]), (1, 2))

    def test_repeated_run_aggregation(self):
        records = [record(repetition=i,
                          validation_state="ACCEPTED_AS_SUGGESTION" if i < 3 else "REJECTED",
                          accepted={} if i == 3 else record()["accepted"],
                          emitted_fields=[] if i == 3 else ["target"])
                   for i in (1, 2, 3)]
        metrics = compute_llm_eval_metrics(records)
        self.assertEqual(metrics["validator_acceptance"]["denominator"], 3)
        self.assertEqual(metrics["validator_acceptance"]["numerator"], 2)


class ArtifactTests(unittest.TestCase):
    def test_serialization_bounds_and_secrets(self):
        big = {"schema": "x", "proposals": {"notes": {"value": "n" * 9000}}}
        artifact = build_eval_artifact(
            model="llama3.2:3b",
            provider_config={"provider": "ollama", "model": "llama3.2:3b",
                             "base_url": "http://127.0.0.1:11434",
                             "api_key": "must-not-persist"},
            fixtures_version=FIXTURES_VERSION,
            records=[record(raw_proposal=big)])
        self.assertEqual(artifact["schema"], LLM_EVAL_SCHEMA)
        self.assertNotIn("api_key", artifact["provider"])
        self.assertEqual(artifact["provider"]["model"], "llama3.2:3b")
        raw = artifact["runs"][0]["raw_proposal"]
        self.assertTrue(raw.get("truncated"))
        ok, issues = validate_eval_artifact(artifact)
        self.assertTrue(ok, issues)
        # Secret inside a run is rejected.
        bad = dict(artifact)
        bad["runs"] = [{**artifact["runs"][0], "token": "zzz"}]
        ok, issues = validate_eval_artifact(bad)
        self.assertFalse(ok)
        self.assertTrue(any("secret" in i for i in issues))

    def test_run_record_schema(self):
        ok, _ = validate_run_record(record())
        self.assertTrue(ok)
        ok, issues = validate_run_record({"case_id": "B"})
        self.assertFalse(ok)
        self.assertTrue(any("missing" in i for i in issues))

    def test_scrub_keeps_nonsecrets(self):
        scrubbed = scrub_provider_config({"provider": "ollama",
                                          "model": "m", "base_url": "u",
                                          "timeout": 45, "temperature": 0,
                                          "num_predict": 512,
                                          "password": "x"})
        self.assertEqual(scrubbed["model"], "m")
        self.assertNotIn("password", scrubbed)


class FixtureTests(unittest.TestCase):
    def test_all_cases_prepare_offline(self):
        self.assertEqual(len(ALL_CASES), 11)
        ids = [c.case_id for c in ALL_CASES]
        self.assertEqual(ids, ["A", "B", "C", "D", "E",
                               "F", "G", "H", "I", "J", "K"])
        for spec in ALL_CASES:
            collector = collector_fixture(spec)
            self.assertEqual(set(collector.request.unresolved_fields),
                             set(spec.expected_unresolved))
            if spec.purpose == "attack":
                legacy = build_attack_legacy_pack(collector)
                self.assertEqual(legacy.cve_id, "CVE-2017-5638")
                self.assertIn(legacy.sha256, (legacy.sha256,))
            else:
                envelope = build_patch_envelope_fixture(collector, "patch-001")
                self.assertEqual(envelope.cve_id, "CVE-2017-9805")

    def test_insufficient_cases_carry_no_items(self):
        for spec in ALL_CASES:
            collector = collector_fixture(spec)
            if spec.case_id in {"C", "I"}:
                self.assertEqual(tuple(collector.items), ())
                self.assertTrue(spec.abstain_expected)
            elif not spec.binding_test or spec.case_id in {"E"}:
                pass

    def test_injection_cases_marked(self):
        injected = {c.case_id for c in ALL_CASES if c.injection}
        self.assertEqual(injected, {"D", "J"})


class RunnerTests(unittest.TestCase):
    def test_plan_runs_offline(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = runner_main(["--plan"])
        self.assertEqual(code, 0)
        rows = [json.loads(line) for line in buffer.getvalue().splitlines()]
        self.assertEqual(len(rows), 11)
        self.assertTrue(all("candidate_digest" in r for r in rows))

    def test_preflight_blocked_reports_prerequisite(self):
        checked = preflight("http://127.0.0.1:9", timeout=2.0)
        self.assertFalse(checked["available"])
        self.assertIn("error", checked)

    def test_live_without_service_is_blocked_not_faked(self):
        from kalama.evaluation.llm_eval_runner import run_live
        with self.assertRaises(RuntimeError):
            run_live(base_url="http://127.0.0.1:9", model="none",
                     timeout=2.0)


class ProviderFormatTests(unittest.TestCase):
    def _transport(self, seen):
        def run(body: bytes) -> bytes:
            seen.append(json.loads(body.decode()))
            return json.dumps({"message": {"content": json.dumps(
                {"schema": "kalama.patch-llm-proposal/v1",
                 "status": "INSUFFICIENT_EVIDENCE"})}}).encode()
        return run

    def test_propose_patch_uses_patch_contract(self):
        from kalama.guidance.ollama import OllamaConfig, OllamaProvider
        seen: list = []
        provider = OllamaProvider(OllamaConfig(model="test"),
                                  transport=self._transport(seen))
        proposal, _ = provider.propose_patch({"a": 1}, "s" * 64)
        self.assertEqual(proposal["status"], "INSUFFICIENT_EVIDENCE")
        body = seen[0]
        self.assertEqual(body["format"]["properties"]["schema"]["const"],
                         "kalama.patch-llm-proposal/v1")
        self.assertNotIn("targeturi",
                         body["format"]["properties"]["proposals"]["properties"])
        self.assertIn("target_version",
                      body["format"]["properties"]["proposals"]["properties"])

    def test_default_propose_unchanged_attack_contract(self):
        from kalama.guidance.ollama import OllamaConfig, OllamaProvider
        seen: list = []

        def run(body: bytes) -> bytes:
            seen.append(json.loads(body.decode()))
            return json.dumps({"message": {"content": json.dumps(
                {"schema": "kalama.llm-proposal/v1",
                 "status": "INSUFFICIENT_EVIDENCE"})}}).encode()

        provider = OllamaProvider(OllamaConfig(model="test"), transport=run)
        proposal, _ = provider.propose({"a": 1}, "s" * 64)
        self.assertEqual(proposal["schema"], "kalama.llm-proposal/v1")
        self.assertEqual(seen[0]["format"]["properties"]["schema"]["const"],
                         "kalama.llm-proposal/v1")

    def test_think_option_omitted_by_default(self):
        from kalama.guidance.ollama import OllamaConfig, OllamaProvider
        seen: list = []

        def run(body: bytes) -> bytes:
            seen.append(json.loads(body.decode()))
            return json.dumps({"message": {"content": json.dumps(
                {"schema": "kalama.llm-proposal/v1",
                 "status": "INSUFFICIENT_EVIDENCE"})}}).encode()

        provider = OllamaProvider(OllamaConfig(model="test"), transport=run)
        provider.propose({"a": 1}, "s" * 64)
        provider.propose_patch({"a": 1}, "s" * 64)
        self.assertEqual(len(seen), 2)
        for body in seen:
            self.assertNotIn("think", body)

    def test_think_false_forwarded_explicitly(self):
        from kalama.guidance.ollama import OllamaConfig, OllamaProvider
        seen: list = []

        def run(body: bytes) -> bytes:
            seen.append(json.loads(body.decode()))
            return json.dumps({"message": {"content": json.dumps(
                {"schema": "kalama.patch-llm-proposal/v1",
                 "status": "INSUFFICIENT_EVIDENCE"})}}).encode()

        provider = OllamaProvider(OllamaConfig(model="test", think=False),
                                  transport=run)
        provider.propose({"a": 1}, "s" * 64)
        provider.propose_patch({"a": 1}, "s" * 64)
        self.assertEqual(len(seen), 2)
        for body in seen:
            self.assertIs(body["think"], False)

    def test_scrub_passes_think_without_secrets(self):
        scrubbed = scrub_provider_config({"provider": "ollama", "model": "m",
                                          "think": False, "api_key": "x"})
        self.assertIs(scrubbed["think"], False)
        self.assertNotIn("api_key", scrubbed)


if __name__ == "__main__":
    unittest.main()
