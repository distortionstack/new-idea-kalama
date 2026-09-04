import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.integration import test_before_exploit as task4
from tests.integration import test_reexploit as task7
from kalama.evaluation.metrics import (
    FULL_EMPIRICAL_UNIVERSE, TOP_N_ONLY, compute_metrics,
)
from kalama.evaluation.orchestrator import EvaluationOrchestrator
from kalama.state.models import ArtifactKind, PipelineStage, RunStatus, StageStatus


NOW = task7.NOW


def record(index, confusion=None, *, eligible=True, selected=True, exclusion=None,
           disposition=None, remediation=None, scan=None):
    actual = True if confusion in {"TP", "FN"} else False if confusion in {"FP", "TN"} else None
    return {"cve_id": f"CVE-2099-{index:04d}",
        "prediction": {"selected_top_n": selected},
        "empirical_before": {"disposition": disposition or (
            "EXPLOIT_SUCCEEDED" if actual is True else "EXPLOIT_FAILED" if actual is False else exclusion),
            "metric_eligible": eligible},
        "binary_evaluation": {"eligible": eligible, "predicted_positive": selected,
            "actual_positive": actual, "confusion_class": confusion if eligible else None},
        "exclusion_reason": exclusion, "metasploit": {"module_available": exclusion != "NO_MSF_MODULE"},
        "remediation": {"after_scan_status": scan,
            "after_exploit_disposition": None, "final_remediation_status": remediation}}


def dataset(records, scope=TOP_N_ONLY, top_n=None):
    selected = sum(item["prediction"]["selected_top_n"] for item in records)
    return {"evaluation_universe": {"scope": scope,
            "candidate_universe_available": scope == FULL_EMPIRICAL_UNIVERSE,
            "candidate_universe_total": len(records) if scope == FULL_EMPIRICAL_UNIVERSE else None},
        "prediction": {"top_n_requested": top_n or selected, "top_n_returned": selected},
        "records": records}


class MetricTests(unittest.TestCase):
    def test_top_n_precision_exclusions_and_unobservable_recall(self):
        records = [record(i, "TP") for i in range(1, 13)]
        records += [record(i, "FP") for i in range(13, 18)]
        records += [record(18, eligible=False, exclusion="NO_MSF_MODULE"),
                    record(19, eligible=False, exclusion="ENVIRONMENT_ERROR"),
                    record(20, eligible=False, exclusion="UNRESOLVED_CONFIG"),
                    record(21, eligible=False, exclusion="CHECK_ONLY")]
        metrics = compute_metrics(dataset(records, top_n=30))
        prior = metrics["prioritization"]
        self.assertEqual(prior["confusion_matrix"], {"tp": 12, "fp": 5,
                                                      "fn": None, "tn": None})
        self.assertAlmostEqual(prior["precision"]["value"], 12 / 17)
        self.assertEqual(prior["precision"]["name"], "Precision@21")
        self.assertFalse(prior["recall"]["available"])
        self.assertIsNone(prior["recall"]["value"])
        self.assertEqual(prior["recall"]["reason"],
                         "PREDICTED_NEGATIVES_NOT_EMPIRICALLY_EVALUATED")
        self.assertFalse(prior["f1"]["available"])
        self.assertEqual(metrics["coverage"]["selected_binary_metric_eligible"], 17)
        self.assertEqual(metrics["exclusions"], {"CHECK_ONLY": 1, "ENVIRONMENT_ERROR": 1,
                                                  "NO_MSF_MODULE": 1,
                                                  "UNRESOLVED_CONFIG": 1})

    def test_metric_ineligible_apparent_failure_and_zero_denominator(self):
        value = record(1, eligible=False, exclusion="SESSION_EVIDENCE_UNAVAILABLE",
                       disposition="EXPLOIT_FAILED")
        metrics = compute_metrics(dataset([value]))
        self.assertEqual(metrics["prioritization"]["confusion_matrix"]["fp"], 0)
        self.assertFalse(metrics["prioritization"]["precision"]["available"])
        self.assertIsNone(metrics["prioritization"]["precision"]["value"])

    def test_full_universe_metrics_and_mathematical_zero_f1(self):
        records = [record(1, "TP"), record(2, "FP"),
                   record(3, "FN", selected=False), record(4, "TN", selected=False)]
        metrics = compute_metrics(dataset(records, FULL_EMPIRICAL_UNIVERSE))
        self.assertEqual(metrics["prioritization"]["confusion_matrix"],
                         {"tp": 1, "fp": 1, "fn": 1, "tn": 1})
        self.assertEqual(metrics["prioritization"]["precision"]["value"], .5)
        self.assertEqual(metrics["prioritization"]["recall"]["value"], .5)
        self.assertEqual(metrics["prioritization"]["f1"]["value"], .5)
        zero = compute_metrics(dataset([
            record(1, "FP"), record(2, "FN", selected=False)], FULL_EMPIRICAL_UNIVERSE))
        self.assertTrue(zero["prioritization"]["f1"]["available"])
        self.assertEqual(zero["prioritization"]["f1"]["value"], 0.0)

    def test_remediation_denominator_and_cross_tab(self):
        records = [record(i, "TP", remediation="VERIFIED", scan="NOT_FOUND") for i in range(1, 10)]
        records += [record(10, "TP", remediation="FAILED", scan="NOT_FOUND"),
                    record(11, "TP", remediation="INCONCLUSIVE", scan="FOUND"),
                    record(12, "TP", remediation="INCONCLUSIVE", scan="UNKNOWN")]
        remediation = compute_metrics(dataset(records))["remediation"]
        self.assertEqual(remediation["empirical_success_rate"]["value"], .9)
        self.assertEqual(remediation["evaluation_coverage"], 10 / 12)
        self.assertEqual(remediation["scanner_empirical_cross_tab"], {
            "FOUND+INCONCLUSIVE": 1, "NOT_FOUND+FAILED": 1,
            "NOT_FOUND+VERIFIED": 9, "UNKNOWN+INCONCLUSIVE": 1})


class EvaluationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = task7.ReexploitTests()
        self.fixture.setUp()
        self.store = self.fixture.store
        self.step8 = self.fixture.orchestrate(
            task4.FakeMsf(sessions=(("existing",), ("existing",))))
        self.upstream = {item.kind: item.sha256 for item in self.step8.artifacts}

    def tearDown(self):
        self.fixture.tearDown()

    def test_dataset_drives_metrics_summary_and_completion(self):
        state = EvaluationOrchestrator(self.store, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertEqual(state.stage(PipelineStage.STEP_8_EVALUATION).status,
                         StageStatus.SUCCEEDED)
        self.assertIsNone(state.waiting_reason)
        for kind in (ArtifactKind.EVALUATION_DATASET, ArtifactKind.EVALUATION_METRICS,
                     ArtifactKind.RUN_SUMMARY):
            self.assertIsNotNone(state.artifact(kind))
        dataset_value = json.loads(Path(state.artifact(
            ArtifactKind.EVALUATION_DATASET).path).read_bytes())
        metrics_value = json.loads(Path(state.artifact(
            ArtifactKind.EVALUATION_METRICS).path).read_bytes())
        self.assertEqual(dataset_value["evaluation_universe"]["scope"], "TOP_N_ONLY")
        self.assertEqual(compute_metrics(dataset_value), {
            key: metrics_value[key] for key in ("prioritization", "coverage", "exclusions",
                                                 "metasploit_coverage", "remediation")})
        self.assertEqual(metrics_value["prioritization"]["confusion_matrix"],
                         {"tp": 1, "fp": 0, "fn": None, "tn": None})
        self.assertIsNone(metrics_value["prioritization"]["recall"]["value"])
        summary = json.loads(Path(state.artifact(ArtifactKind.RUN_SUMMARY).path).read_bytes())
        self.assertEqual(summary["stages"]["STEP_8_EVALUATION"], "SUCCEEDED")
        self.assertIn("EVALUATION_DATASET", summary["artifact_index"])
        self.assertIn("EVALUATION_METRICS", summary["artifact_index"])
        for kind, digest in self.upstream.items():
            self.assertEqual(state.artifact(kind).sha256, digest)

    def test_metrics_failure_preserves_dataset_and_prevents_completion(self):
        with patch("kalama.evaluation.orchestrator.write_evaluation_metrics",
                   side_effect=OSError("replace failed")):
            state = EvaluationOrchestrator(self.store, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(state.artifact(ArtifactKind.EVALUATION_DATASET))
        self.assertIsNone(state.artifact(ArtifactKind.EVALUATION_METRICS))
        self.assertIsNone(state.artifact(ArtifactKind.RUN_SUMMARY))

    def test_dataset_failure_commits_no_evaluation_artifact(self):
        with patch("kalama.evaluation.orchestrator.write_evaluation_dataset",
                   side_effect=OSError("replace failed")):
            state = EvaluationOrchestrator(self.store, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNone(state.artifact(ArtifactKind.EVALUATION_DATASET))
        self.assertIsNone(state.artifact(ArtifactKind.EVALUATION_METRICS))
        self.assertIsNone(state.artifact(ArtifactKind.RUN_SUMMARY))

    def test_summary_failure_preserves_dataset_and_metrics(self):
        with patch("kalama.evaluation.orchestrator.write_run_summary",
                   side_effect=OSError("replace failed")):
            state = EvaluationOrchestrator(self.store, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(state.artifact(ArtifactKind.EVALUATION_DATASET))
        self.assertIsNotNone(state.artifact(ArtifactKind.EVALUATION_METRICS))
        self.assertIsNone(state.artifact(ArtifactKind.RUN_SUMMARY))


if __name__ == "__main__":
    unittest.main()
