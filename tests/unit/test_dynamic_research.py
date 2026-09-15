"""Wave 4A research-export unit tests (fixtures are synthetic test data).

Covers one-row-per-candidate export, exact v1 copying, signal taxonomy,
BEFORE ground-truth mapping under existing evaluation policy, BEFORE-only
consumption, application-scope stratification, artifact integrity
rejection, determinism, JSON/CSV parity, and pipeline-state neutrality.
"""

from __future__ import annotations

import csv
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from kalama.dynamic_research import (
    RESEARCH_SCHEMA,
    ResearchExportError,
    build_research_dataset,
    dataset_metrics,
    dataset_to_csv,
    dynamic_scope_version,
    export_run,
    export_sha256,
    write_export,
)
from kalama.state import (
    ArtifactKind,
    ArtifactReference,
    PipelineStage,
    RunStatus,
    StageStatus,
    StateStore,
    TargetState,
)


NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
RUN = "rS1a2"

TOP_CVES = ("CVE-2017-5638", "CVE-2018-11776", "CVE-2021-44228", "CVE-2013-2251")


def _top_entry(rank: int, cve: str) -> dict:
    return {
        "rank": rank, "cve_id": cve,
        "score": {"model": "kalama-priority-v1", "total_display": str(20 - rank),
                  "total_raw": f"{20 - rank}.0",
                  "components": {"cvss": "9.0"}},
        "cvss": {"authority": "nvd", "score": "9.0", "version": "3.1",
                 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "state": "AVAILABLE"},
        "epss": {"score": "0.5", "percentile": "0.9", "state": "AVAILABLE",
                 "source": "FIRST"},
        "kev": {"listed": rank == 1, "state": "LISTED" if rank == 1 else "NOT_LISTED"},
        "exposure": {"classification": "TARGET_CONTEXT_ONLY", "score": None,
                     "state": "UNKNOWN"},
        "occurrences": [{
            "canonical_cve_id": cve, "package_name": "org.example:lib",
            "package_purl": "pkg:maven/org.example/lib@1.0",
            "installed_version": "1.0", "fixed_versions": ["1.1"],
            "data_source": {"ID": "ghsa", "Name": "GitHub Security Advisory Maven"}}],
        "scanner_context": [{"severity": "CRITICAL", "source": "ghsa"}],
    }


def _write(path: Path, document: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
               + "\n").encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


class ResearchFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "output")
        state = self.store.create("example/image:1", now=NOW,
                                  run_id_generator=lambda: RUN)
        facts = {"run_id": RUN, "container_name": f"victim-{RUN}",
                 "container_id": "victim-container-1", "network": "kalama-net",
                 "ip_address": "172.18.0.9",
                 "requested_image_reference": "example/image:1",
                 "image_id": "sha256:abc", "image_digest": "example/image@sha256:abc"}
        state = self.store.load(RUN)
        state = replace(state, target=TargetState({}, facts),
                        status=RunStatus.PAUSED,
                        current_stage=PipelineStage.STEP_4_RESOLVER,
                        updated_at="2026-09-11T12:00:01Z")
        self.store.save(state)
        self.top30_path = self.root / "scoring" / "before" / f"top30_2026-09-11_{RUN}.json"
        top_doc = {
            "schema": "kalama.prioritization/v1",
            "artifact": {"kind": "before_top_cves", "run_id": RUN, "phase": "before",
                         "created_at": "2026-09-11T11:43:32Z",
                         "top_n_requested": 4, "top_n_returned": 4},
            "score_model": {"id": "kalama-priority-v1"},
            "ranked_cves": [_top_entry(index + 1, cve)
                            for index, cve in enumerate(TOP_CVES)],
        }
        top_sha = _write(self.top30_path, top_doc)
        self._attach(ArtifactKind.TOP30_BEFORE, self.top30_path, top_sha,
                     "kalama.prioritization/v1", "2026-09-11T11:43:32Z")
        self.shadow_dir = self.root / "output" / "dynamic" / "before" / RUN
        self._write_shadow()
        self._write_attack(include_after_decoy=True)
        state = self.store.load(RUN)
        self.state_before = (self.store.path_for(RUN)).read_bytes()

    # -- fixture builders -------------------------------------------------
    def _attach(self, kind: ArtifactKind, path: Path, sha: str, schema: str,
                created_at: str) -> None:
        state = self.store.load(RUN)
        state = state.with_artifact(ArtifactReference(
            kind, str(path.resolve()), sha, schema, created_at,
            PipelineStage.STEP_3_PRIORITIZATION, ()), created_at)
        self.store.save(state)

    def _result_record(self, cve: str, template: str, base: str,
                       matches: int, raw_body: bytes) -> None:
        raw_name = (f"dynamic_nuclei_{RUN}_attempt_1_{cve}_{template}"
                    + ("" if base == "/" else "_" + base.strip("/").replace("/", "_") + "_")
                    + ".jsonl")
        raw_path = self.shadow_dir / raw_name
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_bytes(raw_body)
        manifest_name = "dynamic_nuclei_result_" + raw_name[len("dynamic_nuclei_"):-len(".jsonl")] + ".json"
        record = {
            "schema": "kalama.dynamic-result/v1", "run_id": RUN, "attempt": "1",
            "candidate_cve": cve, "template_id": template, "base_path": base,
            "execution_status": "SUCCEEDED", "reachable": True,
            "match_count": matches,
            "container_id": "victim-container-1",
            "endpoint": {"container_id": "victim-container-1", "scheme": "http",
                         "port": 8080},
            "template_sha256": "t-sha",
            "template_manifest": {"sha256": "manifest-sha"},
            "raw_artifact": {"path": str(raw_path),
                             "sha256": hashlib.sha256(raw_body).hexdigest()},
        }
        _write(self.shadow_dir / manifest_name, record)

    def _write_shadow(self) -> None:
        self._result_record("CVE-2017-5638", "t1", "/", 0, b"")
        self._result_record("CVE-2017-5638", "t1", "/app/", 1, b'{"match": true}\n')
        self._result_record("CVE-2018-11776", "t2", "/", 0, b"")

        def candidate(rank: int, cve: str, signal: str, templates: list,
                      bindings: list, refs: list) -> dict:
            return {
                "rank": rank, "cve_id": cve, "score": {"total_display": "x"},
                "applicable_templates": templates,
                "applicable_bindings": bindings, "signal": signal,
                "dynamic_validation": {
                    "provider": "nuclei", "profile": "safe-cve-http",
                    "signal": signal, "score_delta": 0,
                    "evidence_refs": ([{"path": "ev-path", "sha256": "ev-sha"}]
                                      if signal == "CORROBORATED" else []),
                    "execution_refs": refs},
            }

        def ref(template: str, base: str, status: str) -> dict:
            source = ("default_root" if base == "/"
                      else "explicit_reviewed_binding")
            return {"attempt": 1, "template_id": template, "base_path": base,
                    "base_path_source": source, "status": status,
                    "reused": False, "error_code": None}

        doc = {
            "schema": "kalama.dynamic-shadow/v1",
            "artifact": {"kind": "dynamic_shadow_before", "run_id": RUN,
                         "phase": "before", "attempt": 1,
                         "created_at": "2026-09-11T11:43:37Z",
                         "candidate_universe": "top_n", "top_n": 4},
            "inputs": {"application_endpoints": [
                {"base_path": "/", "base_path_source": "default_root",
                 "application_endpoint_key": "k-root"},
                {"base_path": "/app/", "base_path_source": "explicit_reviewed_binding",
                 "application_endpoint_key": "k-app"}]},
            "priority_v1": {"score_model": "kalama-priority-v1",
                            "top30_sha256": "top-sha", "unchanged": True},
            "candidates": [
                candidate(1, "CVE-2017-5638", "CORROBORATED", ["t1"],
                          [{"template_id": "t1", "base_path": "/",
                            "base_path_source": "default_root"},
                           {"template_id": "t1", "base_path": "/app/",
                            "base_path_source": "explicit_reviewed_binding"}],
                          [ref("t1", "/", "SUCCEEDED"), ref("t1", "/app/", "SUCCEEDED")]),
                candidate(2, "CVE-2018-11776", "NOT_OBSERVED", ["t2"],
                          [{"template_id": "t2", "base_path": "/",
                            "base_path_source": "default_root"}],
                          [ref("t2", "/", "SUCCEEDED")]),
                candidate(3, "CVE-2021-44228", "NOT_APPLICABLE", [], [], []),
                candidate(4, "CVE-2013-2251", "INCONCLUSIVE", ["t3"],
                          [{"template_id": "t3", "base_path": "/",
                            "base_path_source": "default_root"}],
                          [ref("t3", "/", "FAILED")]),
            ],
            "notices": [],
        }
        path = self.shadow_dir / f"dynamic_shadow_{RUN}_attempt_1.json"
        sha = _write(path, doc)
        self._attach(ArtifactKind.DYNAMIC_SHADOW_BEFORE, path, sha,
                     "kalama.dynamic-shadow/v1", "2026-09-11T11:43:37Z")

    def _attack_entry(self, rank: int, cve: str, disposition: str,
                      eligible: bool, exclusion: str | None,
                      verdict: str, config_status: str = "READY_TO_EXECUTE") -> dict:
        entry: dict = {
            "rank": rank, "cve_id": cve, "config_status": config_status,
            "disposition": disposition, "attempt": None,
            "oracle": {"verdict": verdict},
            "metric_eligibility": {"eligible": eligible,
                                   "exclusion_reason": exclusion},
        }
        if eligible:
            entry["attempt"] = {"attempt_id": f"{RUN}-{rank:02d}-before-1"}
        return entry

    def _write_attack(self, *, include_after_decoy: bool) -> None:
        doc = {
            "schema": "kalama.attack-result/v1",
            "artifact": {"run_id": RUN, "phase": "before",
                         "created_at": "2026-09-11T12:30:00Z"},
            "summary": {"selected": 4},
            "cves": [
                self._attack_entry(1, "CVE-2017-5638", "EXPLOIT_SUCCEEDED",
                                   True, None, "VULNERABLE"),
                self._attack_entry(2, "CVE-2018-11776", "EXPLOIT_FAILED",
                                   True, None, "NOT_VULNERABLE"),
                self._attack_entry(4, "CVE-2013-2251", "INCONCLUSIVE",
                                   False, "PRECONDITION_FAILED", "INCONCLUSIVE"),
            ],
        }
        path = self.root / "msf" / "before" / f"attack_res_2026-09-11_{RUN}.json"
        sha = _write(path, doc)
        self._attach(ArtifactKind.ATTACK_BEFORE, path, sha,
                     "kalama.attack-result/v1", "2026-09-11T12:30:00Z")
        if include_after_decoy:
            # AFTER-phase evidence must never leak into BEFORE research rows.
            decoy = {
                "schema": "kalama.attack-result/v1",
                "artifact": {"run_id": RUN, "phase": "after",
                             "created_at": "2026-09-11T13:30:00Z"},
                "summary": {"selected": 1},
                "cves": [self._attack_entry(1, "CVE-2017-5638", "EXPLOIT_FAILED",
                                            True, None, "NOT_VULNERABLE")],
            }
            decoy_path = self.root / "msf" / "after" / f"attack_res_2026-09-11_{RUN}.json"
            decoy_sha = _write(decoy_path, decoy)
            self._attach(ArtifactKind.ATTACK_AFTER, decoy_path, decoy_sha,
                         "kalama.attack-result/v1", "2026-09-11T13:30:00Z")

    def _export(self):
        from kalama.dynamic_research import export_run
        return export_run(self.root / "output", RUN,
                          now=datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc))


class ExportShapeTests(ResearchFixture):
    def test_one_row_per_candidate_all_exported(self):
        dataset = self._export()
        self.assertEqual(dataset["schema"], RESEARCH_SCHEMA)
        self.assertEqual(dataset["run_id"], RUN)
        self.assertEqual(len(dataset["rows"]), 4)
        self.assertEqual([row["canonical_cve"] for row in dataset["rows"]],
                         list(TOP_CVES))
        self.assertEqual([row["rank"] for row in dataset["rows"]], [1, 2, 3, 4])
        signals = {row["canonical_cve"]: row["dynamic"]["signal"]
                   for row in dataset["rows"]}
        self.assertEqual(signals, {
            "CVE-2017-5638": "CORROBORATED", "CVE-2018-11776": "NOT_OBSERVED",
            "CVE-2021-44228": "NOT_APPLICABLE", "CVE-2013-2251": "INCONCLUSIVE"})

    def test_ranking_and_scores_copied_exactly(self):
        dataset = self._export()
        for row in dataset["rows"]:
            expected = _top_entry(row["rank"], row["canonical_cve"])
            self.assertEqual(row["priority_v1"]["score_display"],
                             expected["score"]["total_display"])
            self.assertEqual(row["priority_v1"]["score_raw"],
                             expected["score"]["total_raw"])
            self.assertEqual(row["priority_v1"]["score_components"],
                             expected["score"]["components"])
            self.assertEqual(row["priority_v1"]["cvss"], expected["cvss"])
            self.assertEqual(row["priority_v1"]["epss"], expected["epss"])
            self.assertEqual(row["priority_v1"]["kev"], expected["kev"])
            self.assertEqual(row["priority_v1"]["exposure"], expected["exposure"])

    def test_dynamic_taxonomy_preserved(self):
        dataset = self._export()
        by_cve = {row["canonical_cve"]: row for row in dataset["rows"]}
        self.assertTrue(by_cve["CVE-2017-5638"]["research"]["dynamic_positive"])
        self.assertFalse(by_cve["CVE-2018-11776"]["research"]["dynamic_positive"])
        self.assertFalse(by_cve["CVE-2021-44228"]["research"]["dynamic_positive"])
        for row in dataset["rows"]:
            self.assertEqual(row["dynamic"]["score_delta"], 0)
        corroborated = by_cve["CVE-2017-5638"]["dynamic"]
        self.assertEqual(corroborated["approved_template_count"], 1)
        self.assertEqual(corroborated["executed_binding_count"], 2)
        self.assertEqual(corroborated["matched_binding_count"], 1)
        self.assertEqual(corroborated["clean_binding_count"], 1)
        self.assertEqual(corroborated["incomplete_binding_count"], 0)
        self.assertEqual(len(corroborated["evidence_refs"]), 1)

    def test_ground_truth_mapping_follows_evaluation_policy(self):
        dataset = self._export()
        by_cve = {row["canonical_cve"]: row for row in dataset["rows"]}
        succeeded = by_cve["CVE-2017-5638"]["before_exploit"]
        self.assertTrue(succeeded["available"])
        self.assertEqual(succeeded["disposition"], "EXPLOIT_SUCCEEDED")
        self.assertEqual(succeeded["oracle_verdict"], "VULNERABLE")
        self.assertTrue(succeeded["metric_eligible"])
        self.assertIsNone(succeeded["exclusion_reason"])
        failed = by_cve["CVE-2018-11776"]["before_exploit"]
        self.assertEqual(failed["disposition"], "EXPLOIT_FAILED")
        absent = by_cve["CVE-2021-44228"]["before_exploit"]
        self.assertFalse(absent["available"])
        self.assertIsNone(absent["disposition"])
        inconclusive = by_cve["CVE-2013-2251"]["before_exploit"]
        self.assertEqual(inconclusive["disposition"], "INCONCLUSIVE")
        self.assertFalse(inconclusive["metric_eligible"])
        self.assertEqual(inconclusive["exclusion_reason"], "PRECONDITION_FAILED")
        research = {cve: rows["research"] for cve, rows in by_cve.items()}
        self.assertTrue(research["CVE-2017-5638"]["exploit_positive"])
        self.assertFalse(research["CVE-2018-11776"]["exploit_positive"])
        self.assertIsNone(research["CVE-2021-44228"]["exploit_positive"])
        self.assertIsNone(research["CVE-2013-2251"]["exploit_positive"])
        self.assertFalse(research["CVE-2013-2251"]["eligible"])

    def test_after_phase_evidence_never_consumed(self):
        dataset = self._export()
        by_cve = {row["canonical_cve"]: row for row in dataset["rows"]}
        # The AFTER decoy claims EXPLOIT_FAILED; the BEFORE row must keep
        # the genuine BEFORE EXPLOIT_SUCCEEDED disposition.
        self.assertEqual(by_cve["CVE-2017-5638"]["before_exploit"]["disposition"],
                         "EXPLOIT_SUCCEEDED")
        self.assertTrue(by_cve["CVE-2017-5638"]["research"]["exploit_positive"])

    def test_application_scope_stratification(self):
        dataset = self._export()
        by_cve = {row["canonical_cve"]: row for row in dataset["rows"]}
        dynamic = by_cve["CVE-2017-5638"]["dynamic"]
        self.assertEqual(dynamic["scope_version"], "v2-multi-path")
        self.assertEqual(dynamic["application_paths"], ["/", "/app/"])
        self.assertEqual(dynamic["matched_paths"], ["/app/"])
        self.assertEqual(dynamic["path_sources"],
                         {"/": "default_root",
                          "/app/": "explicit_reviewed_binding"})
        self.assertEqual(dynamic_scope_version(None, []), "none")
        self.assertEqual(dynamic_scope_version({"candidates": [], "inputs": {}}, []),
                         "v1-root-only-legacy")
        self.assertEqual(dynamic_scope_version(
            {"candidates": [],
             "inputs": {"application_endpoints": [{"base_path": "/"}]}}, []),
            "v2-root-only")

    def test_temporal_proof_recorded(self):
        dataset = self._export()
        temporal = dataset["temporal"]
        self.assertTrue(temporal["before_phase_only"])
        self.assertTrue(temporal["temporal_order_ok"])
        self.assertEqual(temporal["observed_order"], ["top30", "shadow", "attack"])
        self.assertLess(temporal["top30_created_at"], temporal["shadow_created_at"])
        self.assertLess(temporal["shadow_created_at"], temporal["attack_created_at"])

    def test_artifact_provenance_present(self):
        dataset = self._export()
        sources = dataset["sources"]
        for key in ("top30", "dynamic_shadow", "attack_before"):
            self.assertIn("sha256", sources[key])
        row = dataset["rows"][0]
        self.assertEqual(row["run"]["priority_v1_sha256"],
                         sources["top30"]["sha256"])
        refs = row["dynamic"]["execution_refs"]
        self.assertEqual(len(refs), 2)
        for ref in refs:
            self.assertTrue(Path(ref["result_path"]).is_file())
            self.assertTrue(Path(ref["raw_path"]).is_file())
        self.assertTrue(row["dynamic"]["evidence_refs"])


class IntegrityRejectionTests(ResearchFixture):
    def test_tampered_artifact_rejected(self):
        with self.top30_path.open("ab") as handle:
            handle.write(b"tampered")
        with self.assertRaises(ResearchExportError) as caught:
            self._export()
        self.assertEqual(caught.exception.code, "RESEARCH_ARTIFACT_TAMPERED")

    def test_wrong_run_dynamic_evidence_rejected(self):
        path = self.shadow_dir / f"dynamic_shadow_{RUN}_attempt_1.json"
        document = json.loads(path.read_bytes())
        document["artifact"]["run_id"] = "WR0NG"
        path.write_bytes((json.dumps(document, sort_keys=True) + "\n").encode())
        # State ref hash must be refreshed so the failure is run identity,
        # not tampering.
        state = self.store.load(RUN)
        from kalama.state import ArtifactKind as Kind
        refs = []
        for ref in state.artifacts:
            if ref.kind == Kind.DYNAMIC_SHADOW_BEFORE:
                import hashlib as _hashlib
                refs.append(replace(
                    ref, path=str(path.resolve()),
                    sha256=_hashlib.sha256(path.read_bytes()).hexdigest()))
            else:
                refs.append(ref)
        state = replace(state, artifacts=tuple(refs))
        self.store.save(state)
        with self.assertRaises(ResearchExportError) as caught:
            self._export()
        self.assertEqual(caught.exception.code, "RESEARCH_WRONG_RUN")


class MetricsTests(ResearchFixture):
    def test_coverage_and_crosstab(self):
        dataset = self._export()
        metrics = dataset["metrics"]
        self.assertEqual(metrics["candidate_total"], 4)
        self.assertEqual(metrics["signal_counts"],
                         {"CORROBORATED": 1, "INCONCLUSIVE": 1,
                          "NOT_APPLICABLE": 1, "NOT_OBSERVED": 1})
        # INCONCLUSIVE counts as applicable here: approved templates exist.
        self.assertEqual(metrics["dynamic_applicable_count"], 3)
        self.assertAlmostEqual(metrics["dynamic_coverage_rate"], 0.75)
        cross = metrics["signal_by_disposition"]
        self.assertEqual(cross["CORROBORATED"], {"EXPLOIT_SUCCEEDED": 1})
        self.assertEqual(cross["NOT_OBSERVED"], {"EXPLOIT_FAILED": 1})
        self.assertEqual(cross["NOT_APPLICABLE"],
                         {"GROUND_TRUTH_UNAVAILABLE": 1})
        self.assertEqual(cross["INCONCLUSIVE"], {"INCONCLUSIVE": 1})
        proportions = metrics["conditional_proportions"]
        self.assertEqual(proportions["CORROBORATED"]["numerator"], 1)
        self.assertEqual(proportions["CORROBORATED"]["denominator"], 1)
        self.assertEqual(proportions["CORROBORATED"]["value"], 1.0)
        self.assertEqual(proportions["CORROBORATED"]["kind"],
                         "descriptive_empirical_proportion")
        self.assertIsNone(proportions["NOT_APPLICABLE"]["value"])
        self.assertEqual(metrics["binding_totals"]["matched"], 1)
        self.assertEqual(metrics["exploit_positive_total"], 1)
        self.assertEqual(metrics["eligible_total"], 2)

    def test_metrics_are_descriptive_only(self):
        metrics = dataset_metrics([])
        self.assertEqual(metrics["candidate_total"], 0)
        self.assertIsNone(metrics["dynamic_coverage_rate"])
        self.assertNotIn("weights", metrics)
        self.assertNotIn("ranking", metrics)


class SerializationTests(ResearchFixture):
    def test_json_csv_parity_and_determinism(self):
        first = self._export()
        second = self._export()
        self.assertEqual(first["export_sha256"], second["export_sha256"])
        self.assertEqual(export_sha256(first), first["export_sha256"])
        csv_text = dataset_to_csv(first)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        self.assertEqual(len(rows), len(first["rows"]))
        by_cve = {row["canonical_cve"]: row for row in first["rows"]}
        csv_by_cve = {row["canonical_cve"]: row for row in rows}
        self.assertEqual(set(csv_by_cve), set(by_cve))
        corroborated = csv_by_cve["CVE-2017-5638"]
        self.assertEqual(corroborated["dynamic_signal"], "CORROBORATED")
        self.assertEqual(corroborated["before_disposition"], "EXPLOIT_SUCCEEDED")
        self.assertEqual(corroborated["exclusion_reason"], "")
        self.assertEqual(corroborated["dynamic_scope_version"], "v2-multi-path")
        self.assertEqual(csv_by_cve["CVE-2013-2251"]["exclusion_reason"],
                         "PRECONDITION_FAILED")
        self.assertEqual(csv_by_cve["CVE-2013-2251"]["before_disposition"],
                         "INCONCLUSIVE")

    def test_write_export_pair(self):
        dataset = self._export()
        out = self.root / "research"
        paths = write_export(dataset, out)
        self.assertTrue(Path(paths["json"]).is_file())
        self.assertTrue(Path(paths["csv"]).is_file())
        reloaded = json.loads(Path(paths["json"]).read_bytes())
        self.assertEqual(reloaded["export_sha256"], dataset["export_sha256"])
        self.assertEqual(len(reloaded["rows"]), 4)

    def test_pipeline_state_untouched_and_v1_sha_stable(self):
        top_before = self.top30_path.read_bytes()
        self._export()
        self.assertEqual(self.top30_path.read_bytes(), top_before)
        self.assertEqual((self.store.path_for(RUN)).read_bytes(), self.state_before)


if __name__ == "__main__":
    unittest.main()
