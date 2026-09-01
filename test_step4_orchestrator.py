import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from resolver_core import DiscoveryBackend

from src.app.kalama.resolution.models import (
    ResolverCVEResult, ResolverCVEStatus, Step4Analysis,
)
from src.app.kalama.resolution.orchestrator import (
    ResolverOrchestrator, Step4OrchestrationError, production_step4_processor,
)
from src.app.kalama.resolution.models import RankedCVEInput
from src.app.kalama.resolution.resolver_stage import analyze_cves, target_facts_from_state
from src.app.kalama.state.models import (
    ArtifactKind, ArtifactReference, PipelineStage, RunStatus, StageStatus, TargetState,
)
from src.app.kalama.state.store import StateStore


NOW = datetime(2026, 8, 31, 9, 30, tzinfo=timezone.utc)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def backend(*, candidates=None, live=None):
    return DiscoveryBackend(
        load_cache=lambda: {"present": True},
        find_from_cache=lambda _cache, _cve: candidates or {},
        search_live=lambda _cve, _container: [],
        query_modules=lambda _names, _container: live or {},
        cache_description="test-cache",
    )


class Step4OrchestrationTests(unittest.TestCase):
    def test_complete_port_facts_and_same_network_msf_ip_reach_config(self):
        raw = {"container_name": "victim-aB3x9", "network": "kalama-net",
               "ip_address": "172.20.0.3",
               "exposed_ports": [{"container_port": 80, "protocol": "tcp"}],
               "listening_ports": [{"container_port": 8080, "protocol": "tcp",
                                     "address": "0.0.0.0"}],
               "published_ports": [{"container_port": 8080, "host_port": 18080,
                                     "protocol": "tcp"}],
               "reachable_ports": [8080]}
        facts = target_facts_from_state("aB3x9", raw)
        self.assertEqual([x.port for x in facts.exposed_ports], [80])
        self.assertEqual([x.port for x in facts.observed_ports], [8080])
        self.assertEqual([x.port for x in facts.reachable_ports], [8080])
        selected_networks = []
        candidate = {"exploit/a": {"rank": "excellent", "check_supported": True}}
        live = {"exploit/a": {"options": []}}
        resolver_backend = backend(candidates=candidate, live=live)
        resolver_backend = replace(resolver_backend, resolve_msf_ip=lambda container, network: (
            selected_networks.append((container, network)) or "172.20.0.5"))
        analysis = analyze_cves((RankedCVEInput(1, "CVE-2099-0001", ()),), facts,
                                resolver_backend, "msf-resolver-host")
        self.assertEqual(selected_networks, [("msf-resolver-host", "kalama-net")])
        lhost = analysis.cves[0].exploit_config.environment.lhost
        self.assertEqual(lhost.suggested_value, "172.20.0.5")
        self.assertFalse(lhost.confirmed)

    def test_unrelated_network_ip_is_never_requested_or_selected(self):
        facts = target_facts_from_state("aB3x9", {"network": "kalama-net"})
        resolver_backend = backend(candidates={"exploit/a": {}},
                                   live={"exploit/a": {"options": []}})
        resolver_backend = replace(resolver_backend,
                                   resolve_msf_ip=lambda _container, network: (
                                       "10.99.0.5" if network == "unrelated" else None))
        analysis = analyze_cves((RankedCVEInput(1, "CVE-2099-0001", ()),), facts,
                                resolver_backend, "msf-resolver-host")
        self.assertIsNone(analysis.cves[0].exploit_config.environment.lhost.suggested_value)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, cves=("CVE-2099-0001",)):
        state = self.store.create("victim:test", now=NOW, run_id_generator=lambda: "aB3x9")
        top = self.root / "scoring" / "before" / "top30_2026-08-31_aB3x9.json"
        top.parent.mkdir(parents=True)
        document = {
            "schema": "kalama.prioritization/v1",
            "artifact": {"run_id": "aB3x9", "phase": "before", "created_at": "2026-08-31T09:30:00Z"},
            "ranked_cves": [{"rank": i, "cve_id": cve, "occurrences": [{"package": "demo"}]}
                             for i, cve in enumerate(cves, 1)],
        }
        top.write_text(json.dumps(document), encoding="utf-8")
        reference = ArtifactReference(
            ArtifactKind.TOP30_BEFORE, str(top), digest(top), "kalama.prioritization/v1",
            "2026-08-31T09:30:00Z", PipelineStage.STEP_3_PRIORITIZATION,
        )
        state = state.with_stage(PipelineStage.STEP_2_TARGET_SCAN, StageStatus.SUCCEEDED,
                                 "2026-08-31T09:30:00Z")
        state = state.with_stage(PipelineStage.STEP_3_PRIORITIZATION, StageStatus.SUCCEEDED,
                                 "2026-08-31T09:30:00Z")
        state = state.with_artifact(reference, "2026-08-31T09:30:00Z")
        facts = {"run_id": "aB3x9", "container_name": "victim-aB3x9",
                 "container_id": "cid", "requested_image_reference": "victim:test",
                 "image_id": "sha256:image", "image_digest": "sha256:digest",
                 "network": "kalama-net", "ip_address": "172.18.0.3",
                 "listening_ports": [{"container_port": 8080, "protocol": "tcp", "address": "0.0.0.0"}],
                 "published_ports": []}
        state = replace(state, status=RunStatus.PAUSED,
                        current_stage=PipelineStage.STEP_4_RESOLVER,
                        target=TargetState({"requested_reference": "victim:test"}, facts))
        self.store.save(state)
        return top

    @staticmethod
    def simple_analysis(inputs, status):
        return Step4Analysis(tuple(ResolverCVEResult(x, status, None, None, None, None)
                                   for x in inputs))

    def test_exact_top30_state_reference_not_newer_file(self):
        chosen = self.prepare()
        newer = self.root / "scoring" / "before" / "top30_2099-01-01_zzzzz.json"
        newer.write_text("not even json", encoding="utf-8")
        seen = []

        def processor(inputs, _facts):
            seen.extend(x.cve_id for x in inputs)
            return self.simple_analysis(inputs, ResolverCVEStatus.NO_MSF_MODULE)

        state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(seen, ["CVE-2099-0001"])
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.waiting_reason, "NO_EXECUTABLE_MSF_CANDIDATE")
        self.assertEqual(Path(state.artifact(ArtifactKind.RESOLVER_BEFORE).path).parent,
                         self.root / "resolver")
        self.assertTrue(chosen.exists())

    def test_digest_mismatch_fails_before_processor(self):
        top = self.prepare()
        top.write_text("{}", encoding="utf-8")
        called = []
        state = ResolverOrchestrator(
            self.store, lambda *_: called.append(True), clock=lambda: NOW).run("aB3x9")
        self.assertFalse(called)
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertEqual(state.errors[-1].code, "ARTIFACT_INTEGRITY_ERROR")
        self.assertIsNone(state.artifact(ArtifactKind.RESOLVER_BEFORE))

    def test_incompatible_top30_variants_never_call_processor(self):
        mutations = (
            lambda doc: doc.update(schema="wrong/v1"),
            lambda doc: doc["artifact"].update(run_id="K8mP2"),
            lambda doc: doc.update(ranked_cves=[{"rank": 2, "cve_id": "CVE-2099-0001",
                                                 "occurrences": []}]),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.tearDown()
                self.setUp()
                top = self.prepare()
                document = json.loads(top.read_text(encoding="utf-8"))
                mutate(document)
                top.write_text(json.dumps(document), encoding="utf-8")
                state = self.store.load("aB3x9")
                old = state.artifact(ArtifactKind.TOP30_BEFORE)
                state = state.with_artifact(replace(old, sha256=digest(top)), state.updated_at)
                self.store.save(state)
                called = []
                result = ResolverOrchestrator(
                    self.store, lambda *_: called.append(True), clock=lambda: NOW).run("aB3x9")
                self.assertFalse(called)
                self.assertEqual(result.errors[-1].code, "ARTIFACT_INTEGRITY_ERROR")

    def test_ambiguous_modules_publish_form_and_wait(self):
        self.prepare()
        candidates = {"exploit/a": {"rank": "excellent"}, "exploit/b": {"rank": "good"}}
        live = {"exploit/a": {"options": []}, "exploit/b": {"options": []}}
        processor = production_step4_processor(backend(candidates=candidates, live=live),
                                               msf_container="msf")
        state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.WAITING_FOR_USER_INPUT)
        self.assertEqual(state.stage(PipelineStage.STEP_4_RESOLVER).status, StageStatus.WAITING)
        self.assertEqual(state.waiting_reason, "ATTACK_FORM")
        form = state.artifact(ArtifactKind.ATTACK_FORM)
        self.assertIsNotNone(form)
        self.assertEqual(state.cves[0].resolver_status, "WAITING_FOR_USER_INPUT")
        text = Path(form.path).read_text(encoding="utf-8")
        self.assertIn("exploit/a", text)
        self.assertIn("exploit/b", text)

    def test_all_ready_pauses_without_form(self):
        self.prepare()
        processor = lambda inputs, _: self.simple_analysis(inputs, ResolverCVEStatus.READY_TO_EXECUTE)
        state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.stage(PipelineStage.STEP_4_RESOLVER).status, StageStatus.SUCCEEDED)
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.waiting_reason, "BEFORE_EXPLOIT_NOT_INTEGRATED")
        self.assertIsNone(state.artifact(ArtifactKind.ATTACK_FORM))

    def test_mixed_results_preserve_all_statuses_and_form_only_waiting(self):
        self.prepare(("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"))
        candidates = {"exploit/a": {"rank": "excellent"}, "exploit/b": {"rank": "good"}}
        live = {"exploit/a": {"options": []}, "exploit/b": {"options": []}}
        base = production_step4_processor(backend(candidates=candidates, live=live),
                                          msf_container="msf")

        def processor(inputs, facts):
            values = list(base(inputs, facts).cves)
            values[0] = replace(values[0], status=ResolverCVEStatus.READY_TO_EXECUTE)
            values[2] = replace(values[2], status=ResolverCVEStatus.NO_MSF_MODULE,
                                discovery=None, ranking=None, exploit_config=None, validation=None)
            return Step4Analysis(tuple(values))

        state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual([x.resolver_status for x in state.cves], [
            "READY_TO_EXECUTE", "WAITING_FOR_USER_INPUT", "NO_MSF_MODULE"])
        form_text = Path(state.artifact(ArtifactKind.ATTACK_FORM).path).read_text(encoding="utf-8")
        self.assertNotIn("CVE-2099-0001:", form_text)
        self.assertIn("CVE-2099-0002:", form_text)
        self.assertNotIn("CVE-2099-0003:", form_text)

    def test_resolver_publication_failure_commits_no_reference(self):
        self.prepare()
        processor = lambda inputs, _: self.simple_analysis(inputs, ResolverCVEStatus.NO_MSF_MODULE)
        with patch("src.app.kalama.resolution.orchestrator.write_resolver_artifact",
                   side_effect=OSError("resolver replace failed")):
            state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertEqual(state.errors[-1].code, "RESOLVER_ARTIFACT_WRITE_FAILED")
        self.assertIsNone(state.artifact(ArtifactKind.RESOLVER_BEFORE))

    def test_form_failure_keeps_resolver_reference_truthful(self):
        self.prepare()
        candidates = {"exploit/a": {"rank": "excellent"}, "exploit/b": {"rank": "good"}}
        live = {"exploit/a": {"options": []}, "exploit/b": {"options": []}}
        processor = production_step4_processor(backend(candidates=candidates, live=live),
                                               msf_container="msf")
        with patch("src.app.kalama.resolution.orchestrator.write_attack_form",
                   side_effect=OSError("form replace failed")):
            state = ResolverOrchestrator(self.store, processor, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertIsNotNone(state.artifact(ArtifactKind.RESOLVER_BEFORE))
        self.assertIsNone(state.artifact(ArtifactKind.ATTACK_FORM))
        self.assertEqual(state.errors[-1].code, "ATTACK_FORM_WRITE_FAILED")

    def test_other_running_run_blocks_without_mutating_target(self):
        self.prepare()
        other = self.store.create("other:test", now=NOW, run_id_generator=lambda: "K8mP2")
        other = replace(other, status=RunStatus.RUNNING)
        self.store.save(other)
        with self.assertRaises(Step4OrchestrationError) as raised:
            ResolverOrchestrator(self.store, lambda *_: None, clock=lambda: NOW).run("aB3x9")
        self.assertEqual(raised.exception.code, "ACTIVE_RUN_CONFLICT")
        self.assertEqual(self.store.load("aB3x9").stage(PipelineStage.STEP_4_RESOLVER).status,
                         StageStatus.NOT_STARTED)


if __name__ == "__main__":
    unittest.main()
