"""Wave 3 shadow-integration tests: artifacts, normalization, correlation,
signal derivation, shadow pipeline behavior, CLI, resume.

No Docker, no Nuclei required. Docker/process pieces are faked; the one
live-Nuclei integration lives in tests/integration and skips without a
pinned local setup.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import yaml

from kalama.cli import build_parser, main
from kalama.dynamic_probe import (
    APPROVED_TEMPLATE_MANIFEST_SCHEMA,
    ApprovedTemplate,
    ApprovedTemplateManifest,
    DynamicEndpoint,
    DynamicEvidence,
    DynamicSignal,
    NucleiTemplatePolicy,
    TemplatePolicyError,
)
from kalama.dynamic_probe_runtime import (
    BackendResult,
    NucleiExecutionStatus,
    NucleiMatchRecord,
    ProbeExecutionResult,
)
from kalama.dynamic_shadow import (
    CLEAN,
    DYNAMIC_RESULT_SCHEMA,
    DYNAMIC_SHADOW_SCHEMA,
    DYNAMIC_TEMPLATES_SCHEMA,
    INCOMPLETE,
    MATCHED,
    ArtifactKind,
    DynamicShadowConfig,
    DynamicShadowError,
    DynamicShadowOrchestrator,
    atomic_write_bytes,
    build_probe_endpoint,
    build_shadow_summary,
    classify_execution,
    correlate_evidence,
    derive_dynamic_signal,
    dynamic_config_from_env,
    dynamic_dir,
    dynamic_evidence_identity,
    execution_result_manifest,
    load_verified_results,
    normalize_evidence,
    probe_nuclei_identity,
    read_top30_candidates,
    resolved_template_manifest,
    sanitize_artifact_component,
    select_probe_port,
)
from kalama.state import (
    ArtifactReference,
    PipelineStage,
    RunNotice,
    RunStatus,
    StageStatus,
    StateStore,
    TargetState,
)


NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
ZERO = "0" * 64

MINIMAL_HTTP_TEMPLATE = """\
id: cves/example
info:
  name: Example check
  severity: high
  tags: cve
http:
  - method: GET
    path:
      - "{{BaseURL}}/example"
    matchers:
      - type: word
        words: ["example"]
"""

HELP_TEXT = """Nuclei is a fast, template based vulnerability scanner
FLAGS:
  -duc, -disable-update-check: disable automatic update check
  -dr, -disable-redirects: disable redirects
  -ni, -no-interactsh: disable interactsh server
  -dut, -disable-unsigned-templates: skip unsigned templates
  -jsonl: write output in JSONL format"""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_bytes(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _template_tree(root: Path) -> ApprovedTemplateManifest:
    _write_bytes(root / "http" / "a.yaml", MINIMAL_HTTP_TEMPLATE)
    _write_bytes(root / "http" / "b.yaml", MINIMAL_HTTP_TEMPLATE)
    manifest_path = root / "approved.yaml"
    manifest_path.write_text(yaml.safe_dump({
        "schema": APPROVED_TEMPLATE_MANIFEST_SCHEMA,
        "profile": "safe-cve-http",
        "template_revision": "reviewed-test",
        "approved_templates": [
            {"template_id": "t1", "relative_path": "http/a.yaml",
             "expected_sha256": _sha(MINIMAL_HTTP_TEMPLATE),
             "mapped_cves": ["CVE-2017-5638"]},
            {"template_id": "t2", "relative_path": "http/b.yaml",
             "expected_sha256": _sha(MINIMAL_HTTP_TEMPLATE),
             "mapped_cves": ["CVE-2017-5638", "CVE-2020-0001"]},
        ],
    }, sort_keys=False), encoding="utf-8")
    return manifest_path


def _endpoint() -> DynamicEndpoint:
    return DynamicEndpoint("aB3x9", "victim-id-1", "victim-aB3x9",
                           "kalama-probe-aB3x9-1", "10.0.0.2", 8080, "http", "READY")


def _match_record(cve: str | None = "CVE-2017-5638",
                  matcher: str | None = "body") -> NucleiMatchRecord:
    return NucleiMatchRecord(
        template_id="t1", matcher_name=matcher, matched_at="http://10.0.0.2:8080/",
        host="http://10.0.0.2:8080/", severity="high", cve_id=cve,
        timestamp="2026-01-01T00:00:00Z", raw={"template-id": "t1"})


def _execution(status: NucleiExecutionStatus = NucleiExecutionStatus.SUCCEEDED,
               reachable: bool | None = True,
               records: tuple = (), raw: bytes = b"",
               template_id: str = "t1",
               cve: str = "CVE-2017-5638") -> ProbeExecutionResult:
    endpoint = _endpoint()
    return ProbeExecutionResult(
        run_id="aB3x9", attempt="1", endpoint_identity=endpoint.to_dict(),
        candidate_cve=cve, template_id=template_id,
        template_path="/root/http/a.yaml", template_sha256=_sha(MINIMAL_HTTP_TEMPLATE),
        execution_status=status, started_at="2026-09-01T00:00:00Z",
        finished_at="2026-09-01T00:01:00Z", duration_seconds=60.0,
        reachable=reachable, exit_code=0 if status == NucleiExecutionStatus.SUCCEEDED else 1,
        records=records, raw_stdout=raw)


class FakeSandbox:
    """ProbeSandbox double: canned endpoint, injectable failures, call log."""

    def __init__(self, config, *, fail_setup=None, fail_verify=None):
        self.config = config
        self.runner_name = config.effective_runner_name()
        self.network_name = config.network_name()
        self.calls: list[str] = []
        self._fail_setup = fail_setup
        self._fail_verify = fail_verify

    def setup(self):
        self.calls.append("setup")
        if self._fail_setup is not None:
            raise self._fail_setup
        return DynamicEndpoint(
            self.config.run_id, self.config.expected_container_id,
            self.config.victim_container_name, self.network_name,
            "10.0.0.2", self.config.port, self.config.scheme, "READY")

    def start_runner(self):
        self.calls.append("start_runner")

    def verify_after(self):
        self.calls.append("verify_after")
        if self._fail_verify is not None:
            raise self._fail_verify
        return None

    def cleanup(self):
        self.calls.append("cleanup")


class RoutingNucleiBackend:
    """Answers -h/-version/sha256sum probes; pops queued results otherwise."""

    def __init__(self, results: list[BackendResult]):
        self.results = list(results)
        self.calls: list[tuple] = []

    def run(self, argv, *, timeout=None, stdout_budget=None, stderr_budget=None):
        args = tuple(str(x) for x in argv)
        self.calls.append(args)
        if "-h" in args:
            return BackendResult(args, 0, HELP_TEXT.encode(), b"")
        if "-version" in args:
            return BackendResult(args, 0, b"v3.4.0\n", b"")
        if "sha256sum" in args:
            return BackendResult(args, 0, ("f" * 64 + "  nuclei\n").encode(), b"")
        assert self.results, f"unexpected Nuclei invocation: {args}"
        canned = self.results.pop(0)
        return BackendResult(args, canned.exit_code, canned.stdout,
                             canned.stderr, canned.timed_out)


def _success_result(payload: bytes) -> BackendResult:
    return BackendResult(("nuclei",), 0, payload, b"")


def _match_payload(cve: str = "CVE-2017-5638") -> bytes:
    return (json.dumps({"template-id": "t1", "matcher-name": "body",
                        "host": "http://10.0.0.2:8080/example",
                        "info": {"severity": "high",
                                 "classification": {"cve-id": cve}}}) + "\n").encode()


def _post_step3_state(store: StateStore,
                      cves: tuple[str, ...] = ("CVE-2017-5638", "CVE-2020-0001",
                                               "CVE-2099-9999")) -> Path:
    state = store.create("example/image:1", now=NOW, run_id_generator=lambda: "aB3x9")
    top30_path = store.output_root / "scoring" / "before" / "top30_2026-09-01_aB3x9.json"
    top30_path.parent.mkdir(parents=True, exist_ok=True)
    ranked = [{"rank": index + 1, "cve_id": cve,
               "score": {"model": "kalama-priority-v1",
                         "total_display": str(10 - index)}}
              for index, cve in enumerate(cves)]
    top30_path.write_bytes((json.dumps({
        "schema": "kalama.prioritization/v1",
        "artifact": {"kind": "before_top_cves", "run_id": "aB3x9", "phase": "before",
                     "created_at": "2026-09-01T00:00:00Z",
                     "top_n_requested": len(ranked), "top_n_returned": len(ranked)},
        "score_model": {"id": "kalama-priority-v1"},
        "ranked_cves": ranked,
    }, sort_keys=True) + "\n").encode())
    digest = hashlib.sha256(top30_path.read_bytes()).hexdigest()
    facts = {"run_id": "aB3x9", "container_name": "victim-aB3x9",
             "container_id": "victim-id-1", "network": "kalama-net",
             "ip_address": "172.18.0.11", "reachable_ports": [8080],
             "listening_ports": [], "exposed_ports": [], "published_ports": []}
    state = store.load("aB3x9")
    state = replace(state, target=TargetState({}, facts),
                    updated_at="2026-09-01T00:00:01Z")
    state = state.with_artifact(ArtifactReference(
        ArtifactKind.TOP30_BEFORE, str(top30_path.resolve()), digest,
        "kalama.prioritization/v1", "2026-09-01T00:00:01Z",
        PipelineStage.STEP_3_PRIORITIZATION, ()), "2026-09-01T00:00:01Z")
    state = state.with_stage(PipelineStage.STEP_3_PRIORITIZATION,
                             StageStatus.SUCCEEDED, "2026-09-01T00:00:01Z")
    state = replace(state, status=RunStatus.PAUSED,
                    current_stage=PipelineStage.STEP_4_RESOLVER,
                    updated_at="2026-09-01T00:00:01Z")
    store.save(state)
    return top30_path


def _shadow_config(root: Path, **overrides) -> DynamicShadowConfig:
    kwargs = dict(enabled=True, manifest_path=root / "approved.yaml",
                  template_root=root, nuclei_binary="nuclei",
                  runner_image="img:pinned")
    kwargs.update(overrides)
    return DynamicShadowConfig(**kwargs)


def _orchestrator(store: StateStore, backend: RoutingNucleiBackend,
                  sandboxes: list, reachability=True) -> DynamicShadowOrchestrator:
    return DynamicShadowOrchestrator(
        store, clock=lambda: NOW,
        sandbox_factory=lambda config: sandboxes.append(config) or FakeSandbox(config),
        backend_factory=lambda runner: backend,
        reachability_factory=lambda cli, runner: (lambda endpoint: reachability))


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "output")
        self.manifest_path = _template_tree(self.root / "templates")
        self.top30_path = _post_step3_state(self.store)

    def _run_shadow(self, results: list[BackendResult], **overrides):
        backend = RoutingNucleiBackend(results)
        sandboxes: list = []
        reachability = overrides.pop("reachability", True)
        orchestrator = _orchestrator(self.store, backend, sandboxes, reachability)
        state = orchestrator.run_shadow("aB3x9", _shadow_config(
            self.root / "templates", **overrides))
        return state, backend, sandboxes

    def _dynamic_files(self):
        base = dynamic_dir(self.store.output_root, "aB3x9")
        return sorted(p.name for p in base.iterdir()) if base.is_dir() else []

    def test_successful_execution_writes_immutable_raw_jsonl(self):
        payload = _match_payload()
        self._run_shadow([_success_result(payload), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        raws = sorted(base.glob("*.jsonl"))
        self.assertTrue(raws)
        match = [p for p in raws if p.read_bytes() == payload]
        self.assertEqual(len(match), 1)

    def test_execution_manifest_contains_required_provenance(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        manifests = sorted(base.glob("dynamic_nuclei_result_*.json"))
        self.assertTrue(manifests)
        document = json.loads(manifests[0].read_bytes())
        for field in ("run_id", "attempt", "phase", "candidate_cve", "template_id",
                      "template_sha256", "started_at", "finished_at", "execution_status",
                      "reachable", "exit_code", "error_code", "raw_artifact"):
            self.assertIn(field, document, field)
        self.assertIn("binary", document["nuclei"])
        self.assertIn("sha256", document["template_manifest"])
        self.assertIn("container_id", document)
        self.assertEqual(document["schema"], DYNAMIC_RESULT_SCHEMA)

    def test_resolved_template_manifest_persisted(self):
        self._run_shadow([_success_result(b""), _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        resolved = sorted(base.glob("dynamic_nuclei_templates_*.json"))
        self.assertEqual(len(resolved), 1)
        document = json.loads(resolved[0].read_bytes())
        self.assertEqual(document["schema"], DYNAMIC_TEMPLATES_SCHEMA)
        self.assertTrue(document["resolutions"])

    def test_sha256_references_match_files(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        for manifest_path in base.glob("*.result.json"):
            document = json.loads(manifest_path.read_bytes())
            raw = document["raw_artifact"]
            self.assertEqual(hashlib.sha256(Path(raw["path"]).read_bytes()).hexdigest(),
                             raw["sha256"])
        summaries = list(base.glob("dynamic_shadow_*.json"))
        self.assertEqual(len(summaries), 1)
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        self.assertIsNotNone(ref)
        self.assertEqual(ref.sha256, hashlib.sha256(summaries[0].read_bytes()).hexdigest())

    def test_retry_creates_new_attempt_artifacts(self):
        timeout = BackendResult(("nuclei",), 124, b"", b"", True)
        self._run_shadow([timeout, _success_result(b""), _success_result(b"")])
        first = set(self._dynamic_files())
        self.assertTrue(any("_attempt_1_" in name for name in first))
        second, backend, _ = self._run_shadow(
            [_success_result(b""), _success_result(b""), _success_result(b"")])
        names = set(self._dynamic_files())
        self.assertTrue(any("_attempt_2_" in name for name in names - first))

    def test_retry_never_overwrites_attempt_1(self):
        timeout = BackendResult(("nuclei",), 124, b"", b"", True)
        self._run_shadow([timeout, _success_result(b""), _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        before = {p.name: p.read_bytes() for p in base.iterdir()}
        self._run_shadow([_success_result(b""), _success_result(b""), _success_result(b"")])
        after = {p.name: p.read_bytes() for p in base.iterdir()}
        for name, payload in before.items():
            self.assertEqual(after[name], payload, name)

    def test_partial_output_preserved(self):
        payload = _match_payload() + b"{truncated"
        backend_result = BackendResult(("nuclei",), 1, payload, b"")
        self._run_shadow([backend_result, _success_result(b""), _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        raws = [p for p in base.glob("*.jsonl") if p.read_bytes() == payload]
        self.assertEqual(len(raws), 1)

    def test_invalid_output_preserved(self):
        payload = b'{"a": \n'
        self._run_shadow([BackendResult(("nuclei",), 0, payload, b""),
                          _success_result(b""), _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        raws = [p for p in base.glob("*.jsonl") if p.read_bytes() == payload]
        self.assertEqual(len(raws), 1)

    def test_atomic_write_leaves_no_temp_files(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        dotfiles = [p.name for p in base.iterdir() if p.name.startswith(".")]
        self.assertEqual(dotfiles, [])

    def test_artifact_filename_rejects_traversal(self):
        from kalama.dynamic_shadow import _artifact_paths
        base = dynamic_dir(self.store.output_root, "aB3x9")
        base.mkdir(parents=True, exist_ok=True)
        paths = _artifact_paths(base, "aB3x9", 1, "CVE-2017-5638", "http/x/../../evil")
        for path in paths.values():
            self.assertEqual(path.resolve(strict=False).parent,
                             base.resolve(strict=False))
        with self.assertRaises(DynamicShadowError):
            atomic_write_bytes(paths["raw"], b"first")
            atomic_write_bytes(paths["raw"], b"second")


class NormalizationTests(unittest.TestCase):
    def _provenance(self):
        return dict(run_id="aB3x9", phase="before", attempt="1",
                    container_id="victim-id-1",
                    raw_artifact_path="/out/raw.jsonl",
                    raw_artifact_sha256="a" * 64,
                    execution_manifest_path="/out/result.json")

    def test_valid_match_yields_evidence(self):
        items = normalize_evidence(
            _execution(records=(_match_record(),), raw=_match_payload()),
            **self._provenance())
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertTrue(item.matched)
        self.assertEqual(item.matcher_name, "body")
        self.assertEqual(item.cve_id, "CVE-2017-5638")
        self.assertEqual(item.template_id, "t1")

    def test_zero_match_invents_no_evidence(self):
        items = normalize_evidence(_execution(records=(), raw=b"\n"), **self._provenance())
        self.assertEqual(items, [])

    def test_missing_matcher_remains_null(self):
        items = normalize_evidence(
            _execution(records=(_match_record(matcher=None),)), **self._provenance())
        self.assertIsNone(items[0].matcher_name)

    def test_missing_cve_remains_null(self):
        items = normalize_evidence(
            _execution(records=(_match_record(cve=None),)), **self._provenance())
        self.assertIsNone(items[0].cve_id)

    def test_no_package_identity_invented(self):
        items = normalize_evidence(
            _execution(records=(_match_record(),)), **self._provenance())
        item = items[0]
        self.assertFalse(hasattr(item, "package_name"))
        self.assertNotIn("package_name", item.metadata)
        self.assertNotIn("package_uid", item.metadata)

    def test_evidence_contains_endpoint_container_provenance(self):
        items = normalize_evidence(
            _execution(records=(_match_record(),)), **self._provenance())
        item = items[0]
        self.assertEqual(item.endpoint_key, _endpoint().endpoint_key)
        self.assertEqual(item.metadata["container_id"], "victim-id-1")
        self.assertEqual(item.metadata["template_sha256"], _sha(MINIMAL_HTTP_TEMPLATE))

    def test_evidence_references_immutable_raw_artifact(self):
        items = normalize_evidence(
            _execution(records=(_match_record(),)), **self._provenance())
        self.assertEqual(items[0].metadata["raw_artifact_path"], "/out/raw.jsonl")
        self.assertEqual(items[0].metadata["raw_artifact_sha256"], "a" * 64)

    def test_untrusted_execution_yields_no_evidence(self):
        timed_out = _execution(status=NucleiExecutionStatus.TIMED_OUT, reachable=True)
        self.assertEqual(normalize_evidence(timed_out, **self._provenance()), [])
        unreachable = _execution(reachable=False, records=(_match_record(),))
        self.assertEqual(normalize_evidence(unreachable, **self._provenance()), [])


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest_path = _template_tree(self.root)
        from kalama.dynamic_probe import load_approved_template_manifest
        self.manifest = load_approved_template_manifest(self.manifest_path, self.root)

    def _evidence(self, run_id="aB3x9", candidate="CVE-2017-5638",
                  template="t1", endpoint_key=None) -> DynamicEvidence:
        return DynamicEvidence(
            endpoint_key=endpoint_key or _endpoint().endpoint_key,
            template_id=template, matched=True, matcher_name="body",
            cve_id=candidate,
            metadata={"run_id": run_id, "candidate_cve": candidate})

    def test_exact_same_run_cve_correlates(self):
        items = correlate_evidence([self._evidence()], run_id="aB3x9",
                                   cve_id="CVE-2017-5638", manifest=self.manifest,
                                   endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(len(items), 1)

    def test_wrong_run_does_not_correlate(self):
        items = correlate_evidence([self._evidence(run_id="bC4y0")], run_id="aB3x9",
                                   cve_id="CVE-2017-5638", manifest=self.manifest,
                                   endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(items, [])

    def test_wrong_cve_does_not_correlate(self):
        items = correlate_evidence([self._evidence(candidate="CVE-2020-0001")],
                                   run_id="aB3x9", cve_id="CVE-2017-5638",
                                   manifest=self.manifest,
                                   endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(items, [])

    def test_unapproved_template_does_not_correlate(self):
        items = correlate_evidence([self._evidence(template="rogue")], run_id="aB3x9",
                                   cve_id="CVE-2017-5638", manifest=self.manifest,
                                   endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(items, [])

    def test_ghsa_is_not_auto_converted(self):
        items = correlate_evidence(
            [self._evidence(candidate="GHSA-abcd-1234-efgh")], run_id="aB3x9",
            cve_id="GHSA-abcd-1234-efgh", manifest=self.manifest,
            endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(items, [])

    def test_different_endpoint_run_is_not_reused(self):
        other = DynamicEndpoint("bC4y0", "victim-id-9", "victim-bC4y0",
                                "kalama-probe-bC4y0-1", "10.0.0.9", 8080, "http", "READY")
        items = correlate_evidence([self._evidence(endpoint_key=other.endpoint_key)],
                                   run_id="aB3x9", cve_id="CVE-2017-5638",
                                   manifest=self.manifest,
                                   endpoint_key=_endpoint().endpoint_key)
        self.assertEqual(items, [])

    def test_evidence_identity_has_no_package(self):
        identity = dynamic_evidence_identity("aB3x9", "before", self._evidence())
        self.assertEqual(identity[:5], ("aB3x9", "before", _endpoint().endpoint_key,
                                        "t1", "body"))
        self.assertNotIn("package", " ".join(identity).lower())


class SignalTests(unittest.TestCase):
    def test_one_trusted_match_corroborated(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1"],
                                       outcomes={"t1": MATCHED})
        self.assertEqual(signal, DynamicSignal.CORROBORATED)

    def test_one_complete_zero_match_not_observed(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1"],
                                       outcomes={"t1": CLEAN})
        self.assertEqual(signal, DynamicSignal.NOT_OBSERVED)

    def test_all_complete_zero_match_not_observed(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1", "t2", "t3"],
            outcomes={"t1": CLEAN, "t2": CLEAN, "t3": CLEAN})
        self.assertEqual(signal, DynamicSignal.NOT_OBSERVED)

    def test_subset_timeout_is_inconclusive(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1", "t2", "t3"],
            outcomes={"t1": CLEAN, "t2": INCOMPLETE, "t3": CLEAN})
        self.assertEqual(signal, DynamicSignal.INCONCLUSIVE)

    def test_invalid_output_is_inconclusive(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1", "t2"],
                                       outcomes={"t1": CLEAN, "t2": INCOMPLETE})
        self.assertEqual(signal, DynamicSignal.INCONCLUSIVE)

    def test_unreachable_template_is_inconclusive(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1"],
                                       outcomes={"t1": INCOMPLETE})
        self.assertEqual(signal, DynamicSignal.INCONCLUSIVE)

    def test_match_plus_failure_still_corroborated(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1", "t2"],
                                       outcomes={"t1": MATCHED, "t2": INCOMPLETE})
        self.assertEqual(signal, DynamicSignal.CORROBORATED)

    def test_no_approved_template_not_applicable(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=[],
                                       outcomes={})
        self.assertEqual(signal, DynamicSignal.NOT_APPLICABLE)

    def test_feature_disabled_not_run(self):
        signal = derive_dynamic_signal(enabled=False, applicable_templates=["t1"],
                                       outcomes={"t1": MATCHED})
        self.assertEqual(signal, DynamicSignal.NOT_RUN)

    def test_sandbox_failure_inconclusive(self):
        signal = derive_dynamic_signal(enabled=True, applicable_templates=["t1"],
                                       outcomes={})
        self.assertEqual(signal, DynamicSignal.INCONCLUSIVE)

    def test_identity_drift_inconclusive(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1", "t2"],
            outcomes={"t1": CLEAN})
        self.assertEqual(signal, DynamicSignal.INCONCLUSIVE)

    def test_no_signal_path_yields_not_vulnerable(self):
        cases = [
            dict(enabled=False),
            dict(enabled=True, applicable_templates=[]),
            dict(enabled=True, applicable_templates=["t1"],
                 outcomes={"t1": MATCHED}),
            dict(enabled=True, applicable_templates=["t1"],
                 outcomes={"t1": CLEAN}),
            dict(enabled=True, applicable_templates=["t1", "t2"],
                 outcomes={"t1": CLEAN}),
            dict(enabled=True, applicable_templates=["t1"],
                 outcomes={"t1": INCOMPLETE}),
        ]
        for kwargs in cases:
            signal = derive_dynamic_signal(**kwargs)
            self.assertIn(signal, set(DynamicSignal), kwargs)
            self.assertNotIn(signal.value, ("NOT_VULNERABLE", "SAFE", "PATCHED"))

    def test_classify_execution_trusted_only(self):
        self.assertEqual(classify_execution(_execution(records=(_match_record(),))), MATCHED)
        self.assertEqual(classify_execution(_execution(records=())), CLEAN)
        self.assertEqual(
            classify_execution(_execution(status=NucleiExecutionStatus.TIMED_OUT)), INCOMPLETE)
        self.assertEqual(
            classify_execution(_execution(reachable=False, records=(_match_record(),))),
            INCOMPLETE)


class ShadowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "output")
        self.manifest_path = _template_tree(self.root / "templates")
        self.top30_path = _post_step3_state(self.store)
        self.top30_bytes = self.top30_path.read_bytes()

    def _run_shadow(self, results: list[BackendResult], **overrides):
        backend = RoutingNucleiBackend(results)
        sandboxes: list = []
        reachability = overrides.pop("reachability", True)
        required = overrides.pop("required", False)
        orchestrator = _orchestrator(self.store, backend, sandboxes, reachability)
        state = orchestrator.run_shadow(
            "aB3x9", _shadow_config(self.root / "templates", required=required,
                                    **overrides))
        return state, backend, sandboxes

    def _summary(self):
        base = dynamic_dir(self.store.output_root, "aB3x9")
        summaries = sorted(base.glob("dynamic_shadow_*.json"))
        self.assertEqual(len(summaries), 1)
        return json.loads(summaries[0].read_bytes())

    def test_top30_bytes_identical_after_shadow(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        self.assertEqual(self.top30_path.read_bytes(), self.top30_bytes)

    def test_candidate_order_and_scores_identical(self):
        self._run_shadow([_success_result(b""), _success_result(b""),
                          _success_result(b"")])
        after = json.loads(self.top30_path.read_bytes())
        before = json.loads(self.top30_bytes)
        self.assertEqual([(c["cve_id"], c["score"]) for c in after["ranked_cves"]],
                         [(c["cve_id"], c["score"]) for c in before["ranked_cves"]])

    def test_signals_carry_zero_score_delta(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        summary = self._summary()
        by_cve = {c["cve_id"]: c for c in summary["candidates"]}
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "CORROBORATED")
        self.assertEqual(by_cve["CVE-2020-0001"]["signal"], "NOT_OBSERVED")
        self.assertEqual(by_cve["CVE-2099-9999"]["signal"], "NOT_APPLICABLE")
        for candidate in summary["candidates"]:
            self.assertEqual(candidate["dynamic_validation"]["score_delta"], 0)
            self.assertEqual(candidate["dynamic_validation"]["provider"], "nuclei")
            self.assertEqual(candidate["dynamic_validation"]["profile"], "safe-cve-http")

    def test_inconclusive_has_zero_score_delta(self):
        timeout = BackendResult(("nuclei",), 124, b"", b"", True)
        self._run_shadow([timeout, _success_result(b""), _success_result(b"")])
        summary = self._summary()
        by_cve = {c["cve_id"]: c for c in summary["candidates"]}
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "INCONCLUSIVE")
        self.assertEqual(by_cve["CVE-2017-5638"]["dynamic_validation"]["score_delta"], 0)

    def test_dynamic_evidence_in_state_without_ranking_change(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        state = self.store.load("aB3x9")
        ref = state.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        self.assertIsNotNone(ref)
        summary = self._summary()
        matched = next(c for c in summary["candidates"]
                       if c["cve_id"] == "CVE-2017-5638")
        self.assertTrue(matched["dynamic_validation"]["evidence_refs"])
        self.assertEqual(self.top30_path.read_bytes(), self.top30_bytes)

    def test_best_effort_failure_continues_pipeline(self):
        failing = BackendResult(("nuclei",), 1, b"", b"boom")
        state, _, _ = self._run_shadow([failing, failing, failing], required=False)
        self.assertEqual(state.status, RunStatus.PAUSED)
        self.assertEqual(state.current_stage, PipelineStage.STEP_4_RESOLVER)
        self.assertTrue(state.warnings)
        summary = self._summary()
        by_cve = {c["cve_id"]: c for c in summary["candidates"]}
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "INCONCLUSIVE")
        from kalama.dispatcher import dispatch_stage
        self.assertEqual(dispatch_stage(state), "resolver")

    def test_required_failure_stops_with_existing_semantics(self):
        failing = BackendResult(("nuclei",), 1, b"", b"boom")
        state, _, _ = self._run_shadow([failing, failing, failing], required=True)
        self.assertEqual(state.status, RunStatus.FAILED_FATAL)
        self.assertTrue(state.errors)
        self.assertEqual(state.errors[-1].code, "DYNAMIC_PROBE_FAILED")
        ref = state.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        self.assertIsNotNone(ref)

    def test_required_clean_run_does_not_fail(self):
        state, _, _ = self._run_shadow(
            [_success_result(b""), _success_result(b""), _success_result(b"")],
            required=True)
        self.assertEqual(state.status, RunStatus.PAUSED)

    def test_no_endpoint_yields_not_run(self):
        state = self.store.load("aB3x9")
        facts = dict(state.target.facts)
        facts.pop("ip_address", None)
        state = replace(state, target=TargetState({}, facts))
        self.store.save(state)
        backend = RoutingNucleiBackend([])
        orchestrator = _orchestrator(self.store, backend, [])
        result = orchestrator.run_shadow("aB3x9", _shadow_config(self.root / "templates"))
        self.assertEqual(result.status, RunStatus.PAUSED)
        base = dynamic_dir(self.store.output_root, "aB3x9")
        summary = json.loads(sorted(base.glob("dynamic_shadow_*.json"))[0].read_bytes())
        for candidate in summary["candidates"]:
            self.assertEqual(candidate["signal"], "NOT_RUN")
        self.assertEqual(backend.calls, [])

    def test_sandbox_wiring_uses_validated_config(self):
        self._run_shadow([_success_result(b""), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        resolved = json.loads(sorted(base.glob("dynamic_nuclei_templates_*.json"))[0].read_bytes())
        self.assertEqual(resolved["profile"], "safe-cve-http")
        self.assertEqual(resolved["template_revision"], "reviewed-test")

    def test_summary_inputs_carry_nuclei_and_reachability_provenance(self):
        class ToolProbe:
            detected_tool = "nc"

            def __call__(self, endpoint):
                return True

        backend = RoutingNucleiBackend([_success_result(b""), _success_result(b""),
                                        _success_result(b"")])
        orchestrator = DynamicShadowOrchestrator(
            self.store, clock=lambda: NOW,
            sandbox_factory=lambda config: FakeSandbox(config),
            backend_factory=lambda runner: backend,
            reachability_factory=lambda cli, runner: ToolProbe())
        orchestrator.run_shadow("aB3x9", _shadow_config(self.root / "templates"))
        base = dynamic_dir(self.store.output_root, "aB3x9")
        summary = json.loads(sorted(base.glob("dynamic_shadow_*.json"))[0].read_bytes())
        self.assertEqual(summary["inputs"]["nuclei"]["version"], "v3.4.0")
        self.assertEqual(summary["inputs"]["nuclei"]["sha256"], "f" * 64)
        self.assertEqual(summary["inputs"]["reachability_tool"], "nc")


class ProbePortTests(unittest.TestCase):
    def test_docker_dns_stub_port_is_skipped_for_exposed(self):
        facts = {"reachable_ports": [],
                 "listening_ports": [{"container_port": 37165, "protocol": "tcp",
                                      "address": "127.0.0.11"}],
                 "exposed_ports": [{"container_port": 8080, "protocol": "tcp"}],
                 "published_ports": []}
        self.assertEqual(select_probe_port(facts), 8080)

    def test_loopback_listening_never_selects(self):
        facts = {"reachable_ports": [],
                 "listening_ports": [{"container_port": 9999, "protocol": "tcp",
                                      "address": "127.0.0.1"}],
                 "exposed_ports": [{"container_port": 8080, "protocol": "tcp"}],
                 "published_ports": []}
        self.assertEqual(select_probe_port(facts), 8080)

    def test_wildcard_listening_used_when_nothing_declared(self):
        facts = {"reachable_ports": [],
                 "listening_ports": [{"container_port": 9000, "protocol": "tcp",
                                      "address": "0.0.0.0"}],
                 "exposed_ports": [],
                 "published_ports": []}
        self.assertEqual(select_probe_port(facts), 9000)

    def test_no_eligible_port_is_none(self):
        self.assertIsNone(select_probe_port({"reachable_ports": [],
                                             "listening_ports": [],
                                             "exposed_ports": [],
                                             "published_ports": []}))
        self.assertIsNone(select_probe_port(None))

    def test_override_still_wins(self):
        self.assertEqual(select_probe_port({}, override=1234), 1234)


class NucleiIdentityTests(unittest.TestCase):
    def _backend(self, version_stdout=b"", version_stderr=b"", sha_stdout=b"",
                 sha_absolute_only=True):
        from kalama.dynamic_probe_runtime import BackendResult

        class Fake:
            def __init__(self):
                self.calls = []

            def run(self, argv, *, timeout=None, stdout_budget=None,
                    stderr_budget=None):
                args = tuple(argv)
                self.calls.append(args)
                if "-version" in args:
                    return BackendResult(args, 0, version_stdout, version_stderr)
                if sha_absolute_only and not args[-1].startswith("/"):
                    return BackendResult(args, 1, b"", b"not found")
                return BackendResult(args, 0, sha_stdout, b"")

        return Fake()

    def test_version_falls_back_to_stderr(self):
        backend = self._backend(version_stderr=b"[INF] Nuclei Engine Version: v3.11.1\n")
        identity = probe_nuclei_identity(backend, "nuclei")
        self.assertIn("v3.11.1", identity["version"] or "")

    def test_sha_resolves_absolute_candidates(self):
        backend = self._backend(version_stdout=b"v3.11.1\n",
                                sha_stdout=("f" * 64 + "  /usr/local/bin/nuclei\n").encode())
        identity = probe_nuclei_identity(backend, "nuclei")
        self.assertEqual(identity["sha256"], "f" * 64)
        sha_calls = [call for call in backend.calls if "sha256sum" in call]
        self.assertTrue(sha_calls)
        self.assertTrue(any(call[-1].startswith("/") for call in sha_calls))

    def test_missing_everything_stays_null(self):
        backend = self._backend()
        identity = probe_nuclei_identity(backend, "nuclei")
        self.assertIsNone(identity["version"])
        self.assertIsNone(identity["sha256"])


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output_root = str(Path(self.temp.name) / "output")

    def invoke(self, argv, runtime):
        from io import StringIO
        out, err = StringIO(), StringIO()
        code = main(argv, runtime_factory=lambda _: runtime, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def _runtime(self):
        store = StateStore(Path(self.temp.name) / "output")

        class CaptureRuntime:
            def __init__(self):
                self.store = store
                self.calls: list = []

            def start(self, image, **kwargs):
                self.calls.append((image, kwargs))
                return store.create(image, now=NOW, run_id_generator=lambda: "aB3x9")

        return CaptureRuntime()

    def test_no_flag_feature_off(self):
        runtime = self._runtime()
        code, _, _ = self.invoke(
            ["--output-root", self.output_root, "run", "--image", "img:1"], runtime)
        self.assertEqual(code, 0)
        self.assertEqual(runtime.calls[0][1].get("dynamic_scan"), "off")

    def test_explicit_off(self):
        runtime = self._runtime()
        code, _, _ = self.invoke(
            ["--output-root", self.output_root, "run", "--image", "img:1",
             "--dynamic-scan", "off"], runtime)
        self.assertEqual(code, 0)
        self.assertEqual(runtime.calls[0][1].get("dynamic_scan"), "off")

    def test_nuclei_enables_approved_flow(self):
        runtime = self._runtime()
        code, _, _ = self.invoke(
            ["--output-root", self.output_root, "run", "--image", "img:1",
             "--dynamic-scan", "nuclei"], runtime)
        self.assertEqual(code, 0)
        kwargs = runtime.calls[0][1]
        self.assertEqual(kwargs.get("dynamic_scan"), "nuclei")
        self.assertEqual(kwargs.get("nuclei_profile"), "safe-cve-http")
        self.assertFalse(kwargs.get("dynamic_scan_required"))

    def test_safe_cve_http_profile_accepted(self):
        runtime = self._runtime()
        code, _, _ = self.invoke(
            ["--output-root", self.output_root, "run", "--image", "img:1",
             "--dynamic-scan", "nuclei", "--nuclei-profile", "safe-cve-http"], runtime)
        self.assertEqual(code, 0)
        self.assertEqual(runtime.calls[0][1].get("nuclei_profile"), "safe-cve-http")

    def test_arbitrary_template_path_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(
                ["run", "--image", "img:1", "--template-dir", "/tmp/evil"])
        self.assertEqual(caught.exception.code, 2)

    def test_arbitrary_url_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(
                ["run", "--image", "img:1", "--dynamic-scan", "nuclei",
                 "--target-url", "http://evil.example/"])
        self.assertEqual(caught.exception.code, 2)

    def test_arbitrary_nuclei_flags_rejected(self):
        with self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(
                ["run", "--image", "img:1", "--nuclei-flags", "-duc"])
        self.assertEqual(caught.exception.code, 2)

    def test_required_flag_parsed(self):
        runtime = self._runtime()
        code, _, _ = self.invoke(
            ["--output-root", self.output_root, "run", "--image", "img:1",
             "--dynamic-scan", "nuclei", "--dynamic-scan-required"], runtime)
        self.assertEqual(code, 0)
        self.assertTrue(runtime.calls[0][1].get("dynamic_scan_required"))


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "output")
        self.manifest_path = _template_tree(self.root / "templates")
        _post_step3_state(self.store)

    def _run_shadow(self, results: list[BackendResult]):
        backend = RoutingNucleiBackend(results)
        sandboxes: list = []
        orchestrator = _orchestrator(self.store, backend, sandboxes)
        state = orchestrator.run_shadow("aB3x9", _shadow_config(self.root / "templates"))
        return state, backend

    def _execution_calls(self, backend: RoutingNucleiBackend) -> list:
        return [call for call in backend.calls
                if "-h" not in call and "-version" not in call and "sha256sum" not in call]

    def test_successful_attempt_reused_without_rerun(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        before = {p.name: p.read_bytes() for p in base.iterdir()}
        ref_before = self.store.load("aB3x9").artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        _, backend = self._run_shadow([])
        self.assertEqual(backend.calls, [])
        after = {p.name: p.read_bytes() for p in base.iterdir()}
        self.assertEqual(after, before)
        ref_after = self.store.load("aB3x9").artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE)
        self.assertEqual(ref_after.sha256, ref_before.sha256)

    def test_incomplete_attempt_is_not_mistaken_for_coverage(self):
        timeout = BackendResult(("nuclei",), 124, b"", b"", True)
        self._run_shadow([timeout, _success_result(b""), _success_result(b"")])
        _, backend = self._run_shadow(
            [_success_result(b""), _success_result(b""), _success_result(b"")])
        executions = self._execution_calls(backend)
        self.assertEqual(len(executions), 1)
        base = dynamic_dir(self.store.output_root, "aB3x9")
        self.assertTrue(any("_attempt_2_" in p.name for p in base.iterdir()))
        state = self.store.load("aB3x9")
        summary_path = Path(state.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE).path)
        summary = json.loads(summary_path.read_bytes())
        by_cve = {c["cve_id"]: c for c in summary["candidates"]}
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "NOT_OBSERVED")

    def test_stale_artifact_hash_does_not_count_as_completed(self):
        self._run_shadow([_success_result(_match_payload()), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        target = next(p for p in base.glob("*.jsonl") if "_attempt_1_" in p.name)
        with target.open("ab") as handle:
            handle.write(b"tampered")
        _, backend = self._run_shadow(
            [_success_result(b""), _success_result(b""), _success_result(b"")])
        self.assertEqual(len(self._execution_calls(backend)), 1)


class AppScopeTests(unittest.TestCase):
    """Wave 3.1: same template bound to multiple reviewed base paths."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "output")
        self.manifest_path = _template_tree(self.root / "templates")
        self.top30_path = _post_step3_state(self.store)
        self.top30_before = self.top30_path.read_bytes()

    def _run_shadow(self, results: list[BackendResult], **overrides):
        backend = RoutingNucleiBackend(results)
        sandboxes: list = []
        orchestrator = _orchestrator(self.store, backend, sandboxes)
        state = orchestrator.run_shadow("aB3x9", _shadow_config(
            self.root / "templates", **overrides))
        return state, backend

    def _summary(self):
        base = dynamic_dir(self.store.output_root, "aB3x9")
        summaries = sorted(base.glob("dynamic_shadow_*.json"))
        self.assertTrue(summaries)
        return json.loads(summaries[-1].read_bytes())

    def _by_cve(self, summary):
        return {c["cve_id"]: c for c in summary["candidates"]}

    def _clean6(self):
        return [_success_result(b"") for _ in range(6)]

    def test_reused_execution_requires_same_container_id(self):
        from kalama.dynamic_shadow import (
            DYNAMIC_RESULT_SCHEMA, load_verified_results)
        base = dynamic_dir(self.store.output_root, "aB3x9")
        base.mkdir(parents=True, exist_ok=True)
        raw = base / "dynamic_nuclei_aB3x9_attempt_1_CVE-2017-5638_t1.jsonl"
        raw.write_bytes(b"")
        record = {
            "schema": DYNAMIC_RESULT_SCHEMA, "run_id": "aB3x9", "attempt": "1",
            "candidate_cve": "CVE-2017-5638", "template_id": "t1",
            "execution_status": "SUCCEEDED", "reachable": True,
            "match_count": 0, "base_path": "/",
            "container_id": "victim-old",
            "endpoint": {"container_id": "victim-old", "scheme": "http",
                         "port": 8080, "ip_address": "10.0.0.2",
                         "network": "kalama-probe-aB3x9-1"},
            "template_sha256": _sha(MINIMAL_HTTP_TEMPLATE),
            "template_manifest": {"sha256": "manifest-sha"},
            "raw_artifact": {"path": str(raw), "sha256": hashlib.sha256(b"").hexdigest()},
        }
        (base / "dynamic_nuclei_result_aB3x9_attempt_1_CVE-2017-5638_t1.json"
         ).write_text(json.dumps(record), encoding="utf-8")
        entries = {"t1": _sha(MINIMAL_HTTP_TEMPLATE)}
        same = load_verified_results(
            base, "aB3x9", manifest_entries=entries, manifest_sha256="manifest-sha",
            expected_container_id="victim-old", expected_scheme="http",
            expected_port=8080)
        self.assertEqual(
            list(same), [("CVE-2017-5638", "t1", "/")])
        replaced = load_verified_results(
            base, "aB3x9", manifest_entries=entries, manifest_sha256="manifest-sha",
            expected_container_id="victim-new", expected_scheme="http",
            expected_port=8080)
        self.assertEqual(replaced, {})

    def test_match_on_one_path_corrorborates(self):
        self._run_shadow([_success_result(b""), _success_result(_match_payload()),
                          _success_result(b""), _success_result(b""),
                          _success_result(b""), _success_result(b"")],
                         app_paths=("/", "/app/"))
        by_cve = self._by_cve(self._summary())
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "CORROBORATED")
        self.assertEqual(by_cve["CVE-2020-0001"]["signal"], "NOT_OBSERVED")
        self.assertEqual(by_cve["CVE-2099-9999"]["signal"], "NOT_APPLICABLE")
        refs = by_cve["CVE-2017-5638"]["dynamic_validation"]["evidence_refs"]
        self.assertEqual(len(refs), 1)
        # Same template on two paths yields two distinct executions.
        base = dynamic_dir(self.store.output_root, "aB3x9")
        raws = sorted(base.glob("dynamic_nuclei_aB3x9_attempt_1_CVE-2017-5638_t1*.jsonl"))
        self.assertEqual(len(raws), 2)
        bodies = sorted(p.read_bytes() for p in raws)
        self.assertIn(_match_payload(), bodies)
        manifests = sorted(base.glob(
            "dynamic_nuclei_result_aB3x9_attempt_1_CVE-2017-5638_t1*.json"))
        self.assertEqual(len(manifests), 2)
        paths = sorted(json.loads(p.read_bytes())["base_path"] for p in manifests)
        self.assertEqual(paths, ["/", "/app/"])
        for path in manifests:
            document = json.loads(path.read_bytes())
            self.assertIn("application_endpoint_key", document)
            self.assertIn("effective_target_url", document)
            self.assertEqual(document["base_path_source"],
                             "default_root" if document["base_path"] == "/"
                             else "explicit_reviewed_binding")
        bindings = by_cve["CVE-2017-5638"]["applicable_bindings"]
        self.assertEqual(
            sorted((b["template_id"], b["base_path"]) for b in bindings),
            [("t1", "/"), ("t1", "/app/"), ("t2", "/"), ("t2", "/app/")])

    def test_all_paths_clean_not_observed(self):
        self._run_shadow(self._clean6(), app_paths=("/", "/app/"))
        by_cve = self._by_cve(self._summary())
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "NOT_OBSERVED")
        self.assertEqual(by_cve["CVE-2020-0001"]["signal"], "NOT_OBSERVED")

    def test_one_path_incomplete_is_inconclusive(self):
        timeout = BackendResult(("nuclei",), 124, b"", b"", True)
        self._run_shadow([_success_result(b""), timeout] + self._clean6()[2:],
                         app_paths=("/", "/app/"))
        by_cve = self._by_cve(self._summary())
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "INCONCLUSIVE")
        self.assertEqual(by_cve["CVE-2020-0001"]["signal"], "NOT_OBSERVED")

    def test_resume_does_not_confuse_path_a_with_path_b(self):
        self._run_shadow([_success_result(b""), _success_result(b""),
                          _success_result(b"")])
        _, backend = self._run_shadow(
            [_success_result(b""), _success_result(b""), _success_result(b"")],
            app_paths=("/", "/app/"))
        base = dynamic_dir(self.store.output_root, "aB3x9")
        app_results = [p for p in base.glob("dynamic_nuclei_result_*.json")
                       if p.read_bytes().find(b"/app/") != -1]
        self.assertEqual(len(app_results), 3)
        root_results = [p for p in base.glob("dynamic_nuclei_result_*.json")
                        if json.loads(p.read_bytes()).get("base_path", "/") == "/"]
        self.assertEqual(len(root_results), 3)
        by_cve = self._by_cve(self._summary())
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "NOT_OBSERVED")

    def test_root_only_run_keeps_legacy_artifact_names(self):
        self._run_shadow([_success_result(b""), _success_result(b""),
                          _success_result(b"")])
        base = dynamic_dir(self.store.output_root, "aB3x9")
        names = sorted(p.name for p in base.iterdir())
        scoped = [name for name in names if name.startswith("dynamic_nuclei_")]
        self.assertTrue(scoped)
        self.assertTrue(all("_attempt_1" in name for name in scoped))
        # No application-scope suffix anywhere in a root-only run.
        self.assertFalse([name for name in names if "__" in name])
        manifests = sorted(base.glob("dynamic_nuclei_result_*.json"))
        self.assertTrue(manifests)
        for path in manifests:
            self.assertEqual(json.loads(path.read_bytes())["base_path"], "/")
        by_cve = self._by_cve(self._summary())
        self.assertEqual(by_cve["CVE-2017-5638"]["signal"], "NOT_OBSERVED")

    def test_feature_off_leaves_state_untouched(self):
        before = self.store.load("aB3x9")
        backend = RoutingNucleiBackend([])
        orchestrator = _orchestrator(self.store, backend, [])
        after = orchestrator.run_shadow(
            "aB3x9", _shadow_config(self.root / "templates", enabled=False,
                                    app_paths=("/", "/app/")))
        self.assertEqual(after.updated_at, before.updated_at)
        self.assertEqual(backend.calls, [])
        self.assertIsNone(after.artifact(ArtifactKind.DYNAMIC_SHADOW_BEFORE))

    def test_priority_v1_artifact_order_scores_and_delta_unchanged(self):
        self._run_shadow(self._clean6(), app_paths=("/", "/app/"))
        self.assertEqual(self.top30_path.read_bytes(), self.top30_before)
        summary = self._summary()
        self.assertEqual(
            [c["cve_id"] for c in summary["candidates"]],
            ["CVE-2017-5638", "CVE-2020-0001", "CVE-2099-9999"])
        for candidate in summary["candidates"]:
            self.assertEqual(candidate["score"]["total_display"],
                             {"CVE-2017-5638": "10", "CVE-2020-0001": "9",
                              "CVE-2099-9999": "8"}[candidate["cve_id"]])
            self.assertEqual(
                candidate["dynamic_validation"]["score_delta"], 0)


if __name__ == "__main__":
    unittest.main()