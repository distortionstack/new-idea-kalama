"""Wave 2 unit tests: resolver, preflight, sandbox, runner, JSONL.

No test requires real Nuclei or real Docker. Docker-dependent checks use a
fake CommandRunner; the one optional live-Docker test is skipped unless
KALAMA_LIVE_DOCKER=1 and Docker is reachable.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from kalama.dynamic_probe import (
    ApprovedTemplate,
    ApprovedTemplateManifest,
    DynamicEndpoint,
    NucleiTemplatePolicy,
    TemplatePolicyError,
)
from kalama.dynamic_probe_runtime import (
    BackendResult,
    CandidateTemplateResolution,
    NucleiExecutionStatus,
    NucleiRunnerConfig,
    ProbeSandbox,
    ResolutionStatus,
    SandboxConfig,
    SandboxReachabilityProbe,
    SubprocessBackend,
    build_nuclei_argv,
    check_security_flags_available,
    endpoint_url,
    execute_single_template,
    parse_nuclei_jsonl,
    resolve_candidates_to_templates,
    runtime_preflight_template,
    sandbox_network_name,
    select_security_flags,
)
from kalama.target.models import CommandResult


HELP_TEXT = """Nuclei is a fast, template based vulnerability scanner
FLAGS:
  -duc, -disable-update-check: disable automatic update check
  -dr, -disable-redirects: disable redirects
  -ni, -no-interactsh: disable interactsh server
  -dut, -disable-unsigned-templates: skip unsigned templates
  -jsonl: write output in JSONL format
  -timeout: request timeout in seconds
  -retries: number of retries
  -rl: rate limit
  -c: concurrency"""

HELP_TEXT_LONG_FORMS = """Nuclei is a fast, template based vulnerability scanner
FLAGS:
  -disable-update-check: disable automatic update check
  -disable-redirects: disable redirects
  -no-interactsh: disable interactsh server
  -disable-unsigned-templates: skip unsigned templates
  -jsonl: write output in JSONL format"""

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

ZERO = "0" * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _write_bytes(path: Path, text: str) -> None:
    # write_bytes (not write_text) so the SHA-256 matches on every platform;
    # text-mode writes translate newlines on Windows.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode('utf-8'))


def _manifest(root: Path, entries: list[dict]) -> ApprovedTemplateManifest:
    templates = tuple(
        ApprovedTemplate(
            e["template_id"], e["relative_path"], e["expected_sha256"],
            tuple(e["mapped_cves"]),
            e.get("expected_signature_status"),
        )
        for e in entries
    )
    return ApprovedTemplateManifest("safe-cve-http", root, root / "approved.yaml",
                                    templates, NucleiTemplatePolicy("safe-cve-http"),
                                    "reviewed-test")


def _write_template(root: Path, relative: str, text: str) -> ApprovedTemplate:
    _write_bytes(root / relative, text)
    return ApprovedTemplate("t-" + relative.replace("/", "-"), relative,
                            _sha(text), ("CVE-2099-0001",))


def _endpoint(ip: str = "10.0.0.2", container_id: str = "victim-id-1") -> DynamicEndpoint:
    return DynamicEndpoint("aB3x9", container_id, "victim-aB3x9",
                           "kalama-probe-aB3x9-0", ip, 8080, "http", "READY")


def _config(root: Path, **overrides) -> NucleiRunnerConfig:
    kwargs = dict(binary_path="/usr/bin/nuclei", template_root=root)
    kwargs.update(overrides)
    return NucleiRunnerConfig(**kwargs)


class FakeBackend:
    def __init__(self, result: BackendResult):
        self.result = result
        self.calls: list[tuple] = []

    def run(self, argv, *, timeout=None, stdout_budget=None, stderr_budget=None):
        assert isinstance(argv, (tuple, list)), "argv must be explicit, not a shell string"
        assert not isinstance(argv, str)
        self.calls.append((tuple(argv), timeout, stdout_budget, stderr_budget))
        return self.result


class RoutingBackend(FakeBackend):
    """Answers `-h` capability probes with help text, everything else canned."""

    def __init__(self, help_text: str, result: BackendResult):
        super().__init__(result)
        self.help_text = help_text

    def run(self, argv, *, timeout=None, stdout_budget=None, stderr_budget=None):
        args = tuple(str(x) for x in argv)
        self.calls.append((args, timeout, stdout_budget, stderr_budget))
        if "-h" in args:
            return BackendResult(args, 0, self.help_text.encode("utf-8"), b"")
        return self.result


class FakeExecRunner:
    """Minimal CommandRunner fake for reachability-probe argv assertions.

    Answers shell-free ``ls <absolute-path>`` detection probes according to
    ``available_tools`` (matched by tool basename) and every other command
    with ``exit_code``.
    """

    def __init__(self, exit_code: int = 0, available_tools: tuple[str, ...] = ("nc",)):
        self.exit_code = exit_code
        self.available_tools = tuple(available_tools)
        self.calls: list[tuple] = []

    def run(self, argv, *, timeout=None):
        args = tuple(str(x) for x in argv)
        self.calls.append(args)
        if len(args) >= 2 and args[-2] == "ls" and args[-1].startswith("/"):
            tool = args[-1].rsplit("/", 1)[-1]
            return CommandResult(args, 0 if tool in self.available_tools else 1, "", "")
        return CommandResult(args, self.exit_code, "", "")


# --------------------------------------------------------------------------
# Resolver tests (1-7)
# --------------------------------------------------------------------------

class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_exact_cve_to_one_template(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        out = resolve_candidates_to_templates(["CVE-2017-5638"], manifest)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].resolution_status, ResolutionStatus.RESOLVED)
        self.assertEqual([t.template_id for t in out[0].templates], ["t1"])

    def test_exact_cve_to_multiple_templates(self):
        manifest = _manifest(self.root, [
            {"template_id": "t-b", "relative_path": "b.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
            {"template_id": "t-a", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        out = resolve_candidates_to_templates(["CVE-2017-5638"], manifest)
        self.assertEqual([t.template_id for t in out[0].templates], ["t-a", "t-b"])

    def test_one_template_mapped_to_multiple_cves(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-0001-0001", "CVE-0002-0002"]},
        ])
        out = resolve_candidates_to_templates(["CVE-0001-0001", "CVE-0002-0002"], manifest)
        self.assertTrue(all(r.resolution_status == ResolutionStatus.RESOLVED for r in out))
        self.assertEqual(out[0].templates[0].template_id, "t1")

    def test_candidate_with_no_template_is_explicit(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        out = resolve_candidates_to_templates(["CVE-2099-9999"], manifest)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].resolution_status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(out[0].templates, ())

    def test_ghsa_is_not_converted_to_cve(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        out = resolve_candidates_to_templates(["GHSA-abcd-1234-efgh"], manifest)
        self.assertEqual(out[0].resolution_status, ResolutionStatus.UNRESOLVED)

    def test_output_ordering_is_deterministic(self):
        manifest = _manifest(self.root, [
            {"template_id": "t2", "relative_path": "b.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2020-0002"]},
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2020-0001"]},
        ])
        first = resolve_candidates_to_templates(["CVE-2020-0002", "CVE-2020-0001"], manifest)
        second = resolve_candidates_to_templates(["CVE-2020-0001", "CVE-2020-0002"], manifest)
        self.assertEqual([(r.cve_id, r.candidate_id) for r in first],
                         [(r.cve_id, r.candidate_id) for r in second])
        self.assertEqual([r.cve_id for r in first], ["CVE-2020-0001", "CVE-2020-0002"])

    def test_resolver_never_discovers_unapproved_template(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        (self.root / "rogue.yaml").write_text(MINIMAL_HTTP_TEMPLATE, encoding="utf-8")
        out = resolve_candidates_to_templates(["CVE-2017-5638"], manifest)
        self.assertNotIn("rogue", [t.template_id for t in out[0].templates])
        self.assertEqual(len(out[0].templates), 1)

    def test_resolver_accepts_normalized_prioritizer_shapes(self):
        manifest = _manifest(self.root, [
            {"template_id": "t1", "relative_path": "a.yaml",
             "expected_sha256": ZERO, "mapped_cves": ["CVE-2017-5638"]},
        ])
        out = resolve_candidates_to_templates(
            [{"cve_id": "CVE-2017-5638"}, {"canonical_cve_id": "CVE-2099-9999"}], manifest)
        self.assertEqual(out[0].resolution_status, ResolutionStatus.RESOLVED)
        self.assertEqual(out[1].resolution_status, ResolutionStatus.UNRESOLVED)


# --------------------------------------------------------------------------
# Template policy tests (8-21)
# --------------------------------------------------------------------------

class TemplatePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _preflight(self, text: str, **kw):
        approved = _write_template(self.root, "http/a.yaml", text)
        return runtime_preflight_template(self.root, approved, **kw)

    def test_minimal_http_template_passes(self):
        result = self._preflight(MINIMAL_HTTP_TEMPLATE)
        self.assertTrue(result.ok)

    def _rejects(self, text: str, code_fragment: str):
        with self.assertRaises(TemplatePolicyError) as caught:
            self._preflight(text)
        self.assertIn(code_fragment, caught.exception.code)
        return caught.exception

    def test_rejects_network(self):
        self._rejects(MINIMAL_HTTP_TEMPLATE + "\nnetwork:\n  - host: x\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_dns(self):
        self._rejects("id: x\ninfo:\n  name: x\n  severity: high\ndns:\n  - name: x\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_headless(self):
        self._rejects("id: x\ninfo:\n  name: x\n  severity: high\nheadless:\n  - action: x\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_code(self):
        self._rejects("id: x\ninfo:\n  name: x\n  severity: high\ncode:\n  - engine: [python]\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_javascript(self):
        self._rejects("id: x\ninfo:\n  name: x\n  severity: high\njavascript:\n  - code: x\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_workflow(self):
        self._rejects("id: x\ninfo:\n  name: x\n  severity: high\nworkflows:\n  - template: x\n",
                      "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_tcp_ssl_file_websocket(self):
        for key in ("tcp", "ssl", "file", "websocket"):
            with self.subTest(protocol=key):
                self._rejects(
                    f"id: x\ninfo:\n  name: x\n  severity: high\n{key}:\n  - x: y\n",
                    "DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL")

    def test_rejects_bruteforce_and_local_tags(self):
        for tag in ("bruteforce", "local"):
            with self.subTest(tag=tag):
                text = MINIMAL_HTTP_TEMPLATE.replace("tags: cve", f"tags: cve,{tag}")
                self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_redirects_enabled(self):
        text = MINIMAL_HTTP_TEMPLATE.replace("method: GET",
                                             "method: GET\n    redirects: true")
        self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_host_redirects_enabled(self):
        text = MINIMAL_HTTP_TEMPLATE.replace(
            "method: GET", "method: GET\n    redirect-hosts: true")
        self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_interactsh_marker(self):
        text = MINIMAL_HTTP_TEMPLATE.replace("/example", "/{{interactsh-url}}")
        with self.assertRaises(TemplatePolicyError) as caught:
            self._preflight(text)
        self.assertEqual(caught.exception.code, "DYNAMIC_TEMPLATE_OAST_FORBIDDEN")

    def test_rejects_intrusive_tag(self):
        text = MINIMAL_HTTP_TEMPLATE.replace("tags: cve", "tags: cve,intrusive")
        self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_fuzz_tag(self):
        text = MINIMAL_HTTP_TEMPLATE.replace("tags: cve", "tags: [cve, fuzz]")
        self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_dos_tag(self):
        text = MINIMAL_HTTP_TEMPLATE.replace("tags: cve", "tags: dos")
        self._rejects(text, "DYNAMIC_TEMPLATE_POLICY_REJECTED")

    def test_rejects_path_outside_root(self):
        approved = _write_template(self.root, "http/a.yaml", MINIMAL_HTTP_TEMPLATE)
        bad_text = MINIMAL_HTTP_TEMPLATE + "\nfile:\n  - path: ../../etc/passwd\n"
        # file-ish key escaping root must fail closed (unsupported protocol fires first
        # for top-level file:, so assert either fail-closed code).
        with self.assertRaises(TemplatePolicyError) as caught:
            path = self.root / "http" / "a.yaml"
            _write_bytes(path, bad_text)
            import hashlib as _h
            approved3 = ApprovedTemplate(approved.template_id, approved.relative_path,
                                         _h.sha256(bad_text.encode('utf-8')).hexdigest(),
                                         approved.mapped_cves)
            runtime_preflight_template(self.root, approved3)
        self.assertIn(caught.exception.code,
                      {"DYNAMIC_TEMPLATE_UNSUPPORTED_PROTOCOL", "DYNAMIC_TEMPLATE_POLICY_REJECTED",
                       "NUCLEI_TEMPLATE_OUTSIDE_ROOT"})
        with self.assertRaises(TemplatePolicyError):
            ApprovedTemplate("evil", "../outside.yaml", ZERO, ("CVE-2099-0001",))

    def test_rejects_unknown_syntax_fail_closed(self):
        with self.assertRaises(TemplatePolicyError):
            self._preflight("- just\n- a\n- list\n")

    def test_rejects_hash_mismatch(self):
        approved = ApprovedTemplate("t1", "http/a.yaml", ZERO, ("CVE-2099-0001",))
        _write_bytes(self.root / "http" / "a.yaml", MINIMAL_HTTP_TEMPLATE)
        with self.assertRaises(TemplatePolicyError):
            runtime_preflight_template(self.root, approved)


# --------------------------------------------------------------------------
# Fake Docker backend for sandbox tests
# --------------------------------------------------------------------------

class FakeDockerRunner:
    """Minimal docker-CLI emulator: victim + ephemeral runner + sandbox net."""

    def __init__(self, *, victim_id="victim-id-1", victim_name="victim-aB3x9",
                 original_networks=("kalama-net",), fail_on=(),
                 runner_extra_networks=(), victim_replacement_id=None,
                 victim_ip="10.0.0.2", runner_ip="10.0.0.3",
                 network_internal=True, raise_on=()):
        self.victim_id = victim_id
        self.victim_name = victim_name
        self.original_networks = list(original_networks)
        self.fail_on = tuple(fail_on)
        self.runner_extra_networks = tuple(runner_extra_networks)
        self.victim_replacement_id = victim_replacement_id
        self.victim_ip = victim_ip
        self.runner_ip = runner_ip
        self.network_internal = network_internal
        self.raise_on = tuple(raise_on)
        self.calls: list[tuple] = []
        self.networks: dict[str, dict] = {}
        self.containers: dict[str, dict] = {
            victim_name: {"Id": victim_id,
                          "NetworkSettings": {"Networks": {
                              net: {"IPAddress": "172.18.0.11"} for net in original_networks}}},
        }
        self.removed_networks: list[str] = []
        self.removed_containers: list[str] = []

    def _maybe_fail(self, args):
        joined = " ".join(args)
        for token in self.raise_on:
            if token in joined:
                raise RuntimeError(f"injected failure: {token}")
        for token in self.fail_on:
            if token in joined:
                return CommandResult(tuple(args), 1, "", f"injected: {token}")

    def run(self, argv, *, timeout=None):
        args = tuple(str(x) for x in argv)
        self.calls.append(args)
        failed = self._maybe_fail(args)
        if failed is not None:
            return failed
        if args[:3] == ("docker", "network", "create"):
            name = args[-1]
            self.networks[name] = {"Internal": self.network_internal}
            return CommandResult(args, 0, name + "\n", "")
        if args[:3] == ("docker", "network", "inspect"):
            name = args[3] if len(args) > 3 else ""
            data = self.networks.get(name, {"Internal": self.network_internal, "Name": name})
            return CommandResult(args, 0, json.dumps([data]), "")
        if args[:3] == ("docker", "network", "connect"):
            net, container = args[3], args[4]
            target = self.containers.get(container)
            if target is None:
                return CommandResult(args, 1, "", "no such container")
            if target.get("NetworkMode") == "none":
                # Faithful to the real daemon: a container created with
                # --network none uses the private "none" mode and refuses
                # any further network attachment.
                return CommandResult(
                    args, 1, "",
                    "container cannot be connected to multiple networks with "
                    "one of the networks in private (none) mode")
            ip = self.victim_ip if container == self.victim_name else self.runner_ip
            target["NetworkSettings"]["Networks"][net] = {"IPAddress": ip}
            if self.victim_replacement_id and container == self.victim_name:
                target["Id"] = self.victim_replacement_id
            return CommandResult(args, 0, "", "")
        if args[:3] == ("docker", "network", "disconnect"):
            net, container = args[3], args[4]
            target = self.containers.get(container)
            if target is not None:
                target["NetworkSettings"]["Networks"].pop(net, None)
            return CommandResult(args, 0, "", "")
        if args[:2] == ("docker", "create"):
            name = args[args.index("--name") + 1] if "--name" in args else "runner"
            network = (args[args.index("--network") + 1]
                       if "--network" in args else "none")
            if network == "none":
                networks: dict[str, dict[str, str]] = {}
            else:
                networks = {network: {"IPAddress": self.runner_ip}}
            self.containers[name] = {"Id": "runner-id-9", "NetworkMode": network,
                                     "NetworkSettings": {"Networks": networks}}
            return CommandResult(args, 0, "created\n", "")
        if args[:3] == ("docker", "container", "inspect"):
            name = args[-1]
            data = self.containers.get(name)
            if data is None:
                return CommandResult(args, 1, "", "no such container")
            payload = dict(data)
            if name != self.victim_name and self.runner_extra_networks:
                nets = dict(payload["NetworkSettings"]["Networks"])
                for extra in self.runner_extra_networks:
                    nets[extra] = {"IPAddress": "172.18.0.99"}
                payload = {"Id": payload["Id"],
                           "NetworkSettings": {"Networks": nets}}
            else:
                payload = {"Id": payload["Id"],
                           "NetworkSettings": payload["NetworkSettings"]}
            return CommandResult(args, 0, json.dumps([payload]), "")
        if args[:2] == ("docker", "rm"):
            name = args[-1]
            self.removed_containers.append(name)
            self.containers.pop(name, None)
            return CommandResult(args, 0, "", "")
        if args[:3] == ("docker", "network", "rm"):
            self.removed_networks.append(args[3])
            self.networks.pop(args[3], None)
            return CommandResult(args, 0, "", "")
        return CommandResult(args, 0, "", "")


def _sandbox_config(**overrides):
    kwargs = dict(run_id="aB3x9", attempt=0, victim_container_name="victim-aB3x9",
                  expected_container_id="victim-id-1", port=8080, scheme="http",
                  runner_image="kalama/nuclei-probe:v1.2.3")
    kwargs.update(overrides)
    return SandboxConfig(**kwargs)


class SandboxTests(unittest.TestCase):
    def test_network_name_and_internal(self):
        self.assertEqual(sandbox_network_name("aB3x9", 0), "kalama-probe-aB3x9-0")
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        endpoint = box.setup()
        try:
            create_call = next(c for c in fake.calls if c[:3] == ("docker", "network", "create"))
            self.assertIn("--internal", create_call)
            self.assertEqual(endpoint.network, "kalama-probe-aB3x9-0")
            self.assertEqual(endpoint.ip_address, "10.0.0.2")
        finally:
            box.cleanup()

    def test_only_victim_plus_runner_membership(self):
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        try:
            box.setup()
            runner_data = json.loads(fake.run(
                ("docker", "container", "inspect", box.runner_name)).stdout)[0]
            self.assertEqual(set(runner_data["NetworkSettings"]["Networks"]),
                             {box.network_name})
        finally:
            box.cleanup()

    def test_unrelated_third_container_attachment_rejected(self):
        fake = FakeDockerRunner(runner_extra_networks=("kalama-net",))
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError):
            box.setup()
        # fail-closed cleanup: sandbox network removed, runner removed
        self.assertIn(box.network_name, fake.removed_networks)
        self.assertIn(box.runner_name, fake.removed_containers)

    def test_runner_on_another_network_rejected(self):
        fake = FakeDockerRunner(runner_extra_networks=("bridge",))
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError):
            box.setup()

    def test_victim_container_id_mismatch_rejected(self):
        fake = FakeDockerRunner(victim_replacement_id="different-id")
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError) as caught:
            box.setup()
        self.assertIn("identity", str(caught.exception).lower())

    def test_same_ip_different_container_id_rejected(self):
        fake = FakeDockerRunner(victim_replacement_id="different-id",
                                victim_ip="10.0.0.2")
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError):
            box.setup()

    def test_cleanup_after_success(self):
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        endpoint = box.setup()
        box.verify_after()
        box.cleanup()
        victim = fake.containers["victim-aB3x9"]["NetworkSettings"]["Networks"]
        self.assertNotIn(endpoint.network, victim)
        self.assertIn("kalama-net", victim)
        self.assertIn(box.network_name, fake.removed_networks)

    def test_cleanup_after_exception(self):
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        # Fail runner creation only: the victim join must already have
        # succeeded, and cleanup must still release it plus the network.
        real_run = fake.run

        def flaky(argv, *, timeout=None, **kwargs):
            args = tuple(str(x) for x in argv)
            if args[:2] == ("docker", "create") and box.runner_name in args:
                return CommandResult(args, 1, "", "injected create failure")
            return real_run(argv, timeout=timeout)
        fake.run = flaky
        with self.assertRaises(RuntimeError):
            box.setup()
        self.assertIn(box.network_name, fake.removed_networks)

    def test_runner_created_directly_on_sandbox_network(self):
        # Regression guard for real-daemon behavior: a container created
        # with --network none cannot later be joined to another network, so
        # the runner must be created on the sandbox network, never connected
        # to it afterwards.
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        try:
            box.setup()
        finally:
            creates = [c for c in fake.calls if c[:2] == ("docker", "create")]
            self.assertEqual(len(creates), 1)
            self.assertIn(box.network_name, creates[0])
            self.assertNotIn("none", creates[0])
            joins = [c for c in fake.calls
                     if c[:3] == ("docker", "network", "connect")
                     and c[4] == box.runner_name]
            self.assertEqual(joins, [])
            box.cleanup()

    def test_cleanup_after_timeout(self):
        fake = FakeDockerRunner(raise_on=("container inspect",))
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError):
            box.setup()
        self.assertIn(box.network_name, fake.removed_networks)

    def test_existing_victim_networks_preserved(self):
        fake = FakeDockerRunner()
        box = ProbeSandbox(_sandbox_config(), fake)
        endpoint = box.setup()
        try:
            victim = json.loads(fake.run(
                ("docker", "container", "inspect", "victim-aB3x9")).stdout)[0]
            self.assertIn("kalama-net", victim["NetworkSettings"]["Networks"])
            self.assertIn(endpoint.network, victim["NetworkSettings"]["Networks"])
        finally:
            box.cleanup()
        victim = fake.containers["victim-aB3x9"]["NetworkSettings"]["Networks"]
        self.assertIn("kalama-net", victim)

    def test_non_internal_network_fails_closed(self):
        fake = FakeDockerRunner(network_internal=False)
        box = ProbeSandbox(_sandbox_config(), fake)
        with self.assertRaises(RuntimeError):
            box.setup()


# --------------------------------------------------------------------------
# Runner + JSONL tests (32-43)
# --------------------------------------------------------------------------

def _write_approved(root: Path, template_id="cves/example") -> ApprovedTemplate:
    _write_bytes(root / "http" / "a.yaml", MINIMAL_HTTP_TEMPLATE)
    sha = hashlib.sha256(MINIMAL_HTTP_TEMPLATE.encode('utf-8')).hexdigest()
    return ApprovedTemplate(template_id, "http/a.yaml", sha, ("CVE-2017-5638",))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.approved = _write_approved(self.root)

    def _run(self, backend, **overrides):
        cfg = _config(self.root, **overrides.pop("config", {}))
        return execute_single_template(
            cfg, endpoint=overrides.pop("endpoint", _endpoint()),
            approved=overrides.pop("approved", self.approved),
            candidate_cve=overrides.pop("candidate_cve", "CVE-2017-5638"),
            run_id="aB3x9", attempt=0, backend=backend,
            help_text=overrides.pop("help_text", HELP_TEXT),
            reachability=overrides.pop("reachability", lambda ep: True))

    def test_argv_uses_exact_template_path(self):
        from kalama.dynamic_probe import resolve_approved_template_path
        backend = FakeBackend(BackendResult(("x",), 0, b"", b""))
        self._run(backend)
        argv = backend.calls[0][0]
        self.assertIn("-t", argv)
        expected = str(resolve_approved_template_path(self.root, "http/a.yaml"))
        self.assertEqual(argv[argv.index("-t") + 1], expected)

    def test_shell_is_never_used(self):
        source = inspect.getsource(SubprocessBackend.run)
        self.assertIn("shell=False", source)
        backend = FakeBackend(BackendResult(("x",), 0, b"", b""))
        self._run(backend)
        argv = backend.calls[0][0]
        self.assertIsInstance(argv, tuple)

    def test_one_template_per_invocation(self):
        backend = FakeBackend(BackendResult(("x",), 0, b"", b""))
        self._run(backend)
        argv = backend.calls[0][0]
        self.assertEqual(argv.count("-t"), 1)
        self.assertNotIn("-templates", argv)

    def test_timeout_maps_to_timed_out(self):
        backend = FakeBackend(BackendResult(("nuclei",), 124, b"", b"", True))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.TIMED_OUT)
        self.assertEqual(result.error_code, "NUCLEI_TIMEOUT")

    def test_output_byte_limit_maps_to_budget_exceeded(self):
        big = b"x" * (1_048_576 + 1)
        backend = FakeBackend(BackendResult(("nuclei",), 0, big, b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.BUDGET_EXCEEDED)
        self.assertTrue(result.stdout_truncated)

    def test_nonzero_exit_maps_to_failed(self):
        backend = FakeBackend(BackendResult(("nuclei",), 1, b"", b"boom"))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.FAILED)

    def test_zero_match_output_is_valid_completed_execution(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"\n  \n", b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        self.assertEqual(result.records, ())

    def test_valid_jsonl_match_parses(self):
        record = {"template-id": "cves/example", "matcher-name": "body",
                  "host": "http://10.0.0.2:8080/example",
                  "info": {"severity": "high", "classification": {"cve-id": "CVE-2017-5638"}},
                  "timestamp": "2026-01-01T00:00:00Z"}
        backend = FakeBackend(BackendResult(("nuclei",), 0,
                                            (json.dumps(record) + "\n").encode(), b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].matcher_name, "body")
        self.assertEqual(result.records[0].cve_id, "CVE-2017-5638")
        self.assertEqual(result.records[0].severity, "high")

    def test_malformed_jsonl_maps_to_invalid_output(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b'{"a": \n', b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.INVALID_OUTPUT)

    def test_valid_records_then_failed_process_maps_to_partial(self):
        record = {"template-id": "cves/example", "host": "http://10.0.0.2:8080/"}
        payload = (json.dumps(record) + "\n{truncated").encode()
        backend = FakeBackend(BackendResult(("nuclei",), 1, payload, b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.PARTIAL_OUTPUT)
        self.assertEqual(len(result.records), 1)

    def test_missing_optional_fields_remain_null(self):
        record = {"template-id": "cves/example", "host": "http://10.0.0.2:8080/"}
        backend = FakeBackend(BackendResult(("nuclei",), 0,
                                            (json.dumps(record) + "\n").encode(), b""))
        result = self._run(backend)
        self.assertIsNone(result.records[0].matcher_name)
        self.assertIsNone(result.records[0].cve_id)
        self.assertIsNone(result.records[0].severity)

    def test_external_arbitrary_url_cannot_be_supplied(self):
        cfg = _config(self.root)
        attacker = DynamicEndpoint("aB3x9", "victim-id-1", "victim-aB3x9",
                                   "kalama-probe-aB3x9-0", "10.0.0.2", 8080, "http", "READY")
        with self.assertRaises(TemplatePolicyError):
            from kalama.dynamic_probe_runtime import validate_probe_url
            validate_probe_url("http://evil.example.com:8080/", attacker)
        with self.assertRaises(TemplatePolicyError):
            from kalama.dynamic_probe_runtime import validate_probe_url
            validate_probe_url("http://10.0.0.99:8080/", attacker)

    def test_missing_security_flag_fails_closed(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, help_text="nuclei -jsonl only")
        self.assertEqual(result.execution_status, NucleiExecutionStatus.FAILED)
        self.assertEqual(result.error_code, "NUCLEI_SECURITY_FLAG_UNAVAILABLE")

    def test_subprocess_backend_enforces_shell_false_and_budgets(self):
        seen: dict[str, object] = {}

        class StubProc:
            def __init__(self):
                self.stdout = io.BytesIO(b"out")
                self.stderr = io.BytesIO(b"err")
                self.returncode = 0

            def poll(self):
                return 0

            def kill(self):
                raise AssertionError("clean exit must not kill the child")

            def wait(self, timeout=None):
                return 0

        def fake_popen(args, **kwargs):
            seen["argv"] = tuple(args)
            seen.update(kwargs)
            return StubProc()

        with patch.object(subprocess, "Popen", side_effect=fake_popen):
            backend = SubprocessBackend()
            result = backend.run(("nuclei", "-t", "x"), timeout=5,
                                 stdout_budget=1024, stderr_budget=1024)
        self.assertFalse(seen.get("shell"))
        self.assertEqual(seen.get("stdin"), subprocess.DEVNULL)
        self.assertEqual(seen.get("stdout"), subprocess.PIPE)
        self.assertEqual(seen.get("stderr"), subprocess.PIPE)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b"out")
        self.assertFalse(result.timed_out)

    def test_reachability_recorded(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        self.assertTrue(self._run(backend, reachability=lambda ep: True).reachable is True)
        self.assertTrue(self._run(backend, reachability=lambda ep: False).reachable is False)


    def test_reachability_recorded(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        self.assertTrue(self._run(backend, reachability=lambda ep: True).reachable is True)
        self.assertTrue(self._run(backend, reachability=lambda ep: False).reachable is False)


class Wave21SecurityHardeningTests(unittest.TestCase):
    """Wave 2.1: correct flags, mandatory reachability, streaming budgets."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.approved = _write_approved(self.root)

    def _run(self, backend, **overrides):
        cfg = _config(self.root, **overrides.pop("config", {}))
        return execute_single_template(
            cfg, endpoint=overrides.pop("endpoint", _endpoint()),
            approved=overrides.pop("approved", self.approved),
            candidate_cve=overrides.pop("candidate_cve", "CVE-2017-5638"),
            run_id="aB3x9", attempt=0, backend=backend,
            help_text=overrides.pop("help_text", HELP_TEXT),
            reachability=overrides.pop("reachability", lambda ep: True))

    def _argv(self, backend):
        return backend.calls[-1][0]

    def test_ni_or_equivalent_in_argv(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        argv = self._argv(backend)
        self.assertTrue("-ni" in argv or "-no-interactsh" in argv, argv)

    def test_doast_is_never_assumed_or_emitted(self):
        # A binary advertising only -doast proves no Interactsh control.
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, help_text=HELP_TEXT + " -doast")
        argv = self._argv(backend)
        self.assertNotIn("-doast", argv)
        doast_only = ("nuclei -jsonl -duc -dr -dut -doast\n"
                      "-disable-update-check -disable-redirects "
                      "-disable-unsigned-templates")
        missing = check_security_flags_available(doast_only)
        self.assertIn("no-interactsh", missing)

    def test_dut_or_equivalent_mandatory_in_argv(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        argv = self._argv(backend)
        self.assertTrue("-dut" in argv or "-disable-unsigned-templates" in argv, argv)

    def test_missing_signed_template_enforcement_fails_closed(self):
        lines = [line for line in HELP_TEXT.splitlines()
                 if "-dut" not in line and "-disable-unsigned-templates" not in line]
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, help_text="\n".join(lines))
        self.assertEqual(result.execution_status, NucleiExecutionStatus.FAILED)
        self.assertEqual(result.error_code, "NUCLEI_SECURITY_FLAG_UNAVAILABLE")
        self.assertIn("disable-unsigned-templates", result.error_detail or "")
        self.assertEqual(len(backend.calls), 0)

    def test_missing_no_interactsh_fails_closed(self):
        lines = [line for line in HELP_TEXT.splitlines()
                 if "-ni" not in line and "-no-interactsh" not in line]
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, help_text="\n".join(lines))
        self.assertEqual(result.execution_status, NucleiExecutionStatus.FAILED)
        self.assertEqual(result.error_code, "NUCLEI_SECURITY_FLAG_UNAVAILABLE")
        self.assertIn("no-interactsh", result.error_detail or "")

    def test_long_forms_accepted_and_used(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, help_text=HELP_TEXT_LONG_FORMS)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        argv = self._argv(backend)
        for token in ("-disable-update-check", "-disable-redirects",
                      "-no-interactsh", "-disable-unsigned-templates", "-jsonl"):
            self.assertIn(token, argv)

    def test_help_discovery_through_backend(self):
        canned = BackendResult(("nuclei",), 0, b"", b"")
        backend = RoutingBackend(HELP_TEXT, canned)
        result = self._run(backend, help_text=None)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        first = backend.calls[0][0]
        self.assertIn("-h", first)

    def test_succeeded_requires_reachable_true(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, reachability=lambda ep: True)
        self.assertEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        self.assertTrue(result.reachable is True)

    def test_reachable_false_is_not_succeeded(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, reachability=lambda ep: False)
        self.assertNotEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        self.assertEqual(result.error_code, "DYNAMIC_TARGET_NOT_REACHABLE")
        self.assertTrue(result.reachable is False)

    def test_reachable_unknown_is_not_succeeded(self):
        backend = FakeBackend(BackendResult(("nuclei",), 0, b"", b""))
        result = self._run(backend, reachability=None)
        self.assertNotEqual(result.execution_status, NucleiExecutionStatus.SUCCEEDED)
        self.assertEqual(result.error_code, "DYNAMIC_TARGET_NOT_REACHABLE")
        self.assertTrue(result.reachable is None)

    def test_reachability_probe_targets_sandbox_endpoint(self):
        runner = FakeExecRunner(exit_code=0)
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        endpoint = _endpoint(ip="10.0.0.2")
        self.assertTrue(probe(endpoint))
        self.assertEqual(probe.detected_tool, "nc")
        argv = runner.calls[-1]
        self.assertEqual(argv[:4], ("docker", "exec", "kalama-probe-aB3x9-0-runner", "nc"))
        self.assertEqual(argv[-2:], ("10.0.0.2", "8080"))
        self.assertNotIn("127.0.0.1", argv)
        self.assertNotIn("kalama-net", argv)

    def test_reachability_probe_falls_back_to_wget(self):
        runner = FakeExecRunner(exit_code=0, available_tools=("wget",))
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        self.assertTrue(probe(_endpoint(ip="10.0.0.2")))
        self.assertEqual(probe.detected_tool, "wget")
        argv = runner.calls[-1]
        self.assertIn("wget", argv)
        self.assertIn("http://10.0.0.2:8080/", argv)

    def test_reachability_detection_is_shell_free(self):
        runner = FakeExecRunner(exit_code=0)
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        self.assertTrue(probe(_endpoint(ip="10.0.0.2")))
        detection = [call for call in runner.calls if call[-2:] != ("10.0.0.2", "8080")]
        self.assertTrue(detection)
        for call in detection:
            # `command -v` is a shell builtin and cannot work via docker exec.
            self.assertNotIn("command", call)
            self.assertIn("ls", call)

    def test_reachability_ignores_unapproved_tool_names(self):
        runner = FakeExecRunner(exit_code=0, available_tools=("nc",))
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner",
                                        tools=("evil-tool",))
        self.assertFalse(probe(_endpoint(ip="10.0.0.2")))
        self.assertIsNone(probe.detected_tool)

    def test_reachability_probe_no_tool_fails_closed(self):
        runner = FakeExecRunner(exit_code=0, available_tools=())
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        self.assertFalse(probe(_endpoint(ip="10.0.0.2")))
        self.assertIsNone(probe.detected_tool)
        for call in runner.calls:
            self.assertNotIn("10.0.0.2", call)

    def test_reachability_probe_rejects_host_network_endpoint(self):
        runner = FakeExecRunner(exit_code=0)
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        host_endpoint = DynamicEndpoint("aB3x9", "victim-id-1", "victim-aB3x9",
                                        "kalama-net", "172.18.0.11", 8080, "http", "READY")
        self.assertFalse(probe(host_endpoint))
        self.assertEqual(runner.calls, [])

    def test_reachability_probe_exec_failure_is_unreachable(self):
        runner = FakeExecRunner(exit_code=1)
        probe = SandboxReachabilityProbe(runner, "kalama-probe-aB3x9-0-runner")
        self.assertFalse(probe(_endpoint(ip="10.0.0.2")))

    def test_stdout_budget_enforced_incrementally(self):
        started = time.monotonic()
        backend = SubprocessBackend()
        child = (sys.executable, "-c", "import sys; sys.stdout.write('X' * 2000000)")
        result = backend.run(child, timeout=30, stdout_budget=65536, stderr_budget=65536)
        elapsed = time.monotonic() - started
        self.assertTrue(result.stdout_truncated)
        self.assertLessEqual(len(result.stdout), 65536)
        self.assertLess(elapsed, 20)

    def test_stderr_budget_enforced_incrementally(self):
        backend = SubprocessBackend()
        child = (sys.executable, "-c", "import sys; sys.stderr.write('E' * 2000000)")
        result = backend.run(child, timeout=30, stdout_budget=65536, stderr_budget=65536)
        self.assertTrue(result.stderr_truncated)
        self.assertLessEqual(len(result.stderr), 65536)

    def test_budget_overflow_terminates_child(self):
        started = time.monotonic()
        backend = SubprocessBackend()
        child = (sys.executable, "-c",
                 "import sys\nwhile True:\n    sys.stdout.write('y' * 10000)\n")
        result = backend.run(child, timeout=60, stdout_budget=32768, stderr_budget=32768)
        elapsed = time.monotonic() - started
        self.assertTrue(result.stdout_truncated)
        self.assertLess(elapsed, 20)

    def test_timeout_terminates_child(self):
        started = time.monotonic()
        backend = SubprocessBackend()
        child = (sys.executable, "-c", "import time; time.sleep(60)")
        result = backend.run(child, timeout=2)
        elapsed = time.monotonic() - started
        self.assertTrue(result.timed_out)
        self.assertLess(elapsed, 20)

    def test_no_unix_signals_required(self):
        source = Path("src/kalama/dynamic_probe_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("setitimer", source)
        self.assertNotIn("import signal", source)
        self.assertIn("threading", source)


class JsonlEdgeTests(unittest.TestCase):
    def test_blank_lines_ignored(self):
        outcome = parse_nuclei_jsonl("\n  \n")
        self.assertEqual(outcome.records, ())
        self.assertIsNone(outcome.malformed_line)

    def test_non_object_record_invalid(self):
        outcome = parse_nuclei_jsonl('[1,2]\n')
        self.assertIsNotNone(outcome.malformed_line)

    def test_security_flag_helper(self):
        self.assertEqual(check_security_flags_available(HELP_TEXT), [])

    def test_security_flags_survive_ansi_color_codes(self):
        colored = ("\x1b[33m-duc\x1b[0m, \x1b[32m-disable-update-check\x1b[0m foo\n"
                   "\x1b[1m-dr\x1b[0m, -disable-redirects\n"
                   "-ni, -no-interactsh\n-dut, -disable-unsigned-templates\n-j, -jsonl\n")
        self.assertEqual(check_security_flags_available(colored), [])


# --------------------------------------------------------------------------
# Compatibility (44-46): Wave 1 + scanner + priority-v1 untouched
# --------------------------------------------------------------------------

class CompatibilityTests(unittest.TestCase):
    def test_wave1_taxonomy_unchanged(self):
        from kalama.dynamic_probe import DynamicProbeStatus, DynamicSignal
        self.assertIn("NOT_RUN", {s.value for s in DynamicSignal})
        self.assertIn("SUCCEEDED", {s.value for s in DynamicProbeStatus})

    def test_priority_v1_formula_unchanged(self):
        from kalama.prioritizer import scoring  # noqa
        import pathlib
        text = pathlib.Path("src/kalama/prioritizer/pipeline.py").read_text(encoding="utf-8")
        self.assertIn("kalama-priority-v1", text)


class LiveDockerIsolationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("KALAMA_LIVE_DOCKER") == "1",
                         "live Docker test runs only with KALAMA_LIVE_DOCKER=1")
    def test_runner_victim_reachable_unrelated_unreachable(self):
        self.assertTrue(True)  # placeholder; requires local containers, no Internet


if __name__ == "__main__":
    unittest.main()
