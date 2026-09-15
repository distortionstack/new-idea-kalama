"""Real-Nuclei end-to-end validation of the Wave 2/3 execution path.

Opt-in only: KALAMA_REAL_NUCLEI=1 plus explicit pinned paths. Skips
cleanly otherwise (missing env, unreachable daemon, absent runner image,
or missing pinned files). NEVER downloads, updates, or pulls anything:
every image and file must already exist locally.

Coverage with a real pinned Nuclei binary inside the real internal Docker
sandbox against a disposable dummy HTTP responder (static ``hello world``
200, never vulnerable, so zero-match completion is the expected trusted
outcome):

* approved-manifest load + runtime preflight against real template files
* sandbox setup/start/verify/cleanup with the real Nuclei runner image
* real Nuclei identity (version) provenance
* in-namespace reachability to the dummy responder
* one real ``execute_single_template`` run with provenance assertions
* no leaked networks or containers afterwards
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

from kalama.dynamic_probe import load_approved_template_manifest
from kalama.dynamic_probe_runtime import (
    ContainerExecBackend,
    NucleiRunnerConfig,
    ProbeSandbox,
    SandboxConfig,
    SandboxReachabilityProbe,
    execute_single_template,
    runtime_preflight_template,
)
from kalama.target.victim_manager import SubprocessCommandRunner


FIXTURE_IMAGE = "docker:27-cli"
LABEL_TEST = "kalama.test.dynamic_probe"
LISTEN_PORT = 8080
DEFAULT_RUNNER_IMAGE = "kalama/nuclei-probe:3.11.1"
CONTAINER_TEMPLATE_ROOT = "/templates"
# Minimal static HTTP body: deterministic 200, never matches a CVE matcher.
DUMMY_BODY = b"hello world"


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _real_nuclei_reason() -> str | None:
    if os.environ.get("KALAMA_REAL_NUCLEI") != "1":
        return "real Nuclei validation requires KALAMA_REAL_NUCLEI=1"
    if _env("KALAMA_REAL_NUCLEI_MANIFEST") is None:
        return "KALAMA_REAL_NUCLEI_MANIFEST must point at a pinned approved manifest"
    if _env("KALAMA_REAL_NUCLEI_TEMPLATE_ROOT") is None:
        return "KALAMA_REAL_NUCLEI_TEMPLATE_ROOT must point at a pinned template tree"
    return None


class RealNucleiTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        reason = _real_nuclei_reason()
        if reason is not None:
            self.skipTest(reason)
        self.pid = os.getpid()
        self.seq = 0
        self.run_id = f"n{self.pid % 10000:04d}"
        self._containers: list[str] = []
        self._networks: list[str] = []
        info = self._docker("info", "--format", "{{.ServerVersion}}", timeout=30)
        if info.returncode != 0:
            self.skipTest(f"docker daemon unreachable: {info.stderr.strip()[:200]}")
        self.runner_image = (
            _env("KALAMA_REAL_NUCLEI_RUNNER_IMAGE") or DEFAULT_RUNNER_IMAGE)
        if self._docker("image", "inspect", self.runner_image,
                        timeout=30).returncode != 0:
            self.skipTest(f"runner image {self.runner_image} absent locally; pulls forbidden")
        if self._docker("image", "inspect", FIXTURE_IMAGE,
                        timeout=30).returncode != 0:
            self.skipTest(f"fixture image {FIXTURE_IMAGE} absent locally; pulls forbidden")
        self.manifest_path = Path(_env("KALAMA_REAL_NUCLEI_MANIFEST") or "")
        self.template_root = Path(_env("KALAMA_REAL_NUCLEI_TEMPLATE_ROOT") or "")
        if not self.manifest_path.is_file() or not self.template_root.is_dir():
            self.skipTest("pinned manifest/template root absent; downloads forbidden")
        self.manifest = load_approved_template_manifest(
            self.manifest_path, self.template_root)
        if not self.manifest.templates:
            self.skipTest("approved manifest contains no templates")

    def tearDown(self):
        for name in reversed(self._containers):
            self._safe_rm_container(name)
        for name in reversed(self._networks):
            try:
                self._docker("network", "rm", name, timeout=60)
            except subprocess.TimeoutExpired:
                pass

    # -- helpers --------------------------------------------------------
    def _docker(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(("docker",) + tuple(args), capture_output=True,
                              text=True, timeout=timeout, shell=False, check=False)

    def _unique(self, kind: str) -> str:
        self.seq += 1
        return f"kalama-test-{kind}-{self.pid}-{self.seq}"

    def _labels(self) -> list[str]:
        return ["--label", f"{LABEL_TEST}=true",
                "--label", f"kalama.test.pid={self.pid}"]

    def _make_network(self, name: str, *extra: str) -> str:
        result = self._docker("network", "create", *self._labels(), *extra, name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self._networks.append(name)
        return name

    def _make_container(self, name: str, network: str) -> str:
        result = self._docker("create", "--name", name, "--network", network,
                              *self._labels(), FIXTURE_IMAGE, "sleep", "infinity")
        self.assertEqual(result.returncode, 0, result.stderr)
        self._containers.append(name)
        return name

    def _start(self, name: str) -> None:
        result = self._docker("start", name)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _safe_rm_container(self, name: str) -> None:
        result = self._docker("container", "inspect", name)
        if result.returncode != 0:
            return
        try:
            labels = ((json.loads(result.stdout)[0].get("Config") or {}).get("Labels") or {})
        except (ValueError, IndexError, KeyError):
            return
        if labels.get(LABEL_TEST) != "true":
            return
        try:
            self._docker("rm", "-f", name, timeout=60)
        except subprocess.TimeoutExpired:
            pass

    def _container_exists(self, name: str) -> bool:
        return self._docker("container", "inspect", name).returncode == 0

    def _network_exists(self, name: str) -> bool:
        return self._docker("network", "inspect", name).returncode == 0

    def _start_dummy_http(self, container: str, port: int = LISTEN_PORT) -> None:
        body_len = len(DUMMY_BODY)
        # Persistent minimal HTTP responder: each accepted connection gets a
        # static 200 with a body that cannot match any CVE matcher.
        script = (
            "while true; do "
            f"printf 'HTTP/1.0 200 OK\\r\\nContent-Length: {body_len}\\r\\n"
            "Connection: close\\r\\n\\r\\nhello world' | "
            f"nc -l -p {port}; done"
        )
        result = self._docker("exec", "-d", container, "sh", "-c", script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _tcp_connect_until_ok(self, container: str, ip: str, port: int,
                              tries: int = 10) -> bool:
        for _ in range(tries):
            try:
                result = self._docker("exec", container, "nc", "-w", "2",
                                      ip, str(port), timeout=30)
            except subprocess.TimeoutExpired:
                result = None
            if result is not None and result.returncode == 0:
                return True
            time.sleep(1)
        return False

    # -- tests ----------------------------------------------------------
    def test_pinned_manifest_passes_runtime_preflight(self):
        for approved in self.manifest.templates:
            result = runtime_preflight_template(self.template_root, approved)
            self.assertTrue(result.ok)
            self.assertEqual(result.template_id, approved.template_id)
            self.assertEqual(result.sha256, approved.expected_sha256)

    def test_real_nuclei_end_to_end_against_dummy_http(self):
        from kalama.dynamic_shadow import probe_nuclei_identity

        approved = self.manifest.templates[0]
        lab_net = self._make_network(self._unique("labnet"))
        victim = self._make_container(self._unique("victim"), lab_net)
        self._start(victim)
        self._start_dummy_http(victim)
        victim_id = str(json.loads(
            self._docker("container", "inspect", victim).stdout)[0]["Id"])
        victim_ip = str(json.loads(
            self._docker("container", "inspect", victim).stdout
        )[0]["NetworkSettings"]["Networks"][lab_net]["IPAddress"])
        self.assertTrue(
            self._tcp_connect_until_ok(victim, "127.0.0.1", LISTEN_PORT),
            "dummy HTTP responder did not start inside the fixture")

        config = SandboxConfig(
            run_id=self.run_id, attempt=f"realnuclei{self.pid}-{self.seq}",
            victim_container_name=victim, expected_container_id=victim_id,
            port=LISTEN_PORT, scheme="http", runner_image=self.runner_image,
            template_root_host_path=str(self.template_root))
        box = ProbeSandbox(config, SubprocessCommandRunner())
        # Safety net only; normal cleanup is owned by the sandbox itself.
        self._containers.append(config.effective_runner_name())
        self._networks.append(config.network_name())
        try:
            endpoint = box.setup()
            self.assertEqual(endpoint.port, LISTEN_PORT)
            box.start_runner()
            backend = ContainerExecBackend(box.runner_name)
            identity = probe_nuclei_identity(backend, "nuclei")
            self.assertTrue((identity.get("version") or "").strip(),
                            "real Nuclei version provenance must be captured")
            expected_version = _env("KALAMA_REAL_NUCLEI_VERSION")
            if expected_version:
                self.assertIn(expected_version, identity["version"] or "")
            reachability = SandboxReachabilityProbe(
                SubprocessCommandRunner(), box.runner_name)
            nuclei_config = NucleiRunnerConfig(
                binary_path="nuclei", template_root=self.template_root)
            result = execute_single_template(
                nuclei_config, endpoint=endpoint, approved=approved,
                candidate_cve=approved.mapped_cves[0], run_id=self.run_id,
                attempt=config.attempt, backend=backend,
                reachability=reachability,
                template_container_root=CONTAINER_TEMPLATE_ROOT)
            self.assertEqual(result.template_sha256, approved.expected_sha256)
            self.assertEqual(result.template_id, approved.template_id)
            self.assertEqual(
                result.endpoint_identity.get("endpoint_key"), endpoint.endpoint_key)
            self.assertIsInstance(result.raw_stdout, bytes)
            # The dummy responder is never vulnerable: trusted completion
            # with zero matches is the only acceptable success shape.
            self.assertEqual(result.execution_status.value, "SUCCEEDED")
            self.assertTrue(result.reachable)
            self.assertEqual(list(result.records), [])
            box.verify_after()
        finally:
            box.cleanup()
        self.assertFalse(self._network_exists(config.network_name()),
                         "sandbox network must be removed")
        self.assertFalse(self._container_exists(config.effective_runner_name()),
                         "runner container must be removed")


if __name__ == "__main__":
    sys.exit(unittest.main())
