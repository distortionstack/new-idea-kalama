"""Live-Docker validation of ProbeSandbox (Wave 2 integration check).

Opt-in only: KALAMA_LIVE_DOCKER=1. Skips cleanly otherwise (missing env,
unreachable daemon, or absent fixture image).

Harmless local fixtures only: small already-present image, single-shot
busybox ``nc`` listeners, literal-IP TCP connects. No pulls, no prunes,
no scans, no exploitation, no Nuclei. Every fixture carries
``kalama.test.dynamic_probe=true`` and cleanup removes ONLY exact tracked
names after verifying that ownership label.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest

from kalama.dynamic_probe_runtime import (
    DYNAMIC_TARGET_IDENTITY_DRIFT,
    ProbeSandbox,
    SandboxConfig,
    SandboxError,
    SandboxReachabilityProbe,
    SubprocessBackend,
    sandbox_session,
)
from kalama.target.victim_manager import SubprocessCommandRunner


FIXTURE_IMAGE = "docker:27-cli"
LABEL_TEST = "kalama.test.dynamic_probe"
LISTEN_PORT = 8080
EXTERNAL_PROBE_IP = "8.8.8.8"
EXTERNAL_PROBE_PORT = 53


def _live_reason() -> str | None:
    if os.environ.get("KALAMA_LIVE_DOCKER") != "1":
        return "live Docker validation requires KALAMA_LIVE_DOCKER=1"
    return None


class LiveSandboxTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        reason = _live_reason()
        if reason is not None:
            self.skipTest(reason)
        self.pid = os.getpid()
        self.seq = 0
        self.run_id = f"v{self.pid % 10000:04d}"
        self._containers: list[str] = []
        self._networks: list[str] = []
        info = self._docker("info", "--format", "{{.ServerVersion}}", timeout=30)
        if info.returncode != 0:
            self.skipTest(f"docker daemon unreachable: {info.stderr.strip()[:200]}")
        image = self._docker("image", "inspect", FIXTURE_IMAGE, timeout=30)
        if image.returncode != 0:
            self.skipTest(f"fixture image {FIXTURE_IMAGE} absent locally; pulls forbidden")

    def tearDown(self):
        # Remove ONLY exact tracked names, and only with our ownership label.
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
        try:
            data = self._inspect_container(name)
        except AssertionError:
            return
        labels = ((data.get("Config") or {}).get("Labels") or {})
        if labels.get(LABEL_TEST) != "true":
            return
        try:
            self._docker("rm", "-f", name, timeout=60)
        except subprocess.TimeoutExpired:
            pass

    def _inspect_container(self, name: str) -> dict:
        result = self._docker("container", "inspect", name)
        self.assertEqual(result.returncode, 0, f"{name}: {result.stderr.strip()[:200]}")
        return json.loads(result.stdout)[0]

    def _container_exists(self, name: str) -> bool:
        return self._docker("container", "inspect", name).returncode == 0

    def _network_exists(self, name: str) -> bool:
        return self._docker("network", "inspect", name).returncode == 0

    def _container_networks(self, name: str) -> set[str]:
        return set(self._inspect_container(name)["NetworkSettings"]["Networks"].keys())

    def _container_id(self, name: str) -> str:
        return str(self._inspect_container(name)["Id"])

    def _network_ip(self, container: str, network: str) -> str:
        return str(self._inspect_container(container)["NetworkSettings"]
                   ["Networks"][network]["IPAddress"])

    def _build_topology(self):
        """Disposable victim + lab net and unrelated fixture + separate net."""
        lab_net = self._make_network(self._unique("labnet"))
        victim = self._make_container(self._unique("victim"), lab_net)
        self._start(victim)
        unrelated_net = self._make_network(self._unique("unrelated"))
        unrelated = self._make_container(self._unique("unrelated"), unrelated_net)
        self._start(unrelated)
        return lab_net, victim, unrelated_net, unrelated

    def _sandbox(self, victim: str, victim_id: str) -> ProbeSandbox:
        config = SandboxConfig(
            run_id=self.run_id, attempt=f"live{self.pid}-{self.seq}",
            victim_container_name=victim, expected_container_id=victim_id,
            port=LISTEN_PORT, scheme="http", runner_image=FIXTURE_IMAGE)
        box = ProbeSandbox(config, SubprocessCommandRunner())
        # Safety net only; normal cleanup is owned by the sandbox itself.
        self._containers.append(config.effective_runner_name())
        self._networks.append(config.network_name())
        return box

    def _start_listener(self, container: str, port: int = LISTEN_PORT) -> None:
        result = self._docker("exec", "-d", container, "nc", "-l", "-p", str(port))
        self.assertEqual(result.returncode, 0, result.stderr)

    def _tcp_connect(self, container: str, ip: str, port: int, wait: int) -> int:
        try:
            result = self._docker("exec", container, "nc", "-w", str(wait),
                                  ip, str(port), timeout=wait + 60)
        except subprocess.TimeoutExpired:
            return 124
        return result.returncode

    def _tcp_connect_until_ok(self, container: str, ip: str, port: int,
                              tries: int = 8) -> bool:
        for _ in range(tries):
            if self._tcp_connect(container, ip, port, wait=2) == 0:
                return True
            time.sleep(1)
        return False

    # -- assertions ------------------------------------------------------
    def test_internal_network_is_proven(self):
        _, victim, _, _ = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        try:
            box.setup()
            result = self._docker("network", "inspect", box.network_name)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)[0]["Internal"])
        finally:
            box.cleanup()

    def test_runner_has_sandbox_only_membership(self):
        _, victim, _, _ = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        try:
            box.setup()
            # The runner must be started before it can be inspected for exec,
            # but membership is fixed at creation time.
            networks = self._container_networks(box.runner_name)
            self.assertEqual(networks, {box.network_name})
            for forbidden in ("bridge", "kalama-net", "host", "none"):
                self.assertNotIn(forbidden, networks)
        finally:
            box.cleanup()

    def test_victim_networks_preserved_during_and_after(self):
        lab_net, victim, _, _ = self._build_topology()
        original = self._container_networks(victim)
        self.assertIn(lab_net, original)
        box = self._sandbox(victim, self._container_id(victim))
        endpoint = box.setup()
        try:
            during = self._container_networks(victim)
            self.assertTrue(original.issubset(during))
            self.assertIn(endpoint.network, during)
        finally:
            box.cleanup()
        self.assertEqual(self._container_networks(victim), original)

    def test_runner_to_victim_tcp_connectivity(self):
        _, victim, _, _ = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        endpoint = box.setup()
        try:
            self.assertTrue(self._container_exists(box.runner_name))
            self._docker("start", box.runner_name)
            self._start_listener(victim)
            # Same-namespace assumption behind SandboxReachabilityProbe,
            # exercised here with the fixture image's available tooling.
            reachable = self._tcp_connect_until_ok(
                box.runner_name, endpoint.ip_address, endpoint.port)
            self.assertTrue(reachable, "runner could not reach victim on sandbox net")
            # The python3-based probe fail-closes on this fixture image,
            # which ships no interpreter; it must report False, not raise.
            probe = SandboxReachabilityProbe(SubprocessCommandRunner(), box.runner_name)
            self.assertFalse(probe(endpoint))
        finally:
            box.cleanup()

    def test_runner_to_unrelated_container_isolated(self):
        _, victim, _, unrelated = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        box.setup()
        try:
            self._docker("start", box.runner_name)
            self._start_listener(unrelated)
            unrelated_networks = self._container_networks(unrelated)
            self.assertEqual(len(unrelated_networks), 1)
            unrelated_ip = self._network_ip(unrelated, next(iter(unrelated_networks)))
            self.assertNotEqual(unrelated_ip, "")
            exit_code = self._tcp_connect(box.runner_name, unrelated_ip,
                                          LISTEN_PORT, wait=5)
            self.assertNotEqual(exit_code, 0,
                                "runner reached the unrelated container by literal IP")
        finally:
            box.cleanup()

    def test_no_internet_egress_from_sandbox(self):
        _, victim, _, _ = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        box.setup()
        try:
            self._docker("start", box.runner_name)
            exit_code = self._tcp_connect(box.runner_name, EXTERNAL_PROBE_IP,
                                          EXTERNAL_PROBE_PORT, wait=5)
            self.assertNotEqual(
                exit_code, 0,
                "INTERNET EGRESS OBSERVED from the internal sandbox network; "
                "do not weaken the sandbox, investigate Docker behavior")
        finally:
            box.cleanup()

    def test_no_docker_control_inside_runner(self):
        _, victim, _, _ = self._build_topology()
        box = self._sandbox(victim, self._container_id(victim))
        box.setup()
        try:
            self._docker("start", box.runner_name)
            for path in ("/var/run/docker.sock", "/run/docker.sock"):
                result = self._docker("exec", box.runner_name, "ls", path)
                self.assertNotEqual(result.returncode, 0, f"Docker socket present: {path}")
        finally:
            box.cleanup()

    def test_cleanup_on_success(self):
        lab_net, victim, unrelated_net, unrelated = self._build_topology()
        original_victim = self._container_networks(victim)
        original_unrelated = self._container_networks(unrelated)
        box = self._sandbox(victim, self._container_id(victim))
        with box:
            pass
        self.assertFalse(self._container_exists(box.runner_name))
        self.assertFalse(self._network_exists(box.network_name))
        self.assertTrue(self._container_exists(victim))
        self.assertEqual(self._container_networks(victim), original_victim)
        self.assertIn(lab_net, original_victim)
        self.assertTrue(self._container_exists(unrelated))
        self.assertEqual(self._container_networks(unrelated), original_unrelated)

    def test_cleanup_on_exception(self):
        lab_net, victim, _, _ = self._build_topology()
        original_victim = self._container_networks(victim)
        box = self._sandbox(victim, self._container_id(victim))
        with self.assertRaises(RuntimeError):
            with box:
                raise RuntimeError("simulated probe failure")
        self.assertFalse(self._container_exists(box.runner_name))
        self.assertFalse(self._network_exists(box.network_name))
        self.assertTrue(self._container_exists(victim))
        self.assertEqual(self._container_networks(victim), original_victim)

    def test_cleanup_on_timeout_path(self):
        _, victim, _, _ = self._build_topology()
        original_victim = self._container_networks(victim)
        box = self._sandbox(victim, self._container_id(victim))
        try:
            box.setup()
            # Harmless sleep through the real backend timeout path.
            backend = SubprocessBackend()
            child = (sys.executable, "-c", "import time; time.sleep(30)")
            result = backend.run(child, timeout=2,
                                 stdout_budget=65536, stderr_budget=65536)
            self.assertTrue(result.timed_out)
        finally:
            box.cleanup()
        self.assertFalse(self._container_exists(box.runner_name))
        self.assertFalse(self._network_exists(box.network_name))
        self.assertTrue(self._container_exists(victim))
        self.assertEqual(self._container_networks(victim), original_victim)

    def test_identity_before_equals_after(self):
        _, victim, _, _ = self._build_topology()
        victim_id = self._container_id(victim)
        box = self._sandbox(victim, victim_id)
        endpoint = box.setup()
        try:
            self.assertEqual(box.identity_before.container_id, victim_id)
            self.assertEqual(endpoint.container_id, victim_id)
            after = box.verify_after()
            self.assertEqual(after.container_id, victim_id)
            self.assertEqual(after.ip_address, box.identity_before.ip_address)
        finally:
            box.cleanup()

    def test_container_replacement_detected_as_drift(self):
        lab_net, victim, _, _ = self._build_topology()
        victim_id = self._container_id(victim)
        box = self._sandbox(victim, victim_id)
        box.setup()
        try:
            # Disposable-fixture replacement: same name, new container ID.
            self.assertEqual(self._docker("rm", "-f", victim).returncode, 0)
            self._make_container(victim, lab_net)
            with self.assertRaises(SandboxError) as caught:
                box.verify_after()
            self.assertEqual(caught.exception.code, DYNAMIC_TARGET_IDENTITY_DRIFT)
        finally:
            box.cleanup()

    def test_sandbox_session_context_releases_everything(self):
        lab_net, victim, _, _ = self._build_topology()
        original_victim = self._container_networks(victim)
        config = SandboxConfig(
            run_id=self.run_id, attempt=f"sess{self.pid}-{self.seq}",
            victim_container_name=victim,
            expected_container_id=self._container_id(victim),
            port=LISTEN_PORT, scheme="http", runner_image=FIXTURE_IMAGE)
        self._containers.append(config.effective_runner_name())
        self._networks.append(config.network_name())
        with sandbox_session(config, SubprocessCommandRunner()):
            pass
        self.assertFalse(self._container_exists(config.effective_runner_name()))
        self.assertFalse(self._network_exists(config.network_name()))
        self.assertEqual(self._container_networks(victim), original_victim)


if __name__ == "__main__":
    unittest.main()
