import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kalama.target.models import (
    CommandResult, ImageIdentity, ImageSourceKind, ObservationStatus,
    Step2FailureCode, Step2Request,
)
from kalama.target.trivy_scanner import scan_image, validate_trivy_json
from kalama.target.victim_manager import (
    Step2OperationError, collect_target_facts, ensure_network, observe_listening_ports,
    parse_exposed_ports, parse_proc_net, parse_published_ports, prepare_container,
    resolve_image, validate_run_id, wait_until_ready,
)


def image_data(digests=None):
    return {"Id": "sha256:image1", "RepoDigests": digests if digests is not None else ["z/repo@sha256:b", "a/repo@sha256:a"],
            "RepoTags": ["repo:test"], "Os": "linux", "Architecture": "amd64"}


def container_data(*, run_id="aB3x9", managed="true", image="sha256:image1",
                   running=True, status="running", restarting=False, health=None,
                   networks=None):
    state = {"Running": running, "Status": status, "Restarting": restarting}
    if health is not None:
        state["Health"] = {"Status": health}
    return {
        "Id": "container-id", "Image": image,
        "Config": {"Labels": {"kalama.managed": managed, "kalama.run_id": run_id,
                                "kalama.phase": "before"},
                   "Env": ["B=2", "A=1"], "Cmd": ["serve"], "Entrypoint": ["/bin/app"],
                   "ExposedPorts": {"80/tcp": {}, "53/udp": {}}},
        "State": state,
        "NetworkSettings": {"Networks": networks if networks is not None else {
            "kalama-net": {"IPAddress": "172.18.0.3"}},
            "Ports": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"},
                                   {"HostIp": "0.0.0.0", "HostPort": "28080"}],
                      "53/udp": None}},
    }


class FakeRunner:
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def run(self, argv, *, timeout=None):
        args = tuple(argv)
        self.calls.append((args, timeout))
        result = self.handler(args, timeout)
        return result if isinstance(result, CommandResult) else CommandResult(args, *result)


def success_json(args, value):
    return CommandResult(tuple(args), 0, json.dumps([value]), "")


class ImageTests(unittest.TestCase):
    def request(self, **kwargs):
        values = {"run_id": "aB3x9", "image_reference": "repo:test", "output_path": "out.json"}
        values.update(kwargs)
        return Step2Request(**values)

    def test_run_id_is_strict(self):
        validate_run_id("aB3x9")
        for value in ("shrt", "abcdef", "a-b_1", "åB3x9"):
            with self.assertRaises(Step2OperationError):
                validate_run_id(value)

    def test_local_image_uses_deterministic_digest_without_pull(self):
        runner = FakeRunner(lambda args, _: success_json(args, image_data()))
        identity = resolve_image(self.request(), runner)
        self.assertEqual(identity.source_kind, ImageSourceKind.LOCAL_EXISTING)
        self.assertEqual(identity.selected_digest, "a/repo@sha256:a")
        self.assertEqual(identity.requested_reference, "repo:test")
        self.assertFalse(any(call[0][0:2] == ("docker", "pull") for call in runner.calls))

    def test_missing_image_pulls_then_inspects(self):
        count = {"inspect": 0}
        def handler(args, _):
            if args[1:3] == ("image", "inspect"):
                count["inspect"] += 1
                return (1, "", "No such image") if count["inspect"] == 1 else success_json(args, image_data())
            if args[1] == "pull":
                return (0, "pulled", "")
            raise AssertionError(args)
        identity = resolve_image(self.request(), FakeRunner(handler))
        self.assertEqual(identity.source_kind, ImageSourceKind.PULLED)
        self.assertEqual(count["inspect"], 2)

    def test_pull_failure_is_structured(self):
        def handler(args, _):
            return (1, "", "No such image") if args[1:3] == ("image", "inspect") else (1, "", "registry down")
        with self.assertRaises(Step2OperationError) as caught:
            resolve_image(self.request(), FakeRunner(handler))
        self.assertEqual(caught.exception.issue.code, Step2FailureCode.IMAGE_PULL_FAILED)

    def test_image_inspect_environment_failure_does_not_pull(self):
        runner = FakeRunner(lambda args, _: (1, "", "permission denied"))
        with self.assertRaises(Step2OperationError) as caught:
            resolve_image(self.request(), runner)
        self.assertEqual(caught.exception.issue.code, Step2FailureCode.IMAGE_INSPECT_FAILED)
        self.assertEqual(len(runner.calls), 1)

    def test_local_image_without_digest_falls_back_to_image_id(self):
        runner = FakeRunner(lambda args, _: success_json(args, image_data([])))
        identity = resolve_image(self.request(), runner)
        self.assertIsNone(identity.selected_digest)
        self.assertEqual(identity.canonical_identity, "sha256:image1")
        self.assertEqual(identity.source_kind, ImageSourceKind.LOCAL_BUILT)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.request = Step2Request("aB3x9", "repo:test", "out.json")
        self.image = ImageIdentity("repo:test", "sha256:image1", (), None, (), "linux/amd64",
                                   ImageSourceKind.LOCAL_BUILT)

    def runner_for_existing(self, container, extras=None):
        extras = extras or {}
        def handler(args, _):
            if args[1:3] == ("network", "inspect"):
                return (0, "[]", "")
            if args[1:3] == ("container", "inspect"):
                return success_json(args, container)
            return extras.get(args, (0, "", ""))
        return FakeRunner(handler)

    def test_same_run_valid_container_reused(self):
        runner = self.runner_for_existing(container_data())
        prepare_container(self.request, self.image, runner)
        self.assertFalse(any(call[0][0:2] == ("docker", "create") for call in runner.calls))

    def test_wrong_run_unmanaged_and_wrong_image_rejected(self):
        scenarios = [
            (container_data(run_id="other"), Step2FailureCode.CONTAINER_CONFLICT),
            (container_data(managed="false"), Step2FailureCode.CONTAINER_CONFLICT),
            (container_data(image="sha256:other"), Step2FailureCode.IMAGE_IDENTITY_MISMATCH),
        ]
        for container, expected in scenarios:
            with self.subTest(expected=expected):
                with self.assertRaises(Step2OperationError) as caught:
                    prepare_container(self.request, self.image, self.runner_for_existing(container))
                self.assertEqual(caught.exception.issue.code, expected)

    def test_missing_container_created_with_labels_and_network(self):
        inspections = 0
        def handler(args, _):
            nonlocal inspections
            if args[1:3] == ("network", "inspect"):
                return (0, "[]", "")
            if args[1:3] == ("container", "inspect"):
                inspections += 1
                return (1, "", "No such container") if inspections == 1 else success_json(args, container_data())
            if args[1] == "create":
                return (0, "container-id", "")
            raise AssertionError(args)
        runner = FakeRunner(handler)
        prepare_container(self.request, self.image, runner)
        create = next(call[0] for call in runner.calls if call[0][1] == "create")
        self.assertIn("victim-aB3x9", create)
        self.assertIn("kalama.run_id=aB3x9", create)
        self.assertIn("kalama.managed=true", create)
        self.assertIn("kalama-net", create)

    def test_stopped_same_run_container_is_started(self):
        runner = self.runner_for_existing(container_data(running=False, status="exited"))
        prepare_container(self.request, self.image, runner)
        self.assertIn((("docker", "start", "victim-aB3x9"), None), runner.calls)

    def test_network_missing_attach_and_failure(self):
        missing = FakeRunner(lambda args, _: (1, "", "not found"))
        with self.assertRaises(Step2OperationError) as caught:
            ensure_network("kalama-net", missing)
        self.assertEqual(caught.exception.issue.code, Step2FailureCode.NETWORK_NOT_FOUND)

        container = container_data(networks={"bridge": {"IPAddress": "172.17.0.2"}})
        calls = 0
        def handler(args, _):
            nonlocal calls
            if args[1:3] == ("network", "inspect"): return (0, "[]", "")
            if args[1:3] == ("container", "inspect"):
                calls += 1
                value = container if calls == 1 else container_data(networks={
                    "bridge": {"IPAddress": "172.17.0.2"}, "kalama-net": {"IPAddress": "172.18.0.8"}})
                return success_json(args, value)
            if args[1:3] == ("network", "connect"): return (0, "", "")
            raise AssertionError(args)
        runner = FakeRunner(handler)
        prepare_container(self.request, self.image, runner)
        self.assertTrue(any(call[0][1:3] == ("network", "connect") for call in runner.calls))

        def failed_attach(args, _):
            if args[1:3] == ("network", "inspect"): return (0, "[]", "")
            if args[1:3] == ("container", "inspect"): return success_json(args, container)
            if args[1:3] == ("network", "connect"): return (1, "", "denied")
            raise AssertionError(args)
        with self.assertRaises(Step2OperationError) as caught:
            prepare_container(self.request, self.image, FakeRunner(failed_attach))
        self.assertEqual(caught.exception.issue.code, Step2FailureCode.NETWORK_ATTACH_FAILED)


class RuntimeFactsTests(unittest.TestCase):
    TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1
   1: 0100007F:1234 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 2
"""
    TCP6 = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3
"""

    def test_exposed_and_published_ports_are_distinct(self):
        data = container_data()
        exposed, published = parse_exposed_ports(data), parse_published_ports(data)
        self.assertEqual([(x.container_port, x.protocol) for x in exposed], [(53, "udp"), (80, "tcp")])
        self.assertEqual([x.host_port for x in published], [28080, 18080])
        self.assertTrue(all(x.source == "docker_port_binding" for x in published))

    def test_proc_tcp_tcp6_and_invalid_data(self):
        self.assertEqual(parse_proc_net(self.TCP, "tcp")[0].container_port, 8080)
        self.assertEqual(parse_proc_net(self.TCP6, "tcp6")[0].container_port, 443)
        with self.assertRaises(ValueError):
            parse_proc_net("not proc", "tcp")

    def test_unreadable_or_invalid_proc_is_unknown(self):
        failed = FakeRunner(lambda args, _: (1, "", "unreadable"))
        self.assertEqual(observe_listening_ports("victim", failed), (ObservationStatus.UNKNOWN, ()))
        invalid = FakeRunner(lambda args, _: (0, "bad", ""))
        self.assertEqual(observe_listening_ports("victim", invalid)[0], ObservationStatus.UNKNOWN)

    def test_target_facts_select_kalama_network_not_first(self):
        data = container_data(networks={"bridge": {"IPAddress": "172.17.0.2"},
                                        "kalama-net": {"IPAddress": "172.18.0.9"}})
        def handler(args, _):
            if args[1:3] == ("container", "inspect"): return success_json(args, data)
            if args[1:3] == ("exec", "victim-aB3x9"):
                return (0, self.TCP if args[-1].endswith("tcp") else self.TCP6, "")
            raise AssertionError(args)
        request = Step2Request("aB3x9", "repo:test", "out")
        image = ImageIdentity("repo:test", "sha256:image1", (), None, (), None, ImageSourceKind.LOCAL_BUILT)
        facts = collect_target_facts(request, image, data, FakeRunner(handler))
        self.assertEqual(facts.ip_address, "172.18.0.9")
        self.assertEqual(facts.listening_ports_status, ObservationStatus.AVAILABLE)
        self.assertEqual({x.container_port for x in facts.listening_ports}, {443, 8080})
        self.assertEqual(facts.reachable_ports_status, ObservationStatus.UNKNOWN)

    def test_target_facts_can_inspect_an_explicit_after_container(self):
        data = container_data(networks={"kalama-net": {"IPAddress": "172.18.0.10"}})
        seen = []
        def handler(args, _):
            seen.append(args)
            if args[1:3] == ("container", "inspect"): return success_json(args, data)
            if args[1:3] == ("exec", "victim-after-aB3x9"):
                return (0, self.TCP if args[-1].endswith("tcp") else self.TCP6, "")
            raise AssertionError(args)
        request = Step2Request("aB3x9", "repo:patched", "out", phase="after")
        image = ImageIdentity("repo:patched", "sha256:patched", (), None, (), None,
                              ImageSourceKind.LOCAL_BUILT)
        facts = collect_target_facts(
            request, image, data, FakeRunner(handler),
            container_name="victim-after-aB3x9")
        self.assertEqual(facts.container_name, "victim-after-aB3x9")
        self.assertTrue(any(x[1:3] == ("container", "inspect")
                            and x[3] == "victim-after-aB3x9" for x in seen))

    def test_readiness_health_running_restart_and_timeout(self):
        for health in ("healthy", None):
            runner = FakeRunner(lambda args, _, h=health: success_json(args, container_data(health=h)))
            self.assertTrue(wait_until_ready("victim", runner, 1, sleeper=lambda _: None))
        for value in (container_data(health="unhealthy"),
                      container_data(running=False, status="exited"),
                      container_data(restarting=True)):
            runner = FakeRunner(lambda args, _, v=value: success_json(args, v))
            with self.assertRaises(Step2OperationError) as caught:
                wait_until_ready("victim", runner, 0, sleeper=lambda _: None)
            self.assertEqual(caught.exception.issue.code, Step2FailureCode.RUNTIME_NOT_READY)
        starting = FakeRunner(lambda args, _: success_json(args, container_data(health="starting")))
        ticks = iter([0, 0, 2, 2])
        with self.assertRaises(Step2OperationError):
            wait_until_ready("victim", starting, 1, clock=lambda: next(ticks), sleeper=lambda _: None)


class TrivyTests(unittest.TestCase):
    def setUp(self):
        self.image = ImageIdentity("repo:test", "sha256:image1", ("repo@sha256:a",),
                                   "repo@sha256:a", (), None, ImageSourceKind.LOCAL_EXISTING)

    def payload(self, results=None):
        return {"SchemaVersion": 2, "Trivy": {"Version": "0.72.0"},
                "CreatedAt": "2026-08-31T00:00:00Z", "ArtifactName": "repo:test",
                "ArtifactType": "container_image", "Metadata": {},
                "Results": [] if results is None else results}

    def scanner(self, payload=None, exit_code=0):
        payload = self.payload() if payload is None else payload
        def handler(args, _):
            if args[0] == "trivy" and exit_code == 0:
                output = args[args.index("--output") + 1]
                Path(output).write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
            return (exit_code, "", "failure" if exit_code else "")
        return FakeRunner(handler)

    def test_validation_allows_findings_nested_results_and_empty(self):
        validate_trivy_json(self.payload())
        validate_trivy_json(self.payload([{"Target": "T", "Vulnerabilities": []}]))
        validate_trivy_json(self.payload([{"Target": "T", "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}]))

    def test_validation_rejects_missing_results_and_schema(self):
        for payload, code in (({"SchemaVersion": 2}, Step2FailureCode.ARTIFACT_VALIDATION_FAILED),
                              ({"SchemaVersion": 99, "Results": []}, Step2FailureCode.TRIVY_SCHEMA_UNSUPPORTED)):
            with self.assertRaises(Step2OperationError) as caught:
                validate_trivy_json(payload)
            self.assertEqual(caught.exception.issue.code, code)

    def test_scan_command_publish_and_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.json"
            runner = self.scanner()
            artifact = scan_image(self.image, path, runner, timeout=60)
            command = runner.calls[0]
            self.assertEqual(command[1], 60)
            self.assertEqual(command[0][0:3], ("trivy", "image", "--scanners"))
            self.assertIn("--list-all-pkgs", command[0])
            self.assertNotIn("--ignore-unfixed", command[0])
            self.assertEqual(command[0][-1], "repo@sha256:a")
            self.assertEqual(artifact.artifact_sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_invalid_json_command_failure_and_replace_failure_do_not_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            for runner, expected in ((self.scanner("{"), Step2FailureCode.TRIVY_INVALID_JSON),
                                     (self.scanner(exit_code=2), Step2FailureCode.TRIVY_EXECUTION_FAILED)):
                path = Path(tmp) / f"{expected.value}.json"
                with self.assertRaises(Step2OperationError) as caught:
                    scan_image(self.image, path, runner)
                self.assertEqual(caught.exception.issue.code, expected)
                self.assertFalse(path.exists())
            path = Path(tmp) / "replace.json"
            path.write_text("old")
            with patch("kalama.target.trivy_scanner.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(Step2OperationError) as caught:
                    scan_image(self.image, path, self.scanner())
            self.assertEqual(caught.exception.issue.code, Step2FailureCode.ARTIFACT_WRITE_FAILED)
            self.assertEqual(path.read_text(), "old")

    def test_input_request_and_inspect_fixture_not_mutated(self):
        request = Step2Request("aB3x9", "repo:test", "out")
        fixture = image_data()
        snapshot = copy.deepcopy(fixture)
        resolve_image(request, FakeRunner(lambda args, _: success_json(args, fixture)))
        self.assertEqual(fixture, snapshot)


if __name__ == "__main__":
    unittest.main()
