"""Docker-CLI target preparation behind one injectable command runner."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
from typing import Any, Callable, Protocol, Sequence

from .models import (
    CommandResult, ExposedPort, ImageIdentity, ImageSourceKind, ListeningPort,
    ObservationStatus, PublishedPort, Step2FailureCode, Step2Issue, Step2Request,
    TargetFacts,
)


RUN_ID_RE = re.compile(r"^[A-Za-z0-9]{5}$")


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float | None = None) -> CommandResult: ...


class SubprocessCommandRunner:
    def run(self, argv: Sequence[str], *, timeout: float | None = None) -> CommandResult:
        args = tuple(str(x) for x in argv)
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                       shell=False, check=False)
            return CommandResult(args, completed.returncode, completed.stdout, completed.stderr)
        except FileNotFoundError as exc:
            return CommandResult(args, 127, "", str(exc))
        except subprocess.TimeoutExpired as exc:
            return CommandResult(args, 124, exc.stdout or "", exc.stderr or "command timed out")


class Step2OperationError(RuntimeError):
    def __init__(self, issue: Step2Issue):
        super().__init__(issue.message)
        self.issue = issue


def validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.INVALID_RUN_ID, "request", "run_id must contain exactly five ASCII letters or digits"))


def _command_issue(code: Step2FailureCode, stage: str, message: str,
                   result: CommandResult, retryable: bool = False) -> Step2Issue:
    return Step2Issue(code, stage, message, retryable, result.argv,
                      result.exit_code, result.stderr.strip() or None)


def _inspect_object(result: CommandResult, code: Step2FailureCode, stage: str) -> dict[str, Any]:
    if result.exit_code != 0:
        raise Step2OperationError(_command_issue(code, stage, f"{stage} command failed", result))
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, list) or not value or not isinstance(value[0], dict):
            raise ValueError
        return value[0]
    except (json.JSONDecodeError, ValueError):
        raise Step2OperationError(_command_issue(code, stage, f"{stage} returned invalid JSON", result))


def resolve_image(request: Step2Request, runner: CommandRunner) -> ImageIdentity:
    validate_run_id(request.run_id)
    inspect_args = ("docker", "image", "inspect", request.image_reference)
    inspected = runner.run(inspect_args)
    pulled = False
    if inspected.exit_code != 0:
        inspect_text = f"{inspected.stdout}\n{inspected.stderr}".casefold()
        if "no such image" not in inspect_text and "not found" not in inspect_text:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.IMAGE_INSPECT_FAILED, "image_inspect",
                "unable to determine whether the requested image exists locally", inspected))
        pull_args = ("docker", "pull") + (("--platform", request.platform) if request.platform else ()) + (request.image_reference,)
        pull = runner.run(pull_args)
        if pull.exit_code != 0:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.IMAGE_PULL_FAILED, "image_pull", "unable to pull requested image", pull, True))
        pulled = True
        inspected = runner.run(inspect_args)
    data = _inspect_object(inspected, Step2FailureCode.IMAGE_INSPECT_FAILED, "image_inspect")
    image_id = data.get("Id")
    if not isinstance(image_id, str) or not image_id:
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.IMAGE_INSPECT_FAILED, "image_inspect", "image inspect omitted image Id"))
    digests = tuple(sorted(x for x in (data.get("RepoDigests") or []) if isinstance(x, str)))
    tags = tuple(sorted(x for x in (data.get("RepoTags") or []) if isinstance(x, str)))
    os_name, architecture = data.get("Os"), data.get("Architecture")
    platform = f"{os_name}/{architecture}" if os_name and architecture else request.platform
    source = ImageSourceKind.PULLED if pulled else (
        ImageSourceKind.LOCAL_BUILT if not digests else ImageSourceKind.LOCAL_EXISTING)
    return ImageIdentity(request.image_reference, image_id, digests,
                         digests[0] if digests else None, tags, platform, source)


def ensure_network(network: str, runner: CommandRunner) -> None:
    result = runner.run(("docker", "network", "inspect", network))
    if result.exit_code != 0:
        raise Step2OperationError(_command_issue(
            Step2FailureCode.NETWORK_NOT_FOUND, "network", f"required network {network!r} was not found", result))


def _container_missing(result: CommandResult) -> bool:
    text = f"{result.stdout}\n{result.stderr}".casefold()
    return result.exit_code != 0 and ("no such" in text or "not found" in text)


def _container_create_args(request: Step2Request, image: ImageIdentity) -> tuple[str, ...]:
    args = ["docker", "create", "--name", f"victim-{request.run_id}",
            "--label", "kalama.managed=true", "--label", f"kalama.run_id={request.run_id}",
            "--label", f"kalama.phase={request.phase}", "--label", f"kalama.image_id={image.image_id}",
            "--network", request.network]
    if request.platform:
        args += ["--platform", request.platform]
    for key, value in sorted(request.environment):
        args += ["--env", f"{key}={value}"]
    for port in request.ports:
        args += ["--publish", port]
    for volume in request.volumes:
        args += ["--volume", volume]
    if request.entrypoint:
        args += ["--entrypoint", request.entrypoint[0]]
    args.append(image.canonical_identity)
    if len(request.entrypoint) > 1:
        args.extend(request.entrypoint[1:])
    args.extend(request.command)
    return tuple(args)


def _validate_owned_container(data: dict[str, Any], request: Step2Request,
                              image: ImageIdentity) -> None:
    labels = ((data.get("Config") or {}).get("Labels") or {})
    if (labels.get("kalama.managed") != "true"
            or labels.get("kalama.run_id") != request.run_id
            or labels.get("kalama.phase") != request.phase):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.CONTAINER_CONFLICT, "container_prepare",
            f"victim-{request.run_id} exists but is not owned by this run"))
    if data.get("Image") != image.image_id:
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.IMAGE_IDENTITY_MISMATCH, "container_prepare",
            "same-run victim uses a different immutable image ID"))


def prepare_container(request: Step2Request, image: ImageIdentity,
                      runner: CommandRunner) -> dict[str, Any]:
    ensure_network(request.network, runner)
    name = f"victim-{request.run_id}"
    inspected = runner.run(("docker", "container", "inspect", name))
    if inspected.exit_code == 0:
        data = _inspect_object(inspected, Step2FailureCode.CONTAINER_INSPECT_FAILED, "container_inspect")
        _validate_owned_container(data, request, image)
    elif _container_missing(inspected):
        created = runner.run(_container_create_args(request, image))
        if created.exit_code != 0:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.CONTAINER_CREATE_FAILED, "container_create", "unable to create victim", created))
        inspected = runner.run(("docker", "container", "inspect", name))
        data = _inspect_object(inspected, Step2FailureCode.CONTAINER_INSPECT_FAILED, "container_inspect")
        _validate_owned_container(data, request, image)
    else:
        raise Step2OperationError(_command_issue(
            Step2FailureCode.CONTAINER_INSPECT_FAILED, "container_inspect", "unable to inspect victim name", inspected))

    networks = ((data.get("NetworkSettings") or {}).get("Networks") or {})
    if request.network not in networks:
        connected = runner.run(("docker", "network", "connect", request.network, name))
        if connected.exit_code != 0:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.NETWORK_ATTACH_FAILED, "network_attach", "unable to attach victim network", connected))
        data = _inspect_object(runner.run(("docker", "container", "inspect", name)),
                               Step2FailureCode.CONTAINER_INSPECT_FAILED, "container_inspect")
    state = data.get("State") or {}
    if not state.get("Running"):
        started = runner.run(("docker", "start", name))
        if started.exit_code != 0:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.CONTAINER_START_FAILED, "container_start", "unable to start victim", started))
    return data


def wait_until_ready(name: str, runner: CommandRunner, timeout: float,
                     grace_period: float = 0, *, clock: Callable[[], float] = time.monotonic,
                     sleeper: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    started_at = clock()
    stable_since: float | None = None
    last: dict[str, Any] | None = None
    while clock() - started_at <= timeout:
        result = runner.run(("docker", "container", "inspect", name))
        last = _inspect_object(result, Step2FailureCode.CONTAINER_INSPECT_FAILED, "container_inspect")
        state = last.get("State") or {}
        if state.get("Restarting"):
            stable_since = None
        elif not state.get("Running"):
            stable_since = None
            if state.get("Status") in ("exited", "dead"):
                break
        else:
            health = state.get("Health")
            health_status = health.get("Status") if isinstance(health, dict) else None
            if health_status == "unhealthy":
                break
            if health_status == "healthy":
                return last
            if health_status is None:
                stable_since = stable_since if stable_since is not None else clock()
                if clock() - stable_since >= grace_period:
                    return last
        sleeper(min(0.1, max(timeout, 0.0)))
    detail = (last or {}).get("State")
    raise Step2OperationError(Step2Issue(
        Step2FailureCode.RUNTIME_NOT_READY, "runtime_readiness",
        f"victim did not become ready before timeout; state={detail!r}", True))


def _parse_port_key(value: str) -> tuple[int, str] | None:
    try:
        port_text, protocol = value.rsplit("/", 1)
        port = int(port_text)
    except (ValueError, AttributeError):
        return None
    return (port, protocol.lower()) if 1 <= port <= 65535 else None


def parse_exposed_ports(data: dict[str, Any]) -> tuple[ExposedPort, ...]:
    exposed = ((data.get("Config") or {}).get("ExposedPorts") or {})
    output = [ExposedPort(*parsed) for key in exposed if (parsed := _parse_port_key(key))]
    return tuple(sorted(output, key=lambda x: (x.container_port, x.protocol)))


def parse_published_ports(data: dict[str, Any]) -> tuple[PublishedPort, ...]:
    bindings = ((data.get("NetworkSettings") or {}).get("Ports") or {})
    output = []
    for key, values in bindings.items():
        parsed = _parse_port_key(key)
        if parsed is None or not isinstance(values, list):
            continue
        port, protocol = parsed
        for value in values:
            if not isinstance(value, dict):
                continue
            host_port = value.get("HostPort")
            try:
                host_port_int = int(host_port) if host_port else None
            except ValueError:
                host_port_int = None
            output.append(PublishedPort(port, protocol, value.get("HostIp"), host_port_int))
    return tuple(sorted(output, key=lambda x: (x.container_port, x.protocol, x.host_ip or "", x.host_port or 0)))


def parse_proc_net(text: str, protocol: str) -> tuple[ListeningPort, ...]:
    output = []
    lines = text.splitlines()
    if not lines or "local_address" not in lines[0]:
        raise ValueError("invalid /proc/net table header")
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":
            continue
        try:
            address_hex, port_hex = fields[1].split(":")
            port = int(port_hex, 16)
            if protocol == "tcp" and len(address_hex) == 8:
                raw = bytes.fromhex(address_hex)[::-1]
                address = str(ipaddress.IPv4Address(raw))
            elif protocol == "tcp6" and len(address_hex) == 32:
                # Linux presents each 32-bit word in host byte order.
                raw = b"".join(bytes.fromhex(address_hex[i:i + 8])[::-1] for i in range(0, 32, 8))
                address = str(ipaddress.IPv6Address(raw))
            else:
                continue
        except (ValueError, IndexError):
            raise ValueError("invalid /proc/net socket row")
        output.append(ListeningPort(port, protocol, address))
    unique = {(x.container_port, x.protocol, x.address): x for x in output}
    return tuple(unique[key] for key in sorted(unique))


def observe_listening_ports(name: str, runner: CommandRunner) -> tuple[ObservationStatus, tuple[ListeningPort, ...]]:
    observed = []
    readable = 0
    invalid = False
    for path, protocol in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
        result = runner.run(("docker", "exec", name, "cat", path))
        if result.exit_code != 0:
            continue
        readable += 1
        try:
            observed.extend(parse_proc_net(result.stdout, protocol))
        except ValueError:
            invalid = True
    if not readable or invalid:
        return ObservationStatus.UNKNOWN, ()
    unique = {(x.container_port, x.protocol, x.address): x for x in observed}
    return ObservationStatus.AVAILABLE, tuple(unique[key] for key in sorted(unique))


def collect_target_facts(request: Step2Request, image: ImageIdentity,
                         container: dict[str, Any], runner: CommandRunner, *,
                         container_name: str | None = None) -> TargetFacts:
    name = container_name or f"victim-{request.run_id}"
    current = _inspect_object(runner.run(("docker", "container", "inspect", name)),
                              Step2FailureCode.RUNTIME_INSPECTION_FAILED, "runtime_inspection")
    networks = ((current.get("NetworkSettings") or {}).get("Networks") or {})
    network_data = networks.get(request.network)
    if not isinstance(network_data, dict):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.RUNTIME_INSPECTION_FAILED, "runtime_inspection",
            f"victim is not attached to {request.network!r}"))
    listening_status, listening = observe_listening_ports(name, runner)
    config = current.get("Config") or {}
    state = current.get("State") or {}
    command = config.get("Cmd") if isinstance(config.get("Cmd"), list) else []
    entrypoint = config.get("Entrypoint") if isinstance(config.get("Entrypoint"), list) else []
    environment = config.get("Env") if isinstance(config.get("Env"), list) else []
    return TargetFacts(
        request.run_id, request.phase, name, str(current.get("Id") or ""),
        str(state.get("Status") or "unknown"), request.image_reference, image.image_id,
        image.selected_digest, request.network, network_data.get("IPAddress") or None,
        tuple(sorted(str(x) for x in environment)), tuple(str(x) for x in command),
        tuple(str(x) for x in entrypoint), parse_exposed_ports(current),
        parse_published_ports(current), listening_status, listening,
    )
