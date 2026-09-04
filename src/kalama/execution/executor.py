"""Injected execution boundaries and canonical execution-plan construction."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Protocol

from kalama.resolver.config_models import ExploitConfig

from ..target.victim_manager import CommandRunner
from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, EnvironmentValidation,
    ExecutionPlan, OperationState, SessionCollectionStatus, SessionEvidence,
)


class EnvironmentValidator(Protocol):
    def __call__(self, config: ExploitConfig, target_facts: Mapping[str, Any]) -> EnvironmentValidation: ...


class MetasploitExecutor(Protocol):
    def backend_available(self) -> bool: ...
    def sessions(self, *, timeout: float) -> SessionEvidence: ...
    def check(self, plan: ExecutionPlan, *, timeout: float) -> CheckEvidence: ...
    def exploit(self, plan: ExecutionPlan, *, timeout: float) -> CommandEvidence: ...


class LabCommandExecutor(Protocol):
    def execute(self, target: str, command: str, *, timeout: float) -> CommandEvidence: ...


def build_execution_plan(config: ExploitConfig, rank: int) -> ExecutionPlan:
    invariant, environment = config.invariant, config.environment
    options = {}
    for option in invariant.module_options:
        if option.field.confirmed:
            options[option.name] = option.field.value
    if environment.rhosts.confirmed: options["RHOSTS"] = environment.rhosts.value
    if environment.rport.confirmed: options["RPORT"] = environment.rport.value
    if invariant.targeturi.confirmed: options["TARGETURI"] = invariant.targeturi.value
    payload_options = {x.name: x.field.value for x in invariant.payload.options if x.field.confirmed}
    return ExecutionPlan(
        config.cve_id, rank, invariant.module_selection.module.value,
        invariant.target_selection.target_index.value,
        invariant.target_selection.target_name.value,
        tuple(sorted(options.items())), invariant.payload.payload.value,
        tuple(sorted(payload_options.items())), invariant.execution_protocol.run_check,
        invariant.execution_protocol.run_exploit,
        invariant.execution_protocol.session_confirmation_expected,
        invariant.preconditions.commands, invariant.preconditions.execution_target,
        invariant.preconditions.required, invariant.pre_attack.command,
        invariant.pre_attack.execution_target)


def normalize_check(stdout: str, stderr: str, state: OperationState) -> CheckVerdict:
    if state != OperationState.EXECUTED:
        return CheckVerdict.ERROR
    text = f"{stdout}\n{stderr}".casefold()
    # Negative phrases must win before the generic positive token.  Metasploit
    # commonly emits "not vulnerable", which still contains "vulnerable".
    if re.search(r"\b(safe|not vulnerable|not exploitable)\b", text):
        return CheckVerdict.SAFE
    if re.search(r"\b(vulnerable|appears)\b", text):
        return CheckVerdict.VULNERABLE if "vulnerable" in text else CheckVerdict.APPEARS
    if re.search(r"\bdetected\b", text): return CheckVerdict.DETECTED
    if "check method is not supported" in text: return CheckVerdict.UNSUPPORTED
    return CheckVerdict.UNKNOWN


def validate_committed_environment(config: ExploitConfig,
                                   target_facts: Mapping[str, Any], *,
                                   phase: str = "BEFORE") -> EnvironmentValidation:
    env = config.environment
    expected = {"run_id": target_facts.get("run_id"),
                "container_name": target_facts.get("container_name"),
                "container_id": target_facts.get("container_id"),
                "image_id": target_facts.get("image_id"),
                "image_digest": target_facts.get("image_digest"),
                "network": target_facts.get("network"),
                "ip_address": target_facts.get("ip_address")}
    actual = {"run_id": env.run_id, "container_name": env.container_name,
              "container_id": env.container_id, "image_id": env.image_id,
              "image_digest": env.image_digest, "network": env.network,
              "ip_address": env.ip_address}
    if expected != actual or env.phase.value != phase or env.network != "kalama-net":
        return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                     "canonical environment identity differs from committed TargetFacts")
    if env.rhosts.value != target_facts.get("ip_address"):
        return EnvironmentValidation(False, "TARGET_BINDING_MISMATCH",
                                     "RHOSTS does not match the committed victim IP")
    if env.rport.value is not None and (isinstance(env.rport.value, bool)
                                        or not isinstance(env.rport.value, int)
                                        or not 1 <= env.rport.value <= 65535):
        return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE", "RPORT is invalid")
    return EnvironmentValidation(True, observed=tuple(sorted(actual.items())))


class DockerLabCommandExecutor:
    def __init__(self, runner: CommandRunner, targets: Mapping[str, str]):
        self.runner, self.targets = runner, dict(targets)

    def execute(self, target: str, command: str, *, timeout: float) -> CommandEvidence:
        if target not in self.targets:
            return CommandEvidence(OperationState.EXECUTION_ERROR, stderr="invalid lab target")
        result = self.runner.run(("docker", "exec", self.targets[target], "sh", "-lc", command),
                                 timeout=timeout)
        state = OperationState.EXECUTED if result.exit_code == 0 else (
            OperationState.TIMEOUT if result.exit_code == 124 else OperationState.EXECUTION_ERROR)
        return CommandEvidence(state, exit_code=result.exit_code, stdout=result.stdout,
                               stderr=result.stderr, submitted=True)


class DockerEnvironmentValidator:
    """Read-only validation of the already committed victim container."""

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    def __call__(self, config: ExploitConfig,
                 target_facts: Mapping[str, Any]) -> EnvironmentValidation:
        name = target_facts.get("container_name")
        result = self.runner.run(("docker", "inspect", str(name)), timeout=15)
        if result.exit_code != 0:
            return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                         "committed victim container is unavailable")
        try:
            values = json.loads(result.stdout)
            raw = values[0]
            networks = raw["NetworkSettings"]["Networks"]
            network = target_facts.get("network")
            observed = {"container_id": raw.get("Id"), "image_id": raw.get("Image"),
                        "running": raw.get("State", {}).get("Running"),
                        "network": network,
                        "ip_address": networks.get(network, {}).get("IPAddress")}
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                         f"Docker inspection was malformed: {exc}")
        expected = {"container_id": target_facts.get("container_id"),
                    "image_id": target_facts.get("image_id"), "running": True,
                    "network": target_facts.get("network"),
                    "ip_address": target_facts.get("ip_address")}
        if observed != expected:
            return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                         "live victim identity differs from committed TargetFacts",
                                         tuple(sorted(observed.items())))
        return EnvironmentValidation(True, observed=tuple(sorted(observed.items())))


class DockerMetasploitExecutor:
    """Persistent msf-resolver-host adapter behind the shared CommandRunner."""

    SESSION_RE = re.compile(r"^\s*(\d+)\s+", re.MULTILINE)
    SENSITIVE_RE = re.compile(r"(PASS|PASSWORD|TOKEN|SECRET|API_KEY)", re.IGNORECASE)

    def __init__(self, runner: CommandRunner, *, container: str = "msf-resolver-host",
                 msfconsole_path: str = "/usr/src/metasploit-framework/msfconsole"):
        self.runner, self.container, self.msfconsole_path = runner, container, msfconsole_path

    def backend_available(self) -> bool:
        result = self.runner.run(("docker", "inspect", "-f", "{{.State.Running}}",
                                  self.container), timeout=15)
        return result.exit_code == 0 and result.stdout.strip() == "true"

    @staticmethod
    def _safe(value: Any) -> str:
        text = str(value)
        if any(x in text for x in (";", "\n", "\r")):
            raise ValueError("Metasploit values may not contain command separators")
        return text

    def _commands(self, plan: ExecutionPlan, operation: str) -> tuple[str, list[tuple[str, str]]]:
        commands = [f"use {self._safe(plan.module)}"]
        secrets = []
        if plan.target_index is not None:
            commands.append(f"set TARGET {plan.target_index}")
        for name, value in plan.module_options:
            safe = self._safe(value)
            commands.append(f"set {self._safe(name)} {safe}")
            if self.SENSITIVE_RE.search(name): secrets.append((safe, "<redacted>"))
        if plan.payload:
            commands.append(f"set PAYLOAD {self._safe(plan.payload)}")
        for name, value in plan.payload_options:
            safe = self._safe(value)
            commands.append(f"set {self._safe(name)} {safe}")
            if self.SENSITIVE_RE.search(name): secrets.append((safe, "<redacted>"))
        commands.extend((operation, "exit -y"))
        return "; ".join(commands), secrets

    @staticmethod
    def _redact(text: str, secrets: list[tuple[str, str]]) -> str:
        for value, replacement in secrets:
            if value: text = text.replace(value, replacement)
        return text

    def _run(self, plan: ExecutionPlan, operation: str, timeout: float) -> CommandEvidence:
        try:
            resource, secrets = self._commands(plan, operation)
        except ValueError as exc:
            return CommandEvidence(OperationState.EXECUTION_ERROR, stderr=str(exc))
        result = self.runner.run(("docker", "exec", self.container, self.msfconsole_path,
                                  "-q", "-n", "-x", resource), timeout=timeout)
        state = OperationState.EXECUTED if result.exit_code == 0 else (
            OperationState.TIMEOUT if result.exit_code == 124 else OperationState.BACKEND_ERROR)
        return CommandEvidence(state, exit_code=result.exit_code,
                               stdout=self._redact(result.stdout, secrets),
                               stderr=self._redact(result.stderr, secrets), submitted=True)

    def sessions(self, *, timeout: float) -> SessionEvidence:
        result = self.runner.run(("docker", "exec", self.container, self.msfconsole_path,
                                  "-q", "-n", "-x", "sessions -l; exit -y"), timeout=timeout)
        if result.exit_code != 0:
            return SessionEvidence(SessionCollectionStatus.UNKNOWN,
                                   error=result.stderr.strip() or "session inventory failed")
        return SessionEvidence(SessionCollectionStatus.COLLECTED,
                               post_ids=tuple(sorted(set(self.SESSION_RE.findall(result.stdout)))))

    def check(self, plan: ExecutionPlan, *, timeout: float) -> CheckEvidence:
        operation = self._run(plan, "check", timeout)
        return CheckEvidence(normalize_check(operation.stdout, operation.stderr, operation.state),
                             operation)

    def exploit(self, plan: ExecutionPlan, *, timeout: float) -> CommandEvidence:
        return self._run(plan, "run -z", timeout)
