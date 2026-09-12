"""Injected execution boundaries and canonical execution-plan construction."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from kalama.metasploit_fixtures import (
    ApprovedFixtureRegistry,
    FixtureConfigurationError,
    registry_from_env,
)
from kalama.resolver.config_models import ExploitConfig

from ..target.victim_manager import CommandRunner
from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, EnvironmentValidation,
    ExecutionPlan, ImpactEvidence, ImpactEvidenceStatus, OperationState,
    SessionCollectionStatus, SessionEvidence,
)


class EnvironmentValidator(Protocol):
    def __call__(self, config: ExploitConfig, target_facts: Mapping[str, Any]) -> EnvironmentValidation: ...


class MetasploitExecutor(Protocol):
    def backend_available(self) -> bool: ...
    def sessions(self, *, timeout: float) -> SessionEvidence: ...
    def check(self, plan: ExecutionPlan, *, timeout: float) -> CheckEvidence: ...
    def exploit(self, plan: ExecutionPlan, *, timeout: float) -> CommandEvidence: ...


class SingleInvocationExecutor(Protocol):
    """Optional capability: one msfconsole for check+exploit+session listing."""

    def run_attempt(self, plan: ExecutionPlan, *, target_facts: Mapping[str, Any],
                    run_check: bool, timeout: float,
                    settle_seconds: float | None = ...) -> SingleInvocationResult: ...


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
    selected_candidate = next(
        (item.candidate for item in invariant.module_selection.ranking.ranked_candidates
         if item.candidate.module_path == invariant.module_selection.module.value),
        None,
    )
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
        invariant.pre_attack.execution_target,
        getattr(selected_candidate, "module_source", "stock"),
        getattr(selected_candidate, "fixture_source_path", None),
        getattr(selected_candidate, "fixture_sha256", None),
        getattr(selected_candidate, "fixture_manifest", None),
        getattr(selected_candidate, "fixture_modules_root", None),
        getattr(selected_candidate, "fixture_namespace", None),
        getattr(selected_candidate, "loaded_module_path", None))


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


# ---------------------------------------------------------------------------
# Same-invocation session capture.
#
# Root cause (J1Thf): the executor invoked one ephemeral msfconsole for
# `run -z` and a *separate* msfconsole later for `sessions -l -v -x`.
# Reverse-shell sessions die with the first process, so the later inventory
# structurally returns [].  The fix is a single msfconsole invocation per
# exploit attempt: baseline listing, check (if configured), exploit, brief
# settle wait, post listing, all before exit, with stdout/stderr captured.
# ---------------------------------------------------------------------------

DEFAULT_SESSION_SETTLE_SECONDS = 7.0
SESSION_SETTLE_ENV_VAR = "KALAMA_SESSION_SETTLE_SECONDS"

MARK_BASELINE_BEGIN = "KALAMA_BASELINE_BEGIN"
MARK_BASELINE_END = "KALAMA_BASELINE_END"
MARK_EXPLOIT_BEGIN = "KALAMA_EXPLOIT_BEGIN"
MARK_EXPLOIT_END = "KALAMA_EXPLOIT_END"
MARK_POST_BEGIN = "KALAMA_POST_BEGIN"
MARK_POST_END = "KALAMA_POST_END"

SESSION_OPENED_RE = re.compile(
    r"(?:meterpreter|command\s+shell|shell|session)\s+session\s+(\d+)\s+opened\s*\(([^)]+)\)",
    re.IGNORECASE)
ENDPOINT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*:\s*(\d+)")

# Generic "command executed" style module messages are ambiguous on their
# own (no command output tied to the target).  They must never confirm
# deterministic impact without a target-tied artifact.
AMBIGUOUS_COMMAND_TOKENS = ("command executed", "command sent", "executed the injected")


def session_settle_seconds(value: float | None = None) -> float:
    """Conservative settle wait between `run -z` and the post listing."""
    if value is not None:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return DEFAULT_SESSION_SETTLE_SECONDS
        return min(max(parsed, 0.0), 30.0)
    raw = os.environ.get(SESSION_SETTLE_ENV_VAR, "").strip()
    if not raw:
        return DEFAULT_SESSION_SETTLE_SECONDS
    try:
        return min(max(float(raw), 0.0), 30.0)
    except ValueError:
        return DEFAULT_SESSION_SETTLE_SECONDS


def _host_port(text: str) -> tuple[str | None, int | None]:
    match = ENDPOINT_RE.search(text or "")
    if not match:
        return None, None
    try:
        return match.group(1), int(match.group(2))
    except ValueError:
        return match.group(1), None


def parse_session_opened_events(stdout: str) -> tuple[dict[str, Any], ...]:
    """Extract `session N opened (A -> B)` events from msfconsole output."""
    events: list[dict[str, Any]] = []
    for match in SESSION_OPENED_RE.finditer(stdout or ""):
        sid, endpoints = match.group(1), match.group(2)
        parts = re.split(r"\s*(?:->|<->|<-)\s*", endpoints)
        local_host, local_port, peer_host, peer_port = None, None, None, None
        if len(parts) >= 2:
            local_host, local_port = _host_port(parts[0])
            peer_host, peer_port = _host_port(parts[-1])
        else:
            peer_host, peer_port = _host_port(endpoints)
        events.append({"session_id": sid, "raw": match.group(0).strip(),
                       "local_host": local_host, "local_port": local_port,
                       "peer_host": peer_host, "peer_port": peer_port})
    return tuple(events)


def _section(stdout: str, begin: str, end: str) -> str:
    if begin not in stdout or end not in stdout:
        return ""
    return stdout.split(begin, 1)[1].split(end, 1)[0]


def _plan_lhost_lport(plan: ExecutionPlan) -> tuple[str | None, int | None]:
    lhost, lport = None, None
    for name, value in plan.payload_options:
        if str(name).upper() == "LHOST" and value is not None:
            lhost = str(value).strip() or None
        elif str(name).upper() == "LPORT" and value is not None:
            try:
                lport = int(value)
            except (TypeError, ValueError):
                lport = None
    return lhost, lport


def attribute_same_invocation(*, baseline_ids: tuple[str, ...],
                              post_ids: tuple[str, ...],
                              session_details: Mapping[str, Mapping[str, Any]],
                              stdout: str, plan: ExecutionPlan,
                              target_facts: Mapping[str, Any]) -> SessionEvidence:
    """Attribute sessions opened inside a single msfconsole invocation.

    A session id is attributable only when BOTH hold:
      1. msf stdout reports `session <id> opened` from the target IP to the
         configured LHOST/LPORT (same session id), and
      2. the same-invocation post `sessions -l -v -x` listing confirms that
         session id with a tunnel peer matching the target IP (and the
         module tag, when present, matching the attempted module).

    Stdout-only claims without listing confirmation are never attributed.
    """
    before, after = set(baseline_ids or ()), set(post_ids or ())
    new_ids = tuple(sorted(after - before))
    target_ip = str(target_facts.get("ip_address") or "").strip()
    target_container = str(target_facts.get("container_name") or "")
    lhost, lport = _plan_lhost_lport(plan)
    events_by_id: dict[str, dict[str, Any]] = {}
    for event in parse_session_opened_events(stdout):
        events_by_id.setdefault(str(event.get("session_id")), event)
    attributable, mismatched = [], []
    for sid in new_ids:
        item = dict(session_details.get(sid, {}))

        def _host_of(*names: str) -> str | None:
            for name in names:
                raw = item.get(name)
                if raw is None:
                    continue
                text = str(raw).strip()
                if not text:
                    continue
                host, _ = _host_port(text)
                if host:
                    return host
                if text and "." in text and ":" not in text:
                    return text
            return None

        listing_host = _host_of("tunnel_peer", "session_host", "target_host")
        via = item.get("via_exploit")
        module_ok = via in (None, "", plan.module)
        listing_ok = bool(target_ip and listing_host == target_ip and module_ok)
        event = events_by_id.get(sid)
        event_ok = False
        if event is not None and target_ip:
            peer_ok = event.get("peer_host") == target_ip
            if lhost is not None and lport is not None:
                event_ok = bool(peer_ok and event.get("local_host") == lhost
                                and event.get("local_port") == lport)
            elif lhost is not None:
                event_ok = bool(peer_ok and event.get("local_host") == lhost)
            else:
                event_ok = bool(peer_ok)
        if listing_ok and event_ok:
            attributable.append(sid)
        elif listing_host or event is not None:
            mismatched.append(sid)
    if attributable:
        attribution = "TARGET_MATCH"
    elif mismatched:
        attribution = "MISMATCH"
    elif new_ids:
        attribution = "UNKNOWN"
    else:
        attribution = "NO_NEW_SESSION"
    enriched: list[tuple[str, tuple[tuple[str, Any], ...]]] = []
    for sid in sorted(set(post_ids or ())):
        data = dict(session_details.get(sid, {}))
        if sid in new_ids:
            data.setdefault("kalama_new_in_attempt", True)
            data.setdefault("kalama_attempt_target_ip", target_ip)
            data.setdefault("kalama_attempt_target_container", target_container)
        enriched.append((sid, tuple(sorted(data.items()))))
    return SessionEvidence(
        SessionCollectionStatus.COLLECTED, tuple(sorted(before)),
        tuple(sorted(after)), new_ids, attribution,
        session_details=tuple(enriched),
        attributable_ids=tuple(attributable), mismatched_ids=tuple(mismatched))


def extract_command_impact(*, stdout: str, stderr: str, plan: ExecutionPlan,
                           target_facts: Mapping[str, Any],
                           exploit_state: OperationState) -> ImpactEvidence:
    """Conservative deterministic command-output impact extraction.

    Only confirms impact when the same-invocation output contains an
    unambiguous target-tied artifact for this module attempt.  Generic
    `Command executed` style messages without command output are treated
    as ambiguous and never confirm (NOT_COLLECTED), so the strict oracle
    is never loosened by stdout prose alone.
    """
    _ = (plan, target_facts)
    if exploit_state != OperationState.EXECUTED:
        return ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED)
    text = f"{stdout or ''}\n{stderr or ''}"
    lowered = text.casefold()
    # Explicit lab marker hook: a pre-attack planted marker echoed back by
    # the exploit output ties output to this attempt.  No marker mechanism
    # is planted yet, so this path is dormant but available.
    marker = re.search(r"KALAMA_IMPACT_MARKER\s*:\s*([A-Za-z0-9_:\-.]{4,128})", text)
    if marker:
        return ImpactEvidence(status=ImpactEvidenceStatus.COLLECTED,
                              basis="COMMAND_MARKER", confirmed=True,
                              details=(("marker", marker.group(1)),))
    if any(token in lowered for token in AMBIGUOUS_COMMAND_TOKENS):
        return ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED,
                              error="ambiguous command-execution prose without "
                                    "target-tied command output")
    return ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED)


@dataclass(frozen=True)
class SingleInvocationResult:
    check: CheckEvidence
    exploit: CommandEvidence
    sessions: SessionEvidence
    impact: ImpactEvidence




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
            labels = (raw.get("Config") or {}).get("Labels") or {}
            observed = {"container_id": raw.get("Id"), "image_id": raw.get("Image"),
                        "running": raw.get("State", {}).get("Running"),
                        "network": network,
                        "ip_address": networks.get(network, {}).get("IPAddress"),
                        "kalama_managed": labels.get("kalama.managed"),
                        "kalama_run_id": labels.get("kalama.run_id"),
                        "kalama_phase": labels.get("kalama.phase")}
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                         f"Docker inspection was malformed: {exc}")
        expected = {"container_id": target_facts.get("container_id"),
                    "image_id": target_facts.get("image_id"), "running": True,
                    "network": target_facts.get("network"),
                    "ip_address": target_facts.get("ip_address"),
                    "kalama_managed": "true",
                    "kalama_run_id": target_facts.get("run_id"),
                    "kalama_phase": target_facts.get("phase")}
        if observed != expected:
            if observed.get("kalama_run_id") != expected.get("kalama_run_id"):
                return EnvironmentValidation(False, "ENVIRONMENT_RUN_ID_MISMATCH",
                                             "live victim Docker label does not match the committed run_id",
                                             tuple(sorted(observed.items())))
            return EnvironmentValidation(False, "ENVIRONMENT_BINDING_STALE",
                                         "live victim identity differs from committed TargetFacts",
                                         tuple(sorted(observed.items())))
        return EnvironmentValidation(True, observed=tuple(sorted(observed.items())))


class DockerMetasploitExecutor:
    """Persistent msf-resolver-host adapter behind the shared CommandRunner."""

    SESSION_RE = re.compile(r"^\s*(\d+)\s+", re.MULTILINE)
    VERBOSE_SESSION_RE = re.compile(r"Session ID:\s*(\d+)", re.IGNORECASE)
    VERBOSE_TUNNEL_RE = re.compile(
        r"Tunnel:\s*(\d{1,3}(?:\.\d{1,3}){3}:\d+)\s*(?:->|<->)\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3}:\d+)", re.IGNORECASE)
    VERBOSE_VIA_RE = re.compile(r"Via:\s*(\S+)", re.IGNORECASE)
    VERBOSE_HOST_RE = re.compile(
        r"(?:Session Host|Target Host):\s*(\S+)", re.IGNORECASE)
    SENSITIVE_RE = re.compile(r"(PASS|PASSWORD|TOKEN|SECRET|API_KEY)", re.IGNORECASE)
    PEER_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}:\d+)")

    @staticmethod
    def _parse_session_details(stdout: str) -> tuple[tuple[str, tuple[tuple[str, Any], ...]], ...]:
        details: dict[str, dict[str, Any]] = {}
        verbose_sid: str | None = None
        for line in stdout.splitlines():
            verbose_match = DockerMetasploitExecutor.VERBOSE_SESSION_RE.search(line)
            if verbose_match:
                verbose_sid = verbose_match.group(1)
                details.setdefault(verbose_sid, {"raw_line": line.strip()})
                continue
            if verbose_sid is not None:
                tunnel = DockerMetasploitExecutor.VERBOSE_TUNNEL_RE.search(line)
                if tunnel:
                    item = details.setdefault(verbose_sid, {"raw_line": line.strip()})
                    item.setdefault("tunnel_local", tunnel.group(1))
                    item.setdefault("tunnel_peer", tunnel.group(2))
                    continue
                via = DockerMetasploitExecutor.VERBOSE_VIA_RE.search(line)
                if via:
                    item = details.setdefault(verbose_sid, {"raw_line": line.strip()})
                    value = via.group(1).strip()
                    if value.startswith("exploit/"):
                        item.setdefault("via_exploit", value)
                    elif value.startswith("payload/"):
                        item.setdefault("via_payload", value)
                    continue
                host = DockerMetasploitExecutor.VERBOSE_HOST_RE.search(line)
                if host:
                    item = details.setdefault(verbose_sid, {"raw_line": line.strip()})
                    item.setdefault("session_host", host.group(1).strip())
                    continue
            match = DockerMetasploitExecutor.SESSION_RE.match(line)
            if not match:
                continue
            sid = match.group(1)
            item = details.setdefault(sid, {"raw_line": line.strip()})
            peers = DockerMetasploitExecutor.PEER_RE.findall(line)
            if len(peers) >= 2:
                item.setdefault("tunnel_local", peers[0])
                item.setdefault("tunnel_peer", peers[-1])
            elif len(peers) == 1:
                item.setdefault("tunnel_peer", peers[0])
            words = line.split()
            for word in words:
                if word.startswith("exploit/"):
                    item.setdefault("via_exploit", word)
                elif word.startswith("payload/"):
                    item.setdefault("via_payload", word)
        return tuple((sid, tuple(sorted(value.items()))) for sid, value in sorted(details.items()))

    @staticmethod
    def _session_ids(stdout: str) -> tuple[str, ...]:
        table = DockerMetasploitExecutor.SESSION_RE.findall(stdout)
        verbose = DockerMetasploitExecutor.VERBOSE_SESSION_RE.findall(stdout)
        return tuple(sorted(set(table) | set(verbose)))

    def __init__(self, runner: CommandRunner, *, container: str = "msf-resolver-host",
                 msfconsole_path: str = "/usr/src/metasploit-framework/msfconsole",
                 fixture_registry: ApprovedFixtureRegistry | None = None):
        self.runner, self.container, self.msfconsole_path = runner, container, msfconsole_path
        self.fixture_registry = registry_from_env() if fixture_registry is None else fixture_registry

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

    def _fixture_loadpath_commands(self, plan: ExecutionPlan) -> list[str]:
        if plan.module_source != "lab_fixture":
            return []
        module = self.fixture_registry.require_module(plan.module, plan.fixture_sha256)
        if plan.fixture_source_path and str(module.source_path) != str(plan.fixture_source_path):
            raise FixtureConfigurationError(
                f"fixture module {plan.module!r} source path mismatch: expected artifact "
                f"{plan.fixture_source_path}, approved path has {module.source_path}"
            )
        self.fixture_registry.ensure_container_roots_runner(
            self.runner, self.container, timeout=15)
        return [f"loadpath {self._safe(module.container_modules_root)}"]

    def _commands(self, plan: ExecutionPlan, operation: str) -> tuple[str, list[tuple[str, str]]]:
        commands = self._fixture_loadpath_commands(plan)
        commands.append(f"use {self._safe(plan.module)}")
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
        except (ValueError, FixtureConfigurationError) as exc:
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
                                  "-q", "-n", "-x", "sessions -l -v -x; exit -y"), timeout=timeout)
        if result.exit_code != 0:
            return SessionEvidence(SessionCollectionStatus.UNKNOWN,
                                   error=result.stderr.strip() or "session inventory failed")
        ids = self._session_ids(result.stdout)
        return SessionEvidence(SessionCollectionStatus.COLLECTED, post_ids=ids,
                               session_details=self._parse_session_details(result.stdout))

    def check(self, plan: ExecutionPlan, *, timeout: float) -> CheckEvidence:
        operation = self._run(plan, "check", timeout)
        return CheckEvidence(normalize_check(operation.stdout, operation.stderr, operation.state),
                             operation)

    def exploit(self, plan: ExecutionPlan, *, timeout: float) -> CommandEvidence:
        return self._run(plan, "run -z", timeout)

    def _single_invocation_commands(self, plan: ExecutionPlan, *, run_check: bool,
                                    settle_seconds: float) -> tuple[str, list[tuple[str, str]]]:
        """One msfconsole resource script: baseline, check, exploit, post listing."""
        commands = [f"echo {MARK_BASELINE_BEGIN}", "sessions -l -v -x",
                    f"echo {MARK_BASELINE_END}"]
        commands.extend(self._fixture_loadpath_commands(plan))
        commands.append(f"use {self._safe(plan.module)}")
        secrets: list[tuple[str, str]] = []
        if plan.target_index is not None:
            commands.append(f"set TARGET {plan.target_index}")
        for name, value in plan.module_options:
            safe = self._safe(value)
            commands.append(f"set {self._safe(name)} {safe}")
            if self.SENSITIVE_RE.search(name):
                secrets.append((safe, "<redacted>"))
        if plan.payload:
            commands.append(f"set PAYLOAD {self._safe(plan.payload)}")
        for name, value in plan.payload_options:
            safe = self._safe(value)
            commands.append(f"set {self._safe(name)} {safe}")
            if self.SENSITIVE_RE.search(name):
                secrets.append((safe, "<redacted>"))
        if run_check:
            commands.append("check")
        commands.append(f"echo {MARK_EXPLOIT_BEGIN}")
        commands.append("run -z")
        wait = session_settle_seconds(settle_seconds)
        if wait > 0:
            commands.append(f"sleep {wait:g}")
        commands.append(f"echo {MARK_EXPLOIT_END}")
        commands.append(f"echo {MARK_POST_BEGIN}")
        commands.append("sessions -l -v -x")
        commands.append(f"echo {MARK_POST_END}")
        commands.append("exit -y")
        return "; ".join(commands), secrets

    def run_attempt(self, plan: ExecutionPlan, *, target_facts: Mapping[str, Any],
                    run_check: bool, timeout: float,
                    settle_seconds: float | None = None) -> SingleInvocationResult:
        """Single-invocation check+exploit with same-process session capture.

        Sessions opened by `run -z` are listed before the msfconsole process
        exits, so reverse-shell evidence is attributable instead of dying
        with an ephemeral exploit process.
        """
        wait = session_settle_seconds(settle_seconds)
        not_run = CommandEvidence(OperationState.NOT_RUN)
        try:
            resource, secrets = self._single_invocation_commands(
                plan, run_check=run_check, settle_seconds=wait)
        except (ValueError, FixtureConfigurationError) as exc:
            error = CommandEvidence(OperationState.EXECUTION_ERROR, stderr=str(exc))
            check = CheckEvidence(CheckVerdict.ERROR if run_check else CheckVerdict.NOT_RUN,
                                  error if run_check else not_run)
            unknown = SessionEvidence(SessionCollectionStatus.UNKNOWN, error=str(exc))
            return SingleInvocationResult(
                check, error,
                unknown, ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED))
        total_timeout = timeout + wait + 30.0
        result = self.runner.run(("docker", "exec", self.container, self.msfconsole_path,
                                  "-q", "-n", "-x", resource), timeout=total_timeout)
        state = OperationState.EXECUTED if result.exit_code == 0 else (
            OperationState.TIMEOUT if result.exit_code == 124 else OperationState.BACKEND_ERROR)
        stdout = self._redact(result.stdout, secrets)
        stderr = self._redact(result.stderr, secrets)
        exploit = CommandEvidence(state, exit_code=result.exit_code,
                                  stdout=stdout, stderr=stderr, submitted=True)
        if run_check:
            check = CheckEvidence(normalize_check(stdout, stderr, state), exploit)
        else:
            check = CheckEvidence(CheckVerdict.NOT_RUN, not_run)
        if state != OperationState.EXECUTED:
            sessions = SessionEvidence(SessionCollectionStatus.UNKNOWN,
                                       error=(stderr.strip() or stdout.strip()
                                              or "single-invocation session capture failed"))
            return SingleInvocationResult(
                check, exploit, sessions,
                ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED))
        baseline_text = _section(stdout, MARK_BASELINE_BEGIN, MARK_BASELINE_END)
        post_text = _section(stdout, MARK_POST_BEGIN, MARK_POST_END)
        baseline_ids = self._session_ids(baseline_text) if baseline_text else ()
        if post_text:
            post_ids = self._session_ids(post_text)
            details = {sid: dict(values)
                       for sid, values in self._parse_session_details(post_text)}
        else:
            # Markers missing (old msf without echo, truncated output): fall
            # back to whole-stdout listing rather than claiming NO_NEW_SESSION.
            post_ids = self._session_ids(stdout)
            details = {sid: dict(values)
                       for sid, values in self._parse_session_details(stdout)}
        sessions = attribute_same_invocation(
            baseline_ids=baseline_ids, post_ids=post_ids,
            session_details=details, stdout=stdout, plan=plan,
            target_facts=target_facts)
        impact = extract_command_impact(
            stdout=stdout, stderr=stderr, plan=plan,
            target_facts=target_facts, exploit_state=state)
        return SingleInvocationResult(check, exploit, sessions, impact)
