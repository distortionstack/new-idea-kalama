"""Shared before/after attempt runner using the same execution plan and oracle."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Mapping

from kalama.resolver.config import validate_exploit_config

from .executor import (
    EnvironmentValidator, LabCommandExecutor, MetasploitExecutor,
    build_execution_plan, validate_committed_environment,
)
from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, OperationState, OracleVerdict,
    SessionCollectionStatus, SessionEvidence,
)
from .oracle import classify_oracle


def execute_attempt(*, run_id: str, phase: str, rank: int, config,
                    config_reference: Mapping[str, Any], target_facts: Mapping[str, Any],
                    environment_validator: EnvironmentValidator,
                    metasploit: MetasploitExecutor, lab_commands: LabCommandExecutor,
                    now: Callable[[], str], operation_timeout: float,
                    command_timeout: float, session_timeout: float,
                    target_aliases: Mapping[str, str] | None = None) -> tuple[dict[str, Any], str, bool]:
    started = now()
    validation = validate_exploit_config(config)
    committed = validate_committed_environment(config, target_facts, phase=phase.upper())
    runtime = environment_validator(config, target_facts) if committed.valid else committed
    environment = runtime if not runtime.valid else committed
    not_run = CommandEvidence(OperationState.NOT_RUN)
    check = CheckEvidence(CheckVerdict.NOT_RUN, not_run)
    exploit = not_run
    sessions = SessionEvidence(SessionCollectionStatus.UNKNOWN, error="not collected")
    preconditions, pre_attack = [], None
    prerequisites_ok = validation.ready and environment.valid
    issue, systemic = None, False
    plan = build_execution_plan(config, rank) if validation.ready else None
    aliases = dict(target_aliases or {})

    def target(value: str | None) -> str | None:
        return aliases.get(value, value) if value else value

    if not validation.ready:
        issue = "CONFIG_NOT_READY"
    elif not environment.valid:
        issue = environment.code or "ENVIRONMENT_ERROR"
    elif plan is not None:
        allowed = {"victim", "victim-after", "kalama-workbench", "msf-resolver-host"}
        precondition_target = target(plan.precondition_target)
        pre_attack_target = target(plan.pre_attack_target)
        if plan.precondition_commands:
            if precondition_target not in allowed:
                prerequisites_ok, issue = False, "PRECONDITION_TARGET_INVALID"
            else:
                for index, command in enumerate(plan.precondition_commands, 1):
                    begin = now()
                    evidence = lab_commands.execute(precondition_target, command,
                                                    timeout=command_timeout)
                    evidence = replace(evidence, started_at=evidence.started_at or begin,
                                       ended_at=evidence.ended_at or now())
                    preconditions.append({"step": index, "execution_target": precondition_target,
                                          **evidence.to_dict()})
                    if evidence.state != OperationState.EXECUTED:
                        prerequisites_ok, issue = False, "PRECONDITION_FAILED"
                        break
        if prerequisites_ok and plan.pre_attack_command:
            if pre_attack_target not in allowed:
                prerequisites_ok, issue = False, "PRE_ATTACK_TARGET_INVALID"
            else:
                begin = now()
                value = lab_commands.execute(pre_attack_target, plan.pre_attack_command,
                                             timeout=command_timeout)
                value = replace(value, started_at=value.started_at or begin,
                                ended_at=value.ended_at or now())
                pre_attack = {"execution_target": pre_attack_target, **value.to_dict()}
                if value.state != OperationState.EXECUTED:
                    prerequisites_ok, issue = False, "PRE_ATTACK_FAILED"
        baseline = metasploit.sessions(timeout=session_timeout) if (
            prerequisites_ok and plan.run_exploit) else None
        if prerequisites_ok and plan.run_check:
            check = metasploit.check(plan, timeout=operation_timeout)
            systemic = check.operation.state == OperationState.BACKEND_ERROR
        if prerequisites_ok and plan.run_exploit:
            exploit = metasploit.exploit(plan, timeout=operation_timeout)
            systemic = systemic or exploit.state == OperationState.BACKEND_ERROR
            post = metasploit.sessions(timeout=session_timeout)
            if (baseline is not None and baseline.status == SessionCollectionStatus.COLLECTED
                    and post.status == SessionCollectionStatus.COLLECTED):
                before, after = set(baseline.post_ids), set(post.post_ids)
                sessions = SessionEvidence(SessionCollectionStatus.COLLECTED,
                    tuple(sorted(before)), tuple(sorted(after)), tuple(sorted(after - before)), "UNKNOWN")
            else:
                sessions = SessionEvidence(SessionCollectionStatus.UNKNOWN,
                    error=(post.error or baseline.error if baseline is not None else post.error))

    protocol = config.invariant.execution_protocol
    oracle = classify_oracle(config_ready=validation.ready, environment=environment,
        run_check=protocol.run_check, run_exploit=protocol.run_exploit,
        prerequisites_ok=prerequisites_ok, check=check, exploit=exploit, sessions=sessions)
    disposition = "INCONCLUSIVE"
    if oracle.verdict == OracleVerdict.VULNERABLE:
        disposition = "EXPLOIT_SUCCEEDED" if protocol.run_exploit else "CHECK_ONLY"
    elif oracle.verdict == OracleVerdict.NOT_VULNERABLE:
        disposition = "EXPLOIT_FAILED" if protocol.run_exploit else "CHECK_ONLY"
    elif issue and (issue.startswith("ENVIRONMENT") or issue in {
            "TARGET_BINDING_MISMATCH", "AFTER_RPORT_UNRESOLVED", "AFTER_LHOST_UNRESOLVED"}):
        disposition = "AFTER_ENVIRONMENT_UNRESOLVED" if phase == "after" else "ENVIRONMENT_ERROR"
    elif oracle.verdict == OracleVerdict.NOT_EVALUATED:
        disposition = "NOT_EXECUTED"
    attempt = {"attempt_id": f"{run_id}-{rank:02d}-{phase}-1", "attempt_number": 1,
        "run_id": run_id, "phase": phase, "rank": rank, "cve_id": config.cve_id,
        "config": dict(config_reference), "started_at": started, "ended_at": now(),
        "environment_validation": environment.to_dict(), "preconditions": preconditions,
        "pre_attack": pre_attack, "check_evidence": check.to_dict(),
        "exploit_evidence": exploit.to_dict(), "session_evidence": sessions.to_dict(),
        "oracle": oracle.to_dict(), "metric_eligibility": oracle.metric_eligibility.to_dict(),
        "issues": [issue] if issue else []}
    return attempt, disposition, systemic
