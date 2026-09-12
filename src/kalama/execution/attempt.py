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
    CheckEvidence, CheckVerdict, CommandEvidence, ImpactEvidence,
    ImpactEvidenceStatus, OperationState, OracleVerdict,
    SessionCollectionStatus, SessionEvidence,
)
from .oracle import classify_oracle


def _session_detail_map(evidence: SessionEvidence) -> dict[str, dict[str, Any]]:
    return {sid: dict(values) for sid, values in evidence.session_details}


def _host_part(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    if ":" in text and text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _attribute_sessions(*, baseline: SessionEvidence, post: SessionEvidence,
                        plan, target_facts: Mapping[str, Any]) -> SessionEvidence:
    before, after = set(baseline.post_ids), set(post.post_ids)
    new_ids = tuple(sorted(after - before))
    details = _session_detail_map(post)
    target_ip = str(target_facts.get("ip_address") or "")
    target_container = str(target_facts.get("container_name") or "")
    attributable, mismatched = [], []
    for sid in new_ids:
        item = details.get(sid, {})
        hosts = {_host_part(item.get(name)) for name in (
            "tunnel_peer", "session_host", "target_host")}
        hosts.discard(None)
        module_ok = item.get("via_exploit") in {None, "", plan.module}
        if target_ip and target_ip in hosts and module_ok:
            attributable.append(sid)
        elif hosts:
            mismatched.append(sid)
    if attributable:
        attribution = "TARGET_MATCH"
    elif mismatched:
        attribution = "MISMATCH"
    elif new_ids:
        attribution = "UNKNOWN"
    else:
        attribution = "NO_NEW_SESSION"
    enriched = []
    for sid, values in post.session_details:
        data = dict(values)
        if sid in new_ids:
            data.setdefault("kalama_new_in_attempt", True)
            data.setdefault("kalama_attempt_target_ip", target_ip)
            data.setdefault("kalama_attempt_target_container", target_container)
        enriched.append((sid, tuple(sorted(data.items()))))
    return SessionEvidence(SessionCollectionStatus.COLLECTED,
        tuple(sorted(before)), tuple(sorted(after)), new_ids, attribution,
        session_details=tuple(enriched), attributable_ids=tuple(attributable),
        mismatched_ids=tuple(mismatched))


def execute_attempt(*, run_id: str, phase: str, rank: int, config,
                    config_reference: Mapping[str, Any], target_facts: Mapping[str, Any],
                    environment_validator: EnvironmentValidator,
                    metasploit: MetasploitExecutor, lab_commands: LabCommandExecutor,
                    now: Callable[[], str], operation_timeout: float,
                    command_timeout: float, session_timeout: float,
                    target_aliases: Mapping[str, str] | None = None,
                    session_settle_seconds: float | None = None) -> tuple[dict[str, Any], str, bool]:
    started = now()
    validation = validate_exploit_config(config)
    committed = validate_committed_environment(config, target_facts, phase=phase.upper())
    runtime = environment_validator(config, target_facts) if committed.valid else committed
    environment = runtime if not runtime.valid else committed
    not_run = CommandEvidence(OperationState.NOT_RUN)
    check = CheckEvidence(CheckVerdict.NOT_RUN, not_run)
    exploit = not_run
    sessions = SessionEvidence(SessionCollectionStatus.UNKNOWN, error="not collected")
    impact = ImpactEvidence(status=ImpactEvidenceStatus.NOT_COLLECTED)
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
        baseline = None
        single = getattr(metasploit, "run_attempt", None)
        if prerequisites_ok and plan.run_exploit and callable(single):
            # Preferred path: one msfconsole invocation captures check,
            # exploit, and the post-exploit session listing before exit, so
            # reverse-shell sessions cannot die between processes.
            combined = single(plan, target_facts=dict(target_facts),
                              run_check=bool(plan.run_check),
                              timeout=operation_timeout,
                              settle_seconds=session_settle_seconds)
            if plan.run_check:
                check = combined.check
            exploit = combined.exploit
            sessions = combined.sessions
            impact = combined.impact
            systemic = exploit.state == OperationState.BACKEND_ERROR
        else:
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
                    sessions = _attribute_sessions(baseline=baseline, post=post,
                        plan=plan, target_facts=target_facts)
                else:
                    sessions = SessionEvidence(SessionCollectionStatus.UNKNOWN,
                        error=(post.error or baseline.error if baseline is not None else post.error))

    protocol = config.invariant.execution_protocol
    oracle = classify_oracle(config_ready=validation.ready, environment=environment,
        run_check=protocol.run_check, run_exploit=protocol.run_exploit,
        prerequisites_ok=prerequisites_ok, check=check, exploit=exploit, sessions=sessions,
        impact=impact)
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
        "impact_evidence": (impact.to_dict()
                            if impact.status == ImpactEvidenceStatus.COLLECTED else None),
        "issues": [issue] if issue else []}
    return attempt, disposition, systemic
