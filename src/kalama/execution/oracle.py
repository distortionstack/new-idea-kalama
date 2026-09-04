"""Pure conservative exploit-oracle classification."""

from __future__ import annotations

from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, EvidenceCompleteness,
    EnvironmentValidation, MetricEligibility, OperationState, OracleResult,
    OracleVerdict, SessionCollectionStatus, SessionEvidence,
)


POSITIVE_CHECKS = {CheckVerdict.VULNERABLE, CheckVerdict.APPEARS, CheckVerdict.DETECTED}


def classify_oracle(*, config_ready: bool, environment: EnvironmentValidation,
                    run_check: bool, run_exploit: bool,
                    prerequisites_ok: bool, check: CheckEvidence,
                    exploit: CommandEvidence, sessions: SessionEvidence) -> OracleResult:
    exploit_executed = exploit.state == OperationState.EXECUTED and exploit.submitted
    invalidating = (not config_ready or not environment.valid or not prerequisites_ok
                    or exploit.state in {OperationState.EXECUTION_ERROR, OperationState.TIMEOUT,
                                         OperationState.BACKEND_ERROR})
    session_known = sessions.status == SessionCollectionStatus.COLLECTED
    positive_check = check.verdict in POSITIVE_CHECKS
    positive_session = session_known and bool(sessions.new_ids)
    conflict = positive_session and check.verdict == CheckVerdict.SAFE
    eligible = bool(config_ready and environment.valid and run_exploit and exploit_executed
                    and not invalidating and session_known)
    exclusion = None
    if not config_ready: exclusion = "CONFIG_NOT_READY"
    elif not environment.valid: exclusion = environment.code or "ENVIRONMENT_ERROR"
    elif not prerequisites_ok: exclusion = "PRECONDITION_FAILED"
    elif not run_exploit: exclusion = "CHECK_ONLY_PROTOCOL"
    elif not exploit_executed: exclusion = "EXPLOIT_NOT_RUN"
    elif invalidating: exclusion = "MSF_BACKEND_ERROR"
    elif not session_known: exclusion = "SESSION_EVIDENCE_UNAVAILABLE"
    metric = MetricEligibility(eligible, (
        ("config_complete", config_ready), ("environment_validated", environment.valid),
        ("exploit_required", run_exploit), ("exploit_executed", exploit_executed),
        ("invalidating_error", invalidating)), exclusion)

    if positive_session:
        return OracleResult(OracleVerdict.VULNERABLE, "NEW_SESSION",
                            EvidenceCompleteness.FULL if not conflict else EvidenceCompleteness.PARTIAL,
                            conflict, metric)
    if positive_check:
        complete = (EvidenceCompleteness.FULL if run_check and not run_exploit
                    else EvidenceCompleteness.PARTIAL)
        return OracleResult(OracleVerdict.VULNERABLE, "CHECK_ONLY" if not run_exploit else "CHECK",
                            complete, False, metric)
    if not config_ready:
        return OracleResult(OracleVerdict.NOT_EVALUATED, "CONFIG_NOT_READY",
                            EvidenceCompleteness.NONE, False, metric)
    if not environment.valid or not prerequisites_ok:
        return OracleResult(OracleVerdict.INCONCLUSIVE, exclusion or "ENVIRONMENT",
                            EvidenceCompleteness.NONE, False, metric)
    if run_check and not run_exploit:
        if check.verdict == CheckVerdict.SAFE:
            return OracleResult(OracleVerdict.NOT_VULNERABLE, "CHECK_ONLY",
                                EvidenceCompleteness.FULL, False, metric)
        return OracleResult(OracleVerdict.INCONCLUSIVE, "CHECK_ONLY",
                            EvidenceCompleteness.INSUFFICIENT, False, metric)
    if eligible and not sessions.new_ids:
        return OracleResult(OracleVerdict.NOT_VULNERABLE, "EXPLOIT_NO_NEW_SESSION",
                            EvidenceCompleteness.FULL, False, metric)
    if exploit_executed:
        return OracleResult(OracleVerdict.INCONCLUSIVE, "EXPLOIT_EVIDENCE_INCOMPLETE",
                            EvidenceCompleteness.INSUFFICIENT, False, metric)
    return OracleResult(OracleVerdict.NOT_EVALUATED, "NOT_EXECUTED",
                        EvidenceCompleteness.NONE, False, metric)
