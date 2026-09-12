"""Pure conservative exploit-oracle classification."""

from __future__ import annotations

from .models import (
    CheckEvidence, CheckVerdict, CommandEvidence, EvidenceCompleteness,
    EnvironmentValidation, ImpactEvidence, ImpactEvidenceStatus, MetricEligibility,
    OperationState, OracleResult, OracleVerdict, SessionCollectionStatus,
    SessionEvidence,
)


POSITIVE_CHECKS = {CheckVerdict.VULNERABLE, CheckVerdict.APPEARS, CheckVerdict.DETECTED}


def classify_oracle(*, config_ready: bool, environment: EnvironmentValidation,
                    run_check: bool, run_exploit: bool,
                    prerequisites_ok: bool, check: CheckEvidence,
                    exploit: CommandEvidence, sessions: SessionEvidence,
                    impact: ImpactEvidence | None = None) -> OracleResult:
    impact = impact or ImpactEvidence()
    exploit_executed = exploit.state == OperationState.EXECUTED and exploit.submitted
    invalidating = (not config_ready or not environment.valid or not prerequisites_ok
                    or exploit.state in {OperationState.EXECUTION_ERROR, OperationState.TIMEOUT,
                                         OperationState.BACKEND_ERROR})
    session_known = sessions.status == SessionCollectionStatus.COLLECTED
    positive_check = check.verdict in POSITIVE_CHECKS
    attributable_session = (session_known and bool(sessions.attributable_ids)
                            and sessions.attribution == "TARGET_MATCH")
    deterministic_impact = (impact.status == ImpactEvidenceStatus.COLLECTED
                            and impact.confirmed)
    complete_negative = bool(config_ready and environment.valid and prerequisites_ok
                             and run_exploit and exploit_executed and not invalidating
                             and not positive_check
                             and ((session_known and not sessions.new_ids
                                   and sessions.attribution in {"NO_NEW_SESSION", "UNKNOWN"})
                                  or impact.complete_negative))
    conflict = ((attributable_session or deterministic_impact)
                and check.verdict == CheckVerdict.SAFE)

    binary_observation = attributable_session or deterministic_impact or complete_negative
    eligible = bool(config_ready and environment.valid and run_exploit and exploit_executed
                    and not invalidating and binary_observation)
    exclusion = None
    if not config_ready: exclusion = "CONFIG_NOT_READY"
    elif not environment.valid: exclusion = environment.code or "ENVIRONMENT_ERROR"
    elif not prerequisites_ok: exclusion = "PRECONDITION_FAILED"
    elif not run_exploit: exclusion = "CHECK_ONLY_PROTOCOL"
    elif not exploit_executed: exclusion = "EXPLOIT_NOT_RUN"
    elif invalidating: exclusion = "MSF_BACKEND_ERROR"
    elif not binary_observation:
        if not session_known and impact.status != ImpactEvidenceStatus.COLLECTED:
            exclusion = "IMPACT_EVIDENCE_UNAVAILABLE"
        elif sessions.mismatched_ids:
            exclusion = "SESSION_ATTRIBUTION_MISMATCH"
        elif positive_check:
            exclusion = "IMPACT_EVIDENCE_UNATTRIBUTED"
        else:
            exclusion = "IMPACT_EVIDENCE_INCOMPLETE"
    metric = MetricEligibility(eligible, (
        ("config_complete", config_ready), ("environment_validated", environment.valid),
        ("exploit_required", run_exploit), ("exploit_executed", exploit_executed),
        ("invalidating_error", invalidating),
        ("attributable_session", attributable_session),
        ("deterministic_impact", deterministic_impact),
        ("complete_negative_observation", complete_negative)), exclusion)

    if attributable_session:
        return OracleResult(OracleVerdict.VULNERABLE, "ATTRIBUTABLE_SESSION",
                            EvidenceCompleteness.FULL if not conflict else EvidenceCompleteness.PARTIAL,
                            conflict, metric)
    if deterministic_impact:
        return OracleResult(OracleVerdict.VULNERABLE, impact.basis or "DETERMINISTIC_IMPACT",
                            EvidenceCompleteness.FULL if not conflict else EvidenceCompleteness.PARTIAL,
                            conflict, metric)
    if not config_ready:
        return OracleResult(OracleVerdict.NOT_EVALUATED, "CONFIG_NOT_READY",
                            EvidenceCompleteness.NONE, False, metric)
    if not environment.valid or not prerequisites_ok:
        return OracleResult(OracleVerdict.INCONCLUSIVE, exclusion or "ENVIRONMENT",
                            EvidenceCompleteness.NONE, False, metric)
    if run_check and not run_exploit:
        if positive_check:
            return OracleResult(OracleVerdict.VULNERABLE, "CHECK_ONLY",
                                EvidenceCompleteness.FULL, False, metric)
        if check.verdict == CheckVerdict.SAFE:
            return OracleResult(OracleVerdict.NOT_VULNERABLE, "CHECK_ONLY",
                                EvidenceCompleteness.FULL, False, metric)
        return OracleResult(OracleVerdict.INCONCLUSIVE, "CHECK_ONLY",
                            EvidenceCompleteness.INSUFFICIENT, False, metric)
    if positive_check and exploit_executed:
        return OracleResult(OracleVerdict.INCONCLUSIVE, "CHECK_WITHOUT_ATTRIBUTABLE_IMPACT",
                            EvidenceCompleteness.PARTIAL, False, metric)
    if complete_negative:
        return OracleResult(OracleVerdict.NOT_VULNERABLE, "COMPLETE_NEGATIVE_OBSERVATION",
                            EvidenceCompleteness.FULL, False, metric)
    if exploit_executed:
        basis = "SESSION_ATTRIBUTION_MISMATCH" if sessions.mismatched_ids else "EXPLOIT_EVIDENCE_INCOMPLETE"
        return OracleResult(OracleVerdict.INCONCLUSIVE, basis,
                            EvidenceCompleteness.INSUFFICIENT, False, metric)
    return OracleResult(OracleVerdict.NOT_EVALUATED, "NOT_EXECUTED",
                        EvidenceCompleteness.NONE, False, metric)
