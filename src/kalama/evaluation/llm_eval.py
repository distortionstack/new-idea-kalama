"""Task 7 deterministic LLM golden-path evaluation metrics and artifacts.

This module computes metrics over recorded per-case/per-repetition run
records and builds the versioned ``kalama.llm-evaluation/v1`` research
artifact.  It performs no network, Docker, Ollama, or exploit/patch
activity: live runs are assembled by the opt-in runner
(``llm_eval_runner``) and only *recorded* here.  Raw provider responses
are bounded before persistence and provider secrets are never stored.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


LLM_EVAL_SCHEMA = "kalama.llm-evaluation/v1"

# Bounds keep the research artifact small and secret-free.
MAX_RAW_PROPOSAL_CHARS = 4000
MAX_RUNS_PER_ARTIFACT = 500
MAX_REASON_CHARS = 1000

ACCEPTED_STATES = frozenset({"ACCEPTED_AS_SUGGESTION", "PARTIALLY_ACCEPTED"})
ABSTAIN_STATES = frozenset({"INSUFFICIENT_EVIDENCE"})


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    if denominator <= 0:
        return {"rate": None, "numerator": 0, "denominator": 0,
                "note": "unavailable: zero denominator"}
    return {"rate": numerator / denominator, "numerator": numerator,
            "denominator": denominator}


def _as_set(value: Any) -> set[str]:
    if isinstance(value, (set, frozenset, list, tuple)):
        return {str(x) for x in value}
    return set()


def _acceptable(value: Any, expected: Any) -> bool:
    """True when a suggested value matches ground truth exactly or by set."""
    if isinstance(expected, (list, tuple, set, frozenset)):
        return value in set(expected)
    if isinstance(expected, Mapping):
        if "any_of" in expected or "value" in expected:
            options = expected.get("any_of", expected.get("value"))
            if isinstance(options, (list, tuple, set, frozenset)):
                return value in set(options)
            return value == options
        return value == expected
    return value == expected


def compute_llm_eval_metrics(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate Task 7 metrics over recorded evaluation runs.

    Every metric reports ``{rate, numerator, denominator}`` with explicit
    zero-denominator handling (``rate`` is ``None`` when undefined).
    """
    records = [r for r in records if isinstance(r, Mapping)]
    attempted = [r for r in records if r.get("provider_attempted") is True]
    parsed = [r for r in attempted if r.get("parse_ok") is True]
    accepted_runs = [r for r in parsed
                     if str(r.get("validation_state")) in ACCEPTED_STATES]

    metrics: dict[str, Any] = {
        "runs": len(records),
        "provider_attempts": len(attempted),
        "valid_structured": _rate(
            sum(1 for _ in parsed), len(attempted)),
        "validator_acceptance": _rate(
            len(accepted_runs), len(attempted)),
    }

    # Field accuracy: correct accepted suggestions with known ground truth.
    acc_known = acc_correct = 0
    for run in accepted_runs:
        accepted = run.get("accepted") or {}
        expected = run.get("expected_values") or {}
        if not isinstance(accepted, Mapping) or not isinstance(expected, Mapping):
            continue
        for field, suggestion in accepted.items():
            if field not in expected:
                continue
            acc_known += 1
            value = suggestion.get("value") if isinstance(suggestion, Mapping) else suggestion
            if _acceptable(value, expected[field]):
                acc_correct += 1
    metrics["field_accuracy"] = _rate(acc_correct, acc_known)

    # Field coverage: expected unresolved fields with sufficient evidence
    # that were correctly suggested.
    cov_expected = cov_hit = 0
    for run in records:
        if run.get("sufficient_evidence") is not True:
            continue
        expected_fields = _as_set(run.get("expected_unresolved"))
        if not expected_fields:
            continue
        accepted = run.get("accepted") or {}
        expected = run.get("expected_values") or {}
        for field in expected_fields:
            cov_expected += 1
            suggestion = accepted.get(field) if isinstance(accepted, Mapping) else None
            value = suggestion.get("value") if isinstance(suggestion, Mapping) else None
            if suggestion is not None and field in expected and _acceptable(value, expected[field]):
                cov_hit += 1
    metrics["field_coverage"] = _rate(cov_hit, cov_expected)

    # Evidence attribution: accepted evidence-requiring suggestions whose
    # refs sit inside the exact pack reference set.
    attr_known = attr_good = 0
    for run in accepted_runs:
        accepted = run.get("accepted") or {}
        pack_refs = _as_set(run.get("evidence_refs"))
        no_ref_needed = _as_set(run.get("refs_optional_fields") or {"notes"})
        if not isinstance(accepted, Mapping):
            continue
        for field, suggestion in accepted.items():
            refs = suggestion.get("evidence_refs") if isinstance(suggestion, Mapping) else None
            if field in no_ref_needed and not refs:
                continue
            attr_known += 1
            if isinstance(refs, list) and refs and all(str(x) in pack_refs for x in refs):
                attr_good += 1
    metrics["evidence_attribution"] = _rate(attr_good, attr_known)

    # Unsupported suggestion rate: emitted fields never accepted.
    emitted_total = unsupported_total = 0
    for run in parsed:
        emitted = _as_set(run.get("emitted_fields"))
        accepted = run.get("accepted") or {}
        accepted_keys = set(accepted) if isinstance(accepted, Mapping) else set()
        for field in emitted:
            emitted_total += 1
            if field not in accepted_keys:
                unsupported_total += 1
    metrics["unsupported_suggestion_rate"] = _rate(unsupported_total, emitted_total)

    # Overwrite attempt rate: emitted fields that were protected.
    overwrite_total = 0
    for run in parsed:
        emitted = _as_set(run.get("emitted_fields"))
        protected = _as_set(run.get("protected_fields"))
        overwrite_total += len(emitted & protected)
    metrics["overwrite_attempt_rate"] = _rate(overwrite_total, len(parsed))

    # Abstention correctness over insufficient-evidence cases.
    abstain_cases = [r for r in records if r.get("sufficient_evidence") is False]
    abstain_ok = sum(1 for r in abstain_cases
                     if str(r.get("validation_state")) in ABSTAIN_STATES
                     or not (r.get("accepted") or {}))
    metrics["abstention_correctness"] = _rate(abstain_ok, len(abstain_cases))

    # Binding safety over mismatch cases.
    binding_cases = [r for r in records if r.get("binding_test") is True]
    binding_ok = sum(1 for r in binding_cases if r.get("binding_rejected") is True)
    metrics["binding_safety"] = _rate(binding_ok, len(binding_cases))
    return metrics


def scrub_provider_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep only non-secret provider descriptors (model, endpoint, limits)."""
    config = dict(config or {})
    scrubbed: dict[str, Any] = {"provider": str(config.get("provider") or "ollama"),
            "model": str(config.get("model") or "unknown"),
            "base_url": str(config.get("base_url") or ""),
            "timeout": config.get("timeout"),
            "temperature": config.get("temperature", 0),
            "num_predict": config.get("num_predict", 512)}
    if config.get("think") is not None:
        scrubbed["think"] = bool(config.get("think"))
    return scrubbed


def bound_raw_proposal(raw: Any) -> Any:
    """Truncate raw provider output for bounded artifacts (no CoT stored)."""
    if isinstance(raw, Mapping):
        proposal = {k: raw.get(k) for k in (
            "schema", "status", "run_id", "cve_id", "action_id",
            "candidate_digest", "field_evidence_sha256", "evidence_pack_sha256",
            "patch_binding", "proposals", "missing_evidence",
            "guidance_notes", "reasoning_summary") if k in raw}
        text = str(proposal)
        if len(text) > MAX_RAW_PROPOSAL_CHARS:
            return {"truncated": True,
                    "chars": len(text),
                    "preview": text[:MAX_RAW_PROPOSAL_CHARS]}
        return proposal
    text = str(raw)
    if len(text) > MAX_RAW_PROPOSAL_CHARS:
        return {"truncated": True, "chars": len(text),
                "preview": text[:MAX_RAW_PROPOSAL_CHARS]}
    return {"unparseable_preview": text[:MAX_RAW_PROPOSAL_CHARS]}


def validate_run_record(record: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Schema-check one evaluation run record (deterministic, no I/O)."""
    required = ("case_id", "purpose", "repetition", "candidate_digest",
                "requested_fields", "evidence_pack_sha256", "provider_attempted")
    issues = [f"missing:{k}" for k in required if k not in record]
    if record.get("purpose") not in {"attack", "patch"}:
        issues.append("bad:purpose")
    if not isinstance(record.get("repetition"), int):
        issues.append("bad:repetition")
    return (not issues), tuple(issues)


def build_eval_artifact(*, model: str, provider_config: Mapping[str, Any] | None,
                        fixtures_version: str,
                        records: Sequence[Mapping[str, Any]],
                        created_at: str | None = None,
                        live: bool = False,
                        preflight: Mapping[str, Any] | None = None,
                        ) -> dict[str, Any]:
    """Assemble the versioned evaluation artifact (bounded, secret-free)."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    for record in records or ():
        if len(kept) >= MAX_RUNS_PER_ARTIFACT:
            dropped += 1
            continue
        entry = dict(record)
        if "raw_proposal" in entry:
            entry["raw_proposal"] = bound_raw_proposal(entry.get("raw_proposal"))
        kept.append(entry)
    return {"schema": LLM_EVAL_SCHEMA,
            "created_at": created_at or datetime.now(timezone.utc).isoformat(),
            "live": bool(live),
            "model": model,
            "provider": scrub_provider_config(provider_config),
            "fixtures_version": fixtures_version,
            "preflight": dict(preflight or {}),
            "metrics": compute_llm_eval_metrics(kept),
            "runs": kept,
            "dropped_runs": dropped}


def validate_eval_artifact(artifact: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Validate artifact shape and bounds (deterministic, no I/O)."""
    issues: list[str] = []
    if artifact.get("schema") != LLM_EVAL_SCHEMA:
        issues.append("bad:schema")
    if not isinstance(artifact.get("runs"), list):
        issues.append("bad:runs")
    elif len(artifact["runs"]) > MAX_RUNS_PER_ARTIFACT:
        issues.append("bad:runs-bound")
    provider = artifact.get("provider") or {}
    for secret in ("api_key", "apikey", "token", "secret", "password"):
        if secret in provider:
            issues.append(f"secret:{secret}")
        for run in artifact.get("runs") or ():
            if isinstance(run, Mapping) and secret in run:
                issues.append(f"secret:{secret}")
                break
    metrics = artifact.get("metrics") or {}
    for name in ("valid_structured", "validator_acceptance", "field_accuracy",
                 "field_coverage", "evidence_attribution",
                 "unsupported_suggestion_rate", "overwrite_attempt_rate",
                 "abstention_correctness", "binding_safety"):
        metric = metrics.get(name)
        if not isinstance(metric, Mapping) or "rate" not in metric:
            issues.append(f"bad:metric:{name}")
    return (not issues), tuple(issues)
