"""Task 7 opt-in LLM golden-path evaluation runner (research only).

This module is NEVER invoked by normal Kalama operation.  Entry points:

* ``python -m kalama.evaluation.llm_eval_runner --plan``
  offline case listing; no network, no provider calls.
* ``python -m kalama.evaluation.llm_eval_runner --live [--model X]``
  calls a reachable local Ollama service, validates every response with
  the production Attack/Patch validators, and stores a bounded
  ``kalama.llm-evaluation/v1`` artifact.  It never submits forms,
  executes exploits/patches, or writes VALIDATED Knowledge.

Without a reachable Ollama service (or without ``--live``) no live
results are produced or faked.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .llm_eval import build_eval_artifact as _build_artifact
from .llm_eval_cases import (
    ALL_CASES,
    FIXTURES_VERSION,
    CaseSpec,
    build_attack_legacy_pack,
    build_patch_envelope_fixture,
    collector_fixture,
)

NORMAL_REPS = 3
ABSTAIN_REPS = 1


def preflight(base_url: str = "http://127.0.0.1:11434",
              timeout: float = 5.0) -> dict[str, Any]:
    """Check Ollama reachability and list models (read-only, no side effects)."""
    import urllib.request
    url = base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read(65536).decode("utf-8", "replace"))
    except Exception as exc:
        return {"available": False, "base_url": base_url,
                "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    models = [m.get("name") for m in payload.get("models", [])
              if isinstance(m, Mapping) and m.get("name")]
    version = payload.get("version")
    return {"available": True, "base_url": base_url, "models": sorted(models),
            "server_version": version}


def plan_cases(cases: Sequence[CaseSpec] | None = None) -> list[dict[str, Any]]:
    """Offline case table (no provider): digests, fields, evidence refs."""
    rows = []
    for spec in cases or ALL_CASES:
        collector = collector_fixture(spec)
        rows.append({"case_id": spec.case_id, "purpose": spec.purpose,
                     "description": spec.description,
                     "candidate_digest": collector.request.context.digest,
                     "evidence_pack_sha256": collector.sha256,
                     "requested_fields": list(spec.requested_fields),
                     "protected_fields": sorted(
                         set(spec.protected_fields) | set(spec.resolved_fields)),
                     "allowed_fields": sorted(collector.request.unresolved_fields),
                     "evidence_items": len(collector.items),
                     "sufficient_evidence": spec.sufficient_evidence,
                     "abstain_expected": spec.abstain_expected,
                     "injection": spec.injection,
                     "binding_test": spec.binding_test,
                     "repetitions": ABSTAIN_REPS if spec.abstain_expected else NORMAL_REPS})
    return rows


def _attack_run(spec: CaseSpec, provider: Any, repetition: int) -> dict[str, Any]:
    from ..guidance.validator import validate_proposal
    collector = collector_fixture(spec)
    legacy = build_attack_legacy_pack(collector)
    protected = set(spec.protected_fields) | set(spec.resolved_fields)
    record: dict[str, Any] = {
        "case_id": spec.case_id, "purpose": "attack", "repetition": repetition,
        "candidate_digest": collector.request.context.digest,
        "requested_fields": list(spec.requested_fields),
        "protected_fields": sorted(protected),
        "allowed_fields": sorted(collector.request.unresolved_fields),
        "evidence_pack_sha256": legacy.sha256,
        "evidence_refs": sorted(legacy.references),
        "expected_values": {k: v for k, v in spec.expected_values.items()},
        "expected_unresolved": list(spec.expected_unresolved),
        "sufficient_evidence": spec.sufficient_evidence,
        "provider_attempted": True,
    }
    if not collector.items:
        record.update({"parse_ok": False, "provider_status": "SKIPPED_NO_EVIDENCE",
                       "validation_state": "INSUFFICIENT_EVIDENCE", "accepted": {},
                       "emitted_fields": [], "issues": ("no useful evidence: provider skipped",),
                       "binding_test": False, "binding_rejected": False})
        return record
    try:
        raw, elapsed = provider.propose(legacy.document, legacy.sha256)
        record["latency_s"] = elapsed
    except Exception as exc:
        record.update({"parse_ok": False, "provider_status": "UNAVAILABLE",
                       "validation_state": "UNAVAILABLE", "accepted": {},
                       "emitted_fields": [],
                       "issues": (f"{type(exc).__name__}: {str(exc)[:300]}",),
                       "binding_test": False, "binding_rejected": False})
        return record
    record["raw_proposal"] = raw
    proposals = raw.get("proposals") if isinstance(raw, Mapping) else None
    record["parse_ok"] = isinstance(raw, Mapping) and isinstance(proposals, Mapping)
    record["provider_status"] = "AVAILABLE"
    record["emitted_fields"] = sorted(proposals) if isinstance(proposals, Mapping) else []
    try:
        state, accepted, issues = validate_proposal(legacy, raw)
    except Exception as exc:
        record.update({"validation_state": "REJECTED", "accepted": {},
                       "issues": (f"validator error: {type(exc).__name__}",),
                       "binding_test": False, "binding_rejected": False})
        return record
    record.update({"validation_state": state.value, "accepted": dict(accepted),
                   "issues": [str(x)[:300] for x in issues]})
    if spec.binding_test:
        mutated = dict(raw) if isinstance(raw, Mapping) else {}
        mutated["candidate_digest"] = "0" * 64
        try:
            b_state, b_accepted, _ = validate_proposal(legacy, mutated)
            rejected = (b_state.value == "REJECTED" and not b_accepted)
        except Exception:
            rejected = True
        record.update({"binding_test": True, "binding_rejected": bool(rejected)})
    else:
        record.update({"binding_test": False, "binding_rejected": False})
    return record


def _patch_run(spec: CaseSpec, provider: Any, repetition: int,
               action_id: str = "patch-001") -> dict[str, Any]:
    from ..guidance.service import GuidanceService
    from ..remediation.models import PatchAction, PlanningStatus
    collector = collector_fixture(spec)
    before = tuple(collector.request.context.installed_versions)
    action = PatchAction(
        action_id, (collector.request.context.vulnerability_id,), (), 
        collector.request.context.component,
        collector.request.context.component, collector.request.context.ecosystem,
        (), before, (), None, None, None,
        PlanningStatus.WAITING_FOR_USER_INPUT, ())
    service = GuidanceService(provider)
    protected = set(spec.protected_fields) | set(spec.resolved_fields)
    record: dict[str, Any] = {
        "case_id": spec.case_id, "purpose": "patch", "repetition": repetition,
        "candidate_digest": collector.request.context.digest,
        "requested_fields": list(spec.requested_fields),
        "protected_fields": sorted(protected),
        "allowed_fields": sorted(collector.request.unresolved_fields),
        "evidence_pack_sha256": collector.sha256,
        "evidence_refs": sorted(
            {*(collector.snapshot_refs or ()),
             *(i.provenance_ref for i in collector.items if i.provenance_ref),
             *(f"field_evidence.{i.source_kind.value}" for i in collector.items)}),
        "expected_values": {k: v for k, v in spec.expected_values.items()},
        "expected_unresolved": list(spec.expected_unresolved),
        "sufficient_evidence": spec.sufficient_evidence,
        "provider_attempted": True,
    }
    if not collector.items:
        record.update({"parse_ok": False, "provider_status": "SKIPPED_NO_EVIDENCE",
                       "validation_state": "INSUFFICIENT_EVIDENCE", "accepted": {},
                       "emitted_fields": [], "issues": ("no useful evidence: provider skipped",),
                       "binding_test": False, "binding_rejected": False})
        return record
    try:
        outcome = service.guide_with_patch_pack(
            collector.request.context.run_id, action,
            {"requested_image_reference": collector.request.context.image_identity},
            field_pack=collector,
            allowed_fields=frozenset(collector.request.unresolved_fields),
            plan_revision=1, base_patch_plan_sha256="c" * 64)
    except Exception as exc:
        record.update({"parse_ok": False, "provider_status": "UNAVAILABLE",
                       "validation_state": "UNAVAILABLE", "accepted": {},
                       "emitted_fields": [],
                       "issues": (f"{type(exc).__name__}: {str(exc)[:300]}",),
                       "binding_test": False, "binding_rejected": False})
        return record
    if outcome is None:
        record.update({"parse_ok": False, "provider_status": "SKIPPED",
                       "validation_state": "REJECTED", "accepted": {},
                       "emitted_fields": [], "issues": ("no outcome",),
                       "binding_test": False, "binding_rejected": False})
        return record
    raw = outcome.raw_proposal
    proposals = raw.get("proposals") if isinstance(raw, Mapping) else None
    record.update({
        "parse_ok": isinstance(raw, Mapping) and isinstance(proposals, Mapping),
        "provider_status": outcome.provider_status,
        "provider": outcome.provider, "model": outcome.model,
        "latency_s": outcome.elapsed_seconds,
        "raw_proposal": raw,
        "emitted_fields": sorted(proposals) if isinstance(proposals, Mapping) else [],
        "validation_state": outcome.validation_state.value,
        "accepted": {k: dict(v) for k, v in (outcome.accepted or {}).items()},
        "issues": [str(x)[:300] for x in (outcome.issues or ())],
        "patch_binding": dict(outcome.envelope.document.get("patch_binding") or {}),
    })
    if spec.binding_test and isinstance(raw, Mapping):
        from ..guidance.patch_proposal import validate_patch_proposal
        mutated = dict(raw)
        mutated["patch_binding"] = {**(raw.get("patch_binding") or {}),
                                    "plan_revision": 2}
        try:
            b_state, b_accepted, _ = validate_patch_proposal(outcome.envelope, mutated)
            rejected = (b_state.value == "REJECTED" and not b_accepted)
        except Exception:
            rejected = True
        record.update({"binding_test": True, "binding_rejected": bool(rejected)})
    else:
        record.update({"binding_test": False, "binding_rejected": False})
    return record


def run_live(*, base_url: str, model: str, timeout: float,
             repetitions: int = NORMAL_REPS,
             cases: Sequence[CaseSpec] | None = None,
             think: bool | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Execute the fixed set against a reachable Ollama service.

    ``think`` maps to the Ollama chat ``think`` option (None = omit,
    preserving default provider behavior; False = non-thinking mode).
    """
    from ..guidance.ollama import OllamaConfig, OllamaProvider
    checked = preflight(base_url, timeout=min(10.0, timeout))
    if not checked.get("available"):
        raise RuntimeError(f"Ollama preflight failed: {checked.get('error')}")
    provider = OllamaProvider(OllamaConfig(base_url=base_url, model=model,
                                           timeout=timeout, think=think))
    records: list[dict[str, Any]] = []
    for spec in cases or ALL_CASES:
        reps = ABSTAIN_REPS if spec.abstain_expected else repetitions
        for rep in range(1, reps + 1):
            if spec.purpose == "attack":
                records.append(_attack_run(spec, provider, rep))
            else:
                records.append(_patch_run(spec, provider, rep))
    return records, checked


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Task 7 opt-in LLM golden-path evaluation (research only)")
    parser.add_argument("--plan", action="store_true",
                        help="list fixed cases offline (default)")
    parser.add_argument("--live", action="store_true",
                        help="call a reachable local Ollama service")
    parser.add_argument("--model", default="llama3.2:3b")
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--reps", type=int, default=NORMAL_REPS)
    parser.add_argument("--no-think", action="store_true",
                        help="set Ollama chat option think=false (default: omit)")
    parser.add_argument("--out", default="output/research/llm-evaluation")
    args = parser.parse_args(argv)
    if not args.live:
        for row in plan_cases():
            print(json.dumps(row, sort_keys=True))
        return 0
    try:
        records, checked = run_live(
            base_url=args.base_url, model=args.model,
            timeout=args.timeout, repetitions=args.reps,
            think=False if args.no_think else None)
    except RuntimeError as exc:
        print(f"LIVE_OLLAMA_STATUS: BLOCKED: {exc}", file=sys.stderr)
        return 2
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = "".join(c if c.isalnum() else "-" for c in args.model).strip("-")
    if args.no_think:
        slug += "-nothink"
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    provider_config: dict[str, Any] = {"provider": "ollama", "model": args.model,
                     "base_url": args.base_url, "timeout": args.timeout,
                     "temperature": 0, "num_predict": 512}
    if args.no_think:
        provider_config["think"] = False
    artifact = _build_artifact(
        model=args.model,
        provider_config=provider_config,
        fixtures_version=FIXTURES_VERSION, records=records,
        live=True, preflight=checked)
    path = out_dir / f"llm_eval_{slug}_{stamp}.json"
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    print(json.dumps(artifact["metrics"], indent=2, sort_keys=True))
    print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
