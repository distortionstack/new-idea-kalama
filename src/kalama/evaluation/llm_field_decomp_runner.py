"""Task 7.4 runner: offline plan + opt-in live field diagnostics.

RESEARCH ONLY.  Never invoked by production code.

* ``--plan``: offline field/prompt table from Task 7 fixtures (no network).
* ``--live``: qwen3:8b, think=false, 45 s, tiny {value, evidence_refs} calls.
* ``--live --control-3b``: repeat same prompts once with llama3.2:3b
  (only meaningful after unblocked 8b run; still research-only).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .llm_eval_runner import preflight
from .llm_field_decomp import (
    BASE_URL,
    FIELD_DECOMP_SCHEMA,
    FIXTURES_VERSION,
    MAX_RAW_CHARS,
    MODEL_CONTROL,
    MODEL_PRIMARY,
    NUM_PREDICT_FIELD,
    TIMEOUT_S,
    attach_response,
    binding_store,
    build_field_prompt,
    build_field_specs,
    check_cross_field,
    diagnostic_request_id,
    has_forbidden_expansion,
    ollama_field_call,
    parse_field_response,
    refs_supported,
    values_equal,
)


def plan_rows() -> list[dict[str, Any]]:
    rows = []
    specs = build_field_specs()
    store = binding_store(specs)
    for s in specs:
        prompt = build_field_prompt(s)
        rid = diagnostic_request_id(s.candidate_digest, s.field, s.field_evidence_sha256)
        rows.append({
            "case_id": s.case_id, "purpose": s.purpose, "field": s.field,
            "request_id": rid,
            "candidate_digest": s.candidate_digest,
            "field_evidence_sha256": s.field_evidence_sha256,
            "allowed_evidence_ids": list(s.allowed_evidence_ids),
            "evidence_blocks": len(s.evidence_blocks),
            "prompt_chars": len(prompt),
            "expected_value": s.expected_value,
            "candidate_summary": dict(s.candidate_summary),
            "evidence": [dict(b) for b in s.evidence_blocks],
        })
    return rows


def _run_one_model(*, model: str, specs: Any, store: Any,
                   stop_after_first_block: bool = True) -> tuple[list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    first_blocked = False
    for idx, spec in enumerate(specs):
        prompt = build_field_prompt(spec)
        rid = diagnostic_request_id(spec.candidate_digest, spec.field,
                                    spec.field_evidence_sha256)
        rec: dict[str, Any] = {
            "case_id": spec.case_id, "purpose": spec.purpose, "field": spec.field,
            "request_id": rid,
            "model": model, "think": False, "temperature": 0,
            "timeout_s": TIMEOUT_S, "num_predict": NUM_PREDICT_FIELD,
            "candidate_digest": spec.candidate_digest,
            "field_evidence_sha256": spec.field_evidence_sha256,
            "supplied_evidence_ids": list(spec.allowed_evidence_ids),
            "prompt_chars": len(prompt),
            "expected_value": spec.expected_value,
        }
        try:
            out = ollama_field_call(model=model, prompt=prompt, timeout=TIMEOUT_S,
                                    num_predict=NUM_PREDICT_FIELD)
        except TimeoutError:
            rec.update({
                "completed_in_budget": False, "timeout": True,
                "latency_s": TIMEOUT_S, "eval_count": None,
                "prompt_eval_count": None, "tokens_per_sec": None,
                "raw_preview": "TimeoutError: timed out",
                "structured_ok": False, "value_correct": False,
                "attribution_ok": False, "forbidden_expansion": False,
                "failure_class": "TIMEOUT",
            })
            records.append(rec)
            if idx == 0:
                first_blocked = True
                if stop_after_first_block:
                    break
            continue
        except Exception as exc:
            rec.update({
                "completed_in_budget": False, "timeout": False,
                "latency_s": round(float(out.get("wall_s", 0)) if isinstance(out, dict) else 0, 3),
                "raw_preview": "%s: %s" % (type(exc).__name__, str(exc)[:300]),
                "structured_ok": False, "value_correct": False,
                "attribution_ok": False, "forbidden_expansion": False,
                "failure_class": "TRANSPORT_%s" % type(exc).__name__,
            })
            records.append(rec)
            continue
        content = out.get("content", "")
        parsed, ok, issues = parse_field_response(content)
        hit_cap = (isinstance(out.get("eval_count"), int)
                   and out["eval_count"] >= NUM_PREDICT_FIELD)
        value_ok = bool(ok and parsed is not None
                        and values_equal(parsed.get("value"), spec.expected_value))
        # Attribution: refs subset of allowed AND non-empty unless value is null.
        if ok and parsed is not None:
            refs = parsed.get("evidence_refs") or []
            if parsed.get("value") is None:
                attr_ok = (refs == [] and refs_supported(refs, spec.allowed_evidence_ids))
            else:
                attr_ok = (len(refs) > 0 and refs_supported(refs, spec.allowed_evidence_ids))
        else:
            attr_ok = False
        forbidden = has_forbidden_expansion(content)
        if not ok:
            failure = "HIT_TOKEN_CAP" if hit_cap else "UNPARSEABLE"
        elif hit_cap:
            failure = "HIT_TOKEN_CAP"
        elif not value_ok or not attr_ok:
            failure = "SEMANTIC_MISMATCH"
        else:
            failure = "NONE"
        rec.update({
            "completed_in_budget": True, "timeout": False,
            "latency_s": round(float(out.get("wall_s", 0)), 3),
            "eval_count": out.get("eval_count"),
            "prompt_eval_count": out.get("prompt_eval_count"),
            "tokens_per_sec": (round(float(out["tokens_per_sec"]), 2)
                               if isinstance(out.get("tokens_per_sec"), (int, float)) else None),
            "done_reason": out.get("done_reason"),
            "hit_token_cap": bool(hit_cap),
            "raw_preview": content[:MAX_RAW_CHARS],
            "parsed_value": (parsed.get("value") if parsed else None),
            "parsed_refs": (parsed.get("evidence_refs") if parsed else None),
            "structured_ok": bool(ok),
            "parse_issues": list(issues),
            "value_correct": bool(value_ok),
            "attribution_ok": bool(attr_ok),
            "forbidden_expansion": bool(forbidden),
            "failure_class": failure,
            "binding_envelope": None,
        })
        if ok and parsed is not None:
            env, msg = attach_response(store, rid, parsed)
            rec["binding_envelope"] = env
            rec["binding_msg"] = msg
        records.append(rec)
        if idx == 0 and (rec.get("timeout") or hit_cap):
            first_blocked = True
            if stop_after_first_block:
                break
        # Primary stop rule: single narrow field already blocked -> at most
        # one additional confirmation field.
        if first_blocked and len(records) >= 2 and stop_after_first_block:
            break
    status = "FIELD_LEVEL_RUNTIME_BLOCKED" if first_blocked else "FIELD_LEVEL_OK"
    return records, status


def run_harness_safety(specs: Any, store: Any) -> dict[str, Any]:
    """Offline binding-harness negatives (no model). Never touches production."""
    rids = list(store.keys())
    first = rids[0]
    entry = store[first]
    good = {"value": "probe", "evidence_refs": [entry["allowed_evidence_ids"][0]]} \
        if entry["allowed_evidence_ids"] else {"value": None, "evidence_refs": []}
    env, _ = attach_response(store, first, good)
    ok_attach = env is not None and env["candidate_digest"] == entry["candidate_digest"]
    wrong, msg_wrong = attach_response(store, "R-unknown", good)
    bad_ref = {"value": "probe", "evidence_refs": ["evidence:does-not-exist"]}
    bad, msg_bad = attach_response(store, first, bad_ref)
    cross_ok, msg_cross = check_cross_field(store, first, good, claimed_field="__other_field__")
    return {
        "valid_attach_accepted": bool(ok_attach),
        "wrong_request_rejected": wrong is None,
        "wrong_request_msg": msg_wrong,
        "unknown_ref_rejected": bad is None,
        "unknown_ref_msg": msg_bad,
        "cross_field_rejected": (not cross_ok),
        "cross_field_msg": msg_cross,
    }


def main(argv: Any = None) -> int:
    ap = argparse.ArgumentParser(description="Task 7.4 field decomposition (research only)")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--control-3b", action="store_true")
    ap.add_argument("--model", default=MODEL_PRIMARY)
    ap.add_argument("--base-url", default=BASE_URL)
    ap.add_argument("--out", default="output/research/llm-evaluation")
    args = ap.parse_args(argv)
    if not args.live:
        for row in plan_rows():
            print(json.dumps(row, sort_keys=True))
        return 0
    checked = preflight(args.base_url, timeout=min(10.0, TIMEOUT_S))
    if not checked.get("available"):
        print("LIVE_OLLAMA_STATUS: BLOCKED: %s" % checked.get("error"), file=sys.stderr)
        return 2
    specs = build_field_specs()
    store = binding_store(specs)
    records, status = _run_one_model(model=args.model, specs=specs, store=store)
    control_records: list[dict[str, Any]] = []
    if args.control_3b and status == "FIELD_LEVEL_OK":
        control_records, _ = _run_one_model(model=MODEL_CONTROL, specs=specs,
                                            store=store)
    harness = run_harness_safety(specs, store)
    artifact = {
        "schema": FIELD_DECOMP_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "live": True,
        "model": args.model,
        "think": False,
        "temperature": 0,
        "timeout_s": TIMEOUT_S,
        "num_predict": NUM_PREDICT_FIELD,
        "fixtures_version": FIXTURES_VERSION,
        "preflight": dict(checked),
        "field_status": status,
        "runs": records,
        "control_3b_runs": control_records,
        "harness_binding_safety": harness,
        "dropped_runs": 0,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = "".join(c if c.isalnum() else "-" for c in args.model).strip("-")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / ("llm_field_decomp_%s_%s.json" % (slug, stamp))
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"field_status": status,
                      "runs": len(records),
                      "harness": harness}, indent=2, sort_keys=True))
    print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
