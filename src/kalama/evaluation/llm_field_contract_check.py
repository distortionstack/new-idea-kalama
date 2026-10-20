"""Task 7.5 typed-target + abstention validation (RESEARCH ONLY).

Never imported by production code. Uses the SAME Case B ``target``
evidence/IDs/digests as Task 7.4 (via ``llm_field_decomp`` specs) and the
SAME Case C empty-evidence condition for abstention. The only deliberate
change for ``target`` is an explicitly typed contract: prose shape
requirement PLUS a provider-enforced JSON Schema (Ollama ``format``).

Live model: qwen3:8b, think=false, temperature 0, 45 s timeout.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .llm_eval_runner import preflight
from .llm_field_decomp import (
    BASE_URL,
    FIXTURES_VERSION,
    MAX_RAW_CHARS,
    MODEL_PRIMARY,
    TIMEOUT_S,
    TEMPERATURE,
    NUM_PREDICT_FIELD,
    attach_response,
    binding_store,
    has_forbidden_expansion,
    refs_supported,
    values_equal,
)

CONTRACT_CHECK_SCHEMA = "kalama.llm-field-contract-validation/v1"

TARGET_TYPED_FORMAT: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["value", "evidence_refs"],
    "properties": {
        "value": {
            "anyOf": [
                {"type": "object", "additionalProperties": False,
                 "required": ["index"],
                 "properties": {"index": {"type": "integer"},
                                "name": {"type": "string"}}},
                {"type": "null"},
            ]
        },
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
    },
}

ABSTAIN_FORMAT: Mapping[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["value", "evidence_refs"],
    "properties": {
        "value": {"type": "null"},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
    },
}


def build_typed_target_prompt() -> tuple[str, Any]:
    """Same B-target evidence as 7.4; only the output contract is typed."""
    from .llm_field_decomp import build_field_specs
    spec = next(s for s in build_field_specs()
                if s.case_id == "B" and s.field == "target")
    lines = [
        "You are assisting Kalama with one unresolved field.",
        "",
        "Field:",
        "target",
        "",
        "Candidate:",
        "cve_id: %s" % spec.candidate_summary.get("cve_id"),
        "component: %s" % spec.candidate_summary.get("component"),
        "installed_version: %s" % (spec.candidate_summary.get("installed_version"),),
    ]
    lines += ["",
              "Authority constraint:",
              "Select only a target listed in the supplied metasploit evidence facts.",
              "Do not invent modules, targets, payloads, ports, or paths.",
              "Do not echo candidate facts as the value.",
              "",
              "Evidence:"]
    for b in spec.evidence_blocks:
        facts = json.dumps(b["facts"], sort_keys=True, ensure_ascii=False)
        text = (" text=%r" % b["text"]) if b.get("text") else ""
        lines.append("[%s] kind=%s authority=%s facts=%s%s" % (
            b["id"], b["kind"], b["authority"], facts, text))
    lines += [
        "",
        "Rules:",
        "- Use only the supplied evidence.",
        "- Do not invent values or evidence references.",
        "- If evidence is insufficient, return null.",
        "- Return JSON only.",
        "",
        "Output contract (exact):",
        '{"value": {"index": <integer, REQUIRED>, "name": <string, optional>},',
        ' "evidence_refs": [...]}',
        'OR {"value": null, "evidence_refs": []} if evidence is insufficient.',
        'The value MUST be an object with a required integer "index" key and',
        'an optional string "name" key. A bare string is never valid.',
    ]
    return "\n".join(lines), spec


def build_abstention_prompt() -> tuple[str, Any]:
    """Case C target: genuinely zero evidence items (fixture-native)."""
    from .llm_eval_cases import ALL_CASES, collector_fixture
    spec = next(c for c in ALL_CASES if c.case_id == "C")
    collector = collector_fixture(spec)
    assert tuple(collector.items) == ()
    lines = [
        "You are assisting Kalama with one unresolved field.",
        "",
        "Field:",
        "target",
        "",
        "Candidate:",
        "cve_id: %s" % collector.request.context.vulnerability_id,
        "component: %s" % collector.request.context.component,
        "installed_version: %s" % (list(collector.request.context.installed_versions),),
        "",
        "Evidence:",
        "(no evidence - the EvidencePack contains zero items)",
        "",
        "Rules:",
        "- Use only the supplied evidence.",
        "- There is no evidence, so you must abstain.",
        "- Return JSON only.",
        "",
        "Output contract (exact):",
        '{"value": null, "evidence_refs": []}',
    ]
    return "\n".join(lines), spec


def parse_typed_target(text: str) -> tuple[Any, bool, tuple[str, ...]]:
    """Validate the typed target shape. Returns (parsed, ok, issues)."""
    try:
        obj = json.loads(text)
    except Exception as exc:
        return None, False, ("json_parse_error: %s" % type(exc).__name__,)
    if not isinstance(obj, dict) or set(obj) != {"value", "evidence_refs"}:
        return None, False, ("keys_must_be_exactly_value_and_evidence_refs",)
    refs = obj.get("evidence_refs")
    if not isinstance(refs, list) or any(not isinstance(r, str) for r in refs):
        return None, False, ("evidence_refs_must_be_string_list",)
    value = obj.get("value")
    if value is None:
        if refs != []:
            return None, False, ("null_value_must_carry_empty_refs",)
        return {"value": None, "evidence_refs": []}, True, ()
    if not isinstance(value, dict) or set(value) - {"index", "name"}:
        return None, False, ("target_must_be_object_with_index_and_optional_name",)
    index = value.get("index")
    if not isinstance(index, int) or isinstance(index, bool):
        return None, False, ("target_index_must_be_integer",)
    if "name" in value and not isinstance(value["name"], str):
        return None, False, ("target_name_must_be_string",)
    return {"value": {"index": index, **({"name": value["name"]} if "name" in value else {})},
            "evidence_refs": list(refs)}, True, ()


def production_conformance(value: Any, refs: Any) -> dict[str, Any]:
    """Feed the typed value through the UNMODIFIED production validator.

    Assembles the existing proposal representation around the field result
    (Kalama-owned identity fields) and calls ``validate_proposal``.
    """
    from .llm_eval_cases import ALL_CASES, collector_fixture, build_attack_legacy_pack
    from ..guidance.models import PROPOSAL_SCHEMA
    from ..guidance.validator import validate_proposal
    spec = next(c for c in ALL_CASES if c.case_id == "B")
    pack = build_attack_legacy_pack(collector_fixture(spec))
    raw = {
        "schema": PROPOSAL_SCHEMA,
        "status": "PROPOSED",
        "run_id": pack.run_id,
        "cve_id": pack.cve_id,
        "evidence_pack_sha256": pack.sha256,
        "candidate_digest": pack.document.get("candidate_digest"),
        "field_evidence_sha256": pack.document.get("field_evidence_sha256"),
        "proposals": {"target": {"value": value, "evidence_refs": list(refs),
                                 "reason": ""}},
        "missing_evidence": [],
        "guidance_notes": [],
        "reasoning_summary": "",
    }
    state, accepted, issues = validate_proposal(pack, raw)
    return {"validation_state": state.value, "accepted": accepted,
            "issues": list(issues)}


def ollama_typed_call(*, prompt: str, format_schema: Mapping[str, Any],
                      model: str = MODEL_PRIMARY,
                      timeout: float = TIMEOUT_S,
                      num_predict: int = NUM_PREDICT_FIELD,
                      base_url: str = BASE_URL) -> dict[str, Any]:
    body = {
        "model": model, "stream": False, "think": False,
        "options": {"temperature": TEMPERATURE, "num_predict": num_predict},
        "format": dict(format_schema),
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(base_url.rstrip("/") + "/api/chat",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            outer = json.loads(resp.read(4 * 1024 * 1024).decode("utf-8", "replace"))
    except TimeoutError as exc:
        raise TimeoutError("timed out") from exc
    except Exception as exc:
        name = type(exc).__name__.lower()
        if "timed out" in str(exc).lower() or "timeout" in name:
            raise TimeoutError("timed out") from exc
        raise
    wall = time.monotonic() - started
    content = (outer.get("message") or {}).get("content", "")
    eval_count, eval_ns = outer.get("eval_count"), outer.get("eval_duration")
    tok_s = (eval_count / (eval_ns / 1e9) if isinstance(eval_count, int)
             and isinstance(eval_ns, int) and eval_ns > 0 else None)
    return {"content": content if isinstance(content, str) else "",
            "eval_count": eval_count,
            "prompt_eval_count": outer.get("prompt_eval_count"),
            "tokens_per_sec": tok_s, "wall_s": wall,
            "done_reason": outer.get("done_reason")}


def run_target_reps(n: int = 3) -> list[dict[str, Any]]:
    prompt, spec = build_typed_target_prompt()
    records = []
    for rep in range(1, n + 1):
        rec: dict[str, Any] = {
            "check": "typed_target", "repetition": rep,
            "model": MODEL_PRIMARY, "think": False, "temperature": 0,
            "timeout_s": TIMEOUT_S, "num_predict": NUM_PREDICT_FIELD,
            "case_id": "B", "field": "target",
            "supplied_evidence_ids": list(spec.allowed_evidence_ids),
            "prompt_chars": len(prompt),
            "expected_value": spec.expected_value,
            "format": "typed-object-or-null",
            "prompt_frozen_across_reps": True,
        }
        try:
            out = ollama_typed_call(prompt=prompt, format_schema=TARGET_TYPED_FORMAT)
        except TimeoutError:
            rec.update({"completed_in_budget": False, "timeout": True,
                        "latency_s": TIMEOUT_S, "failure_class": "TIMEOUT",
                        "structured_ok": False, "value_correct": False,
                        "attribution_ok": False, "forbidden_expansion": False})
            records.append(rec)
            continue
        content = out["content"]
        parsed, ok, issues = parse_typed_target(content)
        value_ok = bool(ok and values_equal(parsed["value"], spec.expected_value))
        attr_ok = bool(ok and parsed["value"] is not None and len(parsed["evidence_refs"]) > 0
                       and refs_supported(parsed["evidence_refs"], spec.allowed_evidence_ids)) \
            or bool(ok and parsed["value"] is None and parsed["evidence_refs"] == [])
        conformance = None
        if ok:
            try:
                conformance = production_conformance(parsed["value"], parsed["evidence_refs"])
            except Exception as exc:  # noqa: BLE001
                conformance = {"error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
        rec.update({
            "completed_in_budget": True, "timeout": False,
            "latency_s": round(float(out["wall_s"]), 3),
            "eval_count": out.get("eval_count"),
            "prompt_eval_count": out.get("prompt_eval_count"),
            "tokens_per_sec": (round(float(out["tokens_per_sec"]), 2)
                               if isinstance(out.get("tokens_per_sec"), (int, float)) else None),
            "done_reason": out.get("done_reason"),
            "raw_preview": content[:MAX_RAW_CHARS],
            "parsed_value": parsed["value"] if ok else None,
            "parsed_refs": parsed["evidence_refs"] if ok else None,
            "structured_ok": ok, "parse_issues": list(issues),
            "value_correct": value_ok, "attribution_ok": attr_ok,
            "forbidden_expansion": bool(has_forbidden_expansion(content)),
            "production_conformance": conformance,
            "failure_class": ("NONE" if (ok and value_ok and attr_ok)
                              else "SEMANTIC_MISMATCH" if ok else "UNPARSEABLE"),
        })
        records.append(rec)
    return records


def run_abstention_reps(n: int = 3) -> list[dict[str, Any]]:
    prompt, _ = build_abstention_prompt()
    records = []
    for rep in range(1, n + 1):
        rec: dict[str, Any] = {
            "check": "abstention", "repetition": rep,
            "model": MODEL_PRIMARY, "think": False, "temperature": 0,
            "timeout_s": TIMEOUT_S, "num_predict": NUM_PREDICT_FIELD,
            "case_id": "C", "field": "target",
            "supplied_evidence_ids": [],
            "prompt_chars": len(prompt),
            "expected_value": None,
            "format": "null-only",
            "prompt_frozen_across_reps": True,
        }
        try:
            out = ollama_typed_call(prompt=prompt, format_schema=ABSTAIN_FORMAT)
        except TimeoutError:
            rec.update({"completed_in_budget": False, "timeout": True,
                        "latency_s": TIMEOUT_S, "failure_class": "TIMEOUT",
                        "structured_ok": False, "abstained": False})
            records.append(rec)
            continue
        content = out["content"]
        parsed, ok, issues = parse_typed_target(content)
        abstained = bool(ok and parsed["value"] is None and parsed["evidence_refs"] == [])
        rec.update({
            "completed_in_budget": True, "timeout": False,
            "latency_s": round(float(out["wall_s"]), 3),
            "eval_count": out.get("eval_count"),
            "prompt_eval_count": out.get("prompt_eval_count"),
            "tokens_per_sec": (round(float(out["tokens_per_sec"]), 2)
                               if isinstance(out.get("tokens_per_sec"), (int, float)) else None),
            "done_reason": out.get("done_reason"),
            "raw_preview": content[:MAX_RAW_CHARS],
            "parsed_value": parsed["value"] if ok else None,
            "parsed_refs": parsed["evidence_refs"] if ok else None,
            "structured_ok": ok, "parse_issues": list(issues),
            "abstained": abstained,
            "forbidden_expansion": bool(has_forbidden_expansion(content)),
            "failure_class": "NONE" if abstained else ("FABRICATED" if ok else "UNPARSEABLE"),
        })
        records.append(rec)
    return records


def main(argv: Any = None) -> int:
    ap = argparse.ArgumentParser(description="Task 7.5 contract validation (research only)")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--base-url", default=BASE_URL)
    ap.add_argument("--out", default="output/research/llm-evaluation")
    args = ap.parse_args(argv)
    if not args.live:
        prompt, spec = build_typed_target_prompt()
        print(json.dumps({"check": "typed_target", "prompt_chars": len(prompt),
                          "evidence_ids": list(spec.allowed_evidence_ids),
                          "format": "typed-object-or-null"}, sort_keys=True))
        prompt_a, _ = build_abstention_prompt()
        print(json.dumps({"check": "abstention", "prompt_chars": len(prompt_a),
                          "evidence_ids": [], "format": "null-only"}, sort_keys=True))
        return 0
    checked = preflight(args.base_url, timeout=min(10.0, TIMEOUT_S))
    if not checked.get("available"):
        print("LIVE_OLLAMA_STATUS: BLOCKED: %s" % checked.get("error"), file=sys.stderr)
        return 2
    target_recs = run_target_reps(3)
    abst_recs = run_abstention_reps(3)
    artifact = {
        "schema": CONTRACT_CHECK_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "live": True, "model": MODEL_PRIMARY, "think": False,
        "temperature": 0, "timeout_s": TIMEOUT_S,
        "num_predict": NUM_PREDICT_FIELD,
        "fixtures_version": FIXTURES_VERSION,
        "preflight": dict(checked),
        "production_audit": {
            "attack_target": "object{index:integer REQUIRED, name:string optional}, "
                             "validator.py:82-86, ollama.py:95-96",
            "attack_targeturi": "string startswith('/') no scheme, validator.py:87-88",
            "attack_rport": "integer non-bool in supported ports, validator.py:80-81",
            "attack_payload": "string in compatible set + FOUND, validator.py:78-79",
            "patch": "fix_type A/B/C; strategy 9-enum + pairings; target_version "
                     "same-major; artifact_source<=2000; source_identifier<=500; "
                     "build_system={maven}; notes display-only; "
                     "patch_proposal.py:294-336",
        },
        "typed_target_runs": target_recs,
        "abstention_runs": abst_recs,
        "dropped_runs": 0,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / ("llm_field_contract_check_qwen3-8b_%s.json" % stamp)
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "typed_target_correct": [r.get("value_correct") for r in target_recs],
        "abstained": [r.get("abstained") for r in abst_recs]}, indent=2))
    print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
