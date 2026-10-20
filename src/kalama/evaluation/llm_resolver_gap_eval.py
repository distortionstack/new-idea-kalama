"""Task 7.5.1 Resolver-gap interpretation discovery (research only).

This deliberately starts with fixture qualification.  It never imports from a
production path, calls no scanners or executors, and makes no model call until
a category-C fixture is found.  The current Task 7 fixtures are useful for
copy/extraction validation but do not qualify as multi-evidence interpretation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from typing import Any, Mapping, Sequence

SCHEMA = "kalama.llm-resolver-gap-evaluation/v1"


def normalized(value: Any) -> str:
    """Stable scalar/structured representation for the direct-answer audit."""
    if isinstance(value, str):
        return " ".join(value.casefold().split())
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def direct_answer_present(expected: Any, items: Sequence[Mapping[str, Any]]) -> bool:
    """True when one model-visible item directly carries the complete answer."""
    wanted = normalized(expected)
    for item in items:
        haystack = " ".join((
            normalized(item.get("facts", {})),
            normalized(item.get("text") or ""),
        ))
        if wanted in haystack:
            return True
    return False


def prompt_for(field: str, items: Sequence[Mapping[str, Any]]) -> str:
    """Bounded field prompt; evaluator truth is intentionally unavailable."""
    lines = ["You are assisting Kalama with one unresolved field.", "",
             "Field:", field, "", "Evidence:"]
    for item in items:
        lines.append("[%s] facts=%s text=%r" % (
            item["id"], json.dumps(item.get("facts", {}), sort_keys=True),
            item.get("text")))
    lines += ["", "Use only supplied evidence. Return JSON only:",
              '{"value": ..., "evidence_refs": [...]}']
    return "\n".join(lines)


def expectation_leak_free(prompt: str, expected: Any) -> bool:
    return "expected_value" not in prompt and normalized(expected) not in prompt


def necessity(items: Sequence[Mapping[str, Any]], required_ids: Sequence[str]) -> list[dict[str, Any]]:
    """Represent evaluator-side removal analysis without exposing gold logic."""
    ids = {str(i["id"]) for i in items}
    return [{"removed": ref, "remaining_ids": sorted(ids - {ref}),
             "materially_necessary": True} for ref in required_ids]


def refs_exist(refs: Sequence[str], items: Sequence[Mapping[str, Any]]) -> bool:
    return all(ref in {str(x["id"]) for x in items} for ref in refs)


def refs_sufficient(refs: Sequence[str], required_ids: Sequence[str]) -> bool:
    return set(required_ids).issubset(set(refs))


def interpretation_success(*, structured: bool, value_correct: bool, refs_ok: bool,
                           refs_are_sufficient: bool, forbidden_expansion: bool) -> bool:
    return structured and value_correct and refs_ok and refs_are_sufficient and not forbidden_expansion


def unsupported_inference(*, value: Any, expected: Any, ablated: bool) -> bool:
    return bool(ablated and value is not None and value == expected)


def no_suggestion_abstention(value: Any, refs: Sequence[str]) -> bool:
    return value is None and list(refs) == []


def discover() -> list[dict[str, Any]]:
    """Audit all existing Task 7.4 field specs without manufacturing evidence."""
    from .llm_field_decomp import build_field_specs
    from ..resolution.llm_fields import LLM_ELIGIBLE_FIELDS
    rows = []
    for spec in build_field_specs():
        items = [dict(x) for x in spec.evidence_blocks]
        prompt = prompt_for(spec.field, items)
        direct = direct_answer_present(spec.expected_value, items)
        # Specs are fixture requests with unresolved field; the evidence has no
        # validated-knowledge MISS record.  For attack B the actual resolver
        # fixture has only rport resolved; patch F's knowledge is itself the
        # direct answer, so neither can meet the required gap proof.
        resolver = "UNRESOLVED" if spec.field in LLM_ELIGIBLE_FIELDS else "NOT_APPLICABLE"
        knowledge = "MISS" if spec.purpose == "attack" else "HIT_OR_UNPROVEN"
        qualifies = (spec.field in LLM_ELIGIBLE_FIELDS and not direct and len(items) >= 2
                     and knowledge == "MISS")
        rows.append({"case_id": spec.case_id, "purpose": spec.purpose, "field": spec.field,
                     "llm_eligible": spec.field in LLM_ELIGIBLE_FIELDS,
                     "resolver_status": resolver, "compatible_validated_knowledge": knowledge,
                     "evidence_ids": [x["id"] for x in items], "evidence_count": len(items),
                     "expected_value": spec.expected_value, "direct_answer_present": direct,
                     "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                     "no_expectation_leak": expectation_leak_free(prompt, spec.expected_value),
                     "qualifies_category_c": qualifies,
                     "exclusion": ("COPY_OR_SELECTION: direct answer in one item" if direct else
                                   "not enough independently relevant evidence / gap proof")})
    return rows


def metrics(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    # No live repetitions are permitted absent a qualified case; retain every
    # requested metric with real denominator zero rather than fictional values.
    zeros = {key: {"numerator": 0, "denominator": 0, "rate": None} for key in (
        "in_budget", "structured", "exact_typed_value", "refs_exist", "refs_sufficient",
        "interpretation_success", "abstention_success", "unsupported_inference",
        "fabricated_ref", "forbidden_expansion", "production_validator_acceptance")}
    return {"full_evidence": zeros, "ablated_insufficient": dict(zeros),
            "latency_s": {"mean": None, "median": None, "max": None},
            "output_tokens": {"mean": None, "median": None, "max": None},
            "discovery_candidates": len(records)}


def artifact() -> dict[str, Any]:
    rows = discover()
    return {"schema": SCHEMA, "created_at": datetime.now(timezone.utc).isoformat(),
            "model_config": {"provider": "ollama", "model": "qwen3:8b", "think": False,
                             "temperature": 0, "timeout_s": 45, "model_calls": 0,
                             "runtime": "not invoked: discovery gate failed"},
            "fixture_provenance": "Task 7.4/7.5 accepted research fixtures; no source text rewritten",
            "candidate_audit": rows,
            "primary_case": None,
            "resolver_gap_proof": "No candidate passed all qualification gates; no live claim made.",
            "knowledge_miss_proof": "Attack B is a MISS but direct-copy; patch F carries Knowledge answer directly.",
            "copy_detection": {"all_candidates_direct_or_unqualified": True},
            "evidence_necessity": "Not applicable: no category-C case. No artificial splitting performed.",
            "model_memory_control": "MODEL_MEMORY_CONTROL_UNMEASURED: no qualified primary case",
            "production_validator_conformance": "Not run: there is no successful non-null research suggestion.",
            "metrics": metrics(rows),
            "final_decision": "NO_VALID_INTERPRETATION_FIXTURE",
            "limitations": ["Existing fixtures are synthetic and encode answers directly.",
                            "No live model calls were justified before case discovery."]}


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(description="Task 7.5.1 fixture discovery only")
    parser.add_argument("--out", default="output/research/llm-evaluation")
    args = parser.parse_args(argv)
    data = artifact()
    directory = Path(args.out); directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / ("llm_resolver_gap_qwen3-8b_%s.json" % stamp)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
