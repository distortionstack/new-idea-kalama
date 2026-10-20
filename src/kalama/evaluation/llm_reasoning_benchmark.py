"""Task 7.5.2 benchmark representation and guards (research only).

This module freezes benchmark design; it never contacts an LLM or production
runtime.  A future runner receives only ``model_visible_evidence`` through
``serialize_prompt``.  Evaluator truth stays local to the benchmark object.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence


class Classification(str, Enum):
    COPY = "COPY"
    SELECTION = "SELECTION"
    DETERMINISTIC_RULE = "DETERMINISTIC_RULE"
    SEMANTIC_INTERPRETATION = "SEMANTIC_INTERPRETATION"
    INSUFFICIENT = "INSUFFICIENT"
    INVALID = "INVALID"


@dataclass(frozen=True)
class Evidence:
    id: str
    source_class: str
    provenance: str
    content: Mapping[str, Any]


@dataclass(frozen=True)
class Benchmark:
    benchmark_id: str
    domain: str
    field: str
    classification: Classification
    resolver_gap_proof: Mapping[str, Any]
    knowledge_miss_proof: Mapping[str, Any]
    evaluator_truth: Mapping[str, Any]
    model_visible_evidence: tuple[Evidence, ...]
    evidence_necessity: Mapping[str, str]
    production_field_contract: Mapping[str, Any]


def normalized(value: Any) -> str:
    return " ".join(value.casefold().split()) if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def direct_answer_sources(expected: Any, evidence: Sequence[Evidence]) -> tuple[str, ...]:
    needle = normalized(expected)
    return tuple(item.id for item in evidence if needle in normalized(item.content))


def has_two_necessary(necessity: Mapping[str, str]) -> bool:
    return sum(value == "necessary" for value in necessity.values()) >= 2


def is_deterministic_rule(candidate: Mapping[str, Any]) -> bool:
    return bool(candidate.get("exact_lookup") or candidate.get("set_intersection")
                or candidate.get("normalization") or candidate.get("version_comparison"))


def serialize_prompt(benchmark: Benchmark, evidence: Sequence[Evidence] | None = None) -> str:
    """The only model-facing serialization; never serialize evaluator truth."""
    chosen = tuple(benchmark.model_visible_evidence if evidence is None else evidence)
    body = {"field": benchmark.field, "evidence": [
        {"id": item.id, "source_class": item.source_class, "content": dict(item.content)}
        for item in chosen]}
    return json.dumps(body, sort_keys=True, ensure_ascii=False)


def ablate(benchmark: Benchmark, evidence_id: str) -> tuple[Evidence, ...]:
    if evidence_id not in {x.id for x in benchmark.model_visible_evidence}:
        raise ValueError("unknown evidence id")
    out = tuple(x for x in benchmark.model_visible_evidence if x.id != evidence_id)
    if not out:
        raise ValueError("ablation must retain non-zero evidence")
    return out


def ready(benchmark: Benchmark) -> bool:
    return (benchmark.classification is Classification.SEMANTIC_INTERPRETATION
            and benchmark.resolver_gap_proof.get("status") == "UNRESOLVED"
            and benchmark.knowledge_miss_proof.get("status") == "MISS"
            and has_two_necessary(benchmark.evidence_necessity)
            and not direct_answer_sources(benchmark.evaluator_truth["value"], benchmark.model_visible_evidence))
