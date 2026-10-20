"""Task 7.4 field-level LLM workload/output decomposition diagnostic.

RESEARCH ONLY.  Never imported by production Attack/Patch paths, validators,
resolver, planner, prioritizer, Knowledge, scanner, or AFTER pipeline.

Purpose: measure whether qwen3:8b (CPU-only, think=false, 45 s budget) can do
useful evidence-backed Kalama work when the LLM output is only::

    {"value": ..., "evidence_refs": [...]}

using the SAME CandidateContext and SAME evidence semantics as Task 7
fixtures B (attack) and F (patch).  No production behavior is changed here.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

FIELD_DECOMP_SCHEMA = "kalama.llm-field-decomposition-evaluation/v1"
FIXTURES_VERSION = "t7-fixtures/v1-synthetic"

MODEL_PRIMARY = "qwen3:8b"
MODEL_CONTROL = "llama3.2:3b"
BASE_URL = "http://127.0.0.1:11434"
TIMEOUT_S = 45.0
TEMPERATURE = 0
NUM_PREDICT_FIELD = 128  # bounded tiny output; strictly less than prod 512
MAX_RAW_CHARS = 2000

ALLOWED_DIAG_KEYS = frozenset({"value", "evidence_refs"})

# Forbidden production/protocol fields the diagnostic must never request.
FORBIDDEN_TOKENS = (
    "candidate_digest",
    "EvidencePack SHA256",
    "field_evidence_sha256",
    "evidence_pack_sha256",
    "action_id",
    "package_key",
    "plan_revision",
    "base_patch_plan_sha256",
    "execution_protocol",
    "preconditions",
    "payload_options",
    "LHOST",
    "command",
    "validation_command",
    "replacement_target",
    "checksum",
    "human_confirmed_fields",
    "major_version_approved",
    "execution_target",
    "disposition",
    "readiness",
    "remediation_verified",
)


@dataclass(frozen=True)
class FieldDiagnosticSpec:
    case_id: str
    purpose: str  # "attack" | "patch"
    field: str
    candidate_summary: Mapping[str, Any]
    evidence_blocks: tuple[Mapping[str, Any], ...]  # each: {id, kind, authority, facts, text}
    allowed_evidence_ids: tuple[str, ...]
    expected_value: Any
    candidate_digest: str
    field_evidence_sha256: str
    fixtures_version: str = FIXTURES_VERSION


def _collector_pack_sha_for_field(collector: Any, field: str) -> str:
    """Deterministic per-field evidence SHA (diagnostic binding only)."""
    payload = {
        "pack_sha": collector.sha256,
        "field": field,
        "items": [it.to_dict() for it in collector.items],
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def build_field_specs() -> list[FieldDiagnosticSpec]:
    """Derive B/F field specs from existing Task 7 fixtures (no new facts)."""
    from .llm_eval_cases import ALL_CASES, collector_fixture

    by_id = {c.case_id: c for c in ALL_CASES}
    specs: list[FieldDiagnosticSpec] = []

    # ---- Attack case B: requested target, targeturi, payload (rport protected)
    spec_b = by_id["B"]
    col_b = collector_fixture(spec_b)
    # Evidence items in fixture order: [0]=target+payload, [1]=targeturi
    items_b = list(col_b.items)
    item_target_payload = items_b[0]
    item_targeturi = items_b[1]
    cand_b = {
        "cve_id": col_b.request.context.vulnerability_id,
        "component": col_b.request.context.component,
        "installed_version": list(col_b.request.context.installed_versions),
        "image": col_b.request.context.image_identity,
        "resolved_fields": dict(col_b.request.resolved_fields),
    }

    def _block(item: Any) -> Mapping[str, Any]:
        return {
            "id": str(item.provenance_ref),
            "kind": item.source_kind.value,
            "authority": str(item.authority),
            "resource": str(item.resource_identity),
            "facts": json.loads(json.dumps(dict(item.facts), sort_keys=True,
                                           ensure_ascii=False)),
            "text": item.normalized_content,
        }

    b_evidence = {
        "target": (_block(item_target_payload),),
        "payload": (_block(item_target_payload),),
        "targeturi": (_block(item_targeturi),),
    }
    for field in ("target", "targeturi", "payload"):
        blocks = b_evidence[field]
        specs.append(FieldDiagnosticSpec(
            case_id="B", purpose="attack", field=field,
            candidate_summary=cand_b, evidence_blocks=blocks,
            allowed_evidence_ids=tuple(b["id"] for b in blocks),
            expected_value=spec_b.expected_values[field],
            candidate_digest=col_b.request.context.digest,
            field_evidence_sha256=_collector_pack_sha_for_field(col_b, field),
        ))

    # ---- Patch case F: requested target_version only
    spec_f = by_id["F"]
    col_f = collector_fixture(spec_f)
    cand_f = {
        "cve_id": col_f.request.context.vulnerability_id,
        "component": col_f.request.context.component,
        "installed_version": list(col_f.request.context.installed_versions),
        "image": col_f.request.context.image_identity,
        "resolved_fields": dict(col_f.request.resolved_fields),
    }
    blocks_f = tuple(_block(it) for it in col_f.items)
    specs.append(FieldDiagnosticSpec(
        case_id="F", purpose="patch", field="target_version",
        candidate_summary=cand_f, evidence_blocks=blocks_f,
        allowed_evidence_ids=tuple(b["id"] for b in blocks_f),
        expected_value=spec_f.expected_values["target_version"],
        candidate_digest=col_f.request.context.digest,
        field_evidence_sha256=_collector_pack_sha_for_field(col_f, "target_version"),
    ))
    return specs


def build_field_prompt(spec: FieldDiagnosticSpec) -> str:
    """Minimal field prompt. No production system prompt is copied."""
    lines = [
        "You are assisting Kalama with one unresolved field.",
        "",
        "Field:",
        spec.field,
        "",
        "Candidate:",
        "component: %s" % spec.candidate_summary.get("component"),
        "installed_version: %s" % (spec.candidate_summary.get("installed_version"),),
    ]
    resolved = spec.candidate_summary.get("resolved_fields") or {}
    if resolved:
        lines.append("resolved_fields: %s" % json.dumps(resolved, sort_keys=True))
    if spec.purpose == "patch" and spec.field == "target_version":
        lines += ["",
                  "Authority constraint:",
                  "Use only kalama-validated-knowledge facts for the version value.",
                  "Do not promote vendor or runtime text to a version decision."]
    if spec.purpose == "attack" and spec.field in {"target", "payload"}:
        lines += ["",
                  "Authority constraint:",
                  "Select only a value listed in the supplied metasploit evidence facts.",
                  "Do not invent modules, targets, payloads, ports, or paths."]
    lines += ["", "Evidence:"]
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
        "Output:",
        '{"value": ..., "evidence_refs": [...]}',
    ]
    return "\n".join(lines)


def parse_field_response(text: str) -> tuple[Mapping[str, Any] | None, bool, tuple[str, ...]]:
    """Parse tiny diagnostic object. Returns (parsed, structured_ok, issues)."""
    issues: list[str] = []
    try:
        obj = json.loads(text)
    except Exception as exc:
        return None, False, ("json_parse_error: %s" % type(exc).__name__,)
    if not isinstance(obj, dict):
        return None, False, ("not_an_object",)
    keys = set(obj.keys())
    if keys != {"value", "evidence_refs"}:
        issues.append("keys_must_be_exactly_value_and_evidence_refs: %s" % sorted(keys))
        return None, False, tuple(issues)
    refs = obj.get("evidence_refs")
    if not isinstance(refs, list) or any(not isinstance(r, str) for r in refs):
        issues.append("evidence_refs_must_be_string_list")
        return None, False, tuple(issues)
    value = obj.get("value")
    if value is not None and not isinstance(value, (str, int, float, bool, dict, list)):
        issues.append("value_must_be_scalar_object_or_null")
        return None, False, tuple(issues)
    return {"value": value, "evidence_refs": list(refs)}, True, ()


def values_equal(observed: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping) and isinstance(observed, Mapping):
        return dict(observed) == dict(expected)
    return observed == expected


def refs_supported(refs: Sequence[str], allowed: Sequence[str]) -> bool:
    return all(str(r) in set(allowed) for r in refs)


def has_forbidden_expansion(raw_text: str) -> bool:
    low = raw_text.lower()
    for tok in FORBIDDEN_TOKENS:
        if tok.lower() in low:
            # evidence_refs echo of an allowed evidence id is fine; check
            # for protocol-echo patterns instead of bare id mentions.
            if tok in ("command",):
                # 'command' appears in no legitimate tiny output; flag it.
                return True
            return True
    return False


# ---------------- request-binding simulation (offline, diagnostic only) ----

def diagnostic_request_id(candidate_digest: str, field: str,
                           field_evidence_sha256: str) -> str:
    raw = ("%s|%s|%s" % (candidate_digest, field, field_evidence_sha256)).encode()
    return "R-" + hashlib.sha256(raw).hexdigest()[:16]


def binding_store(specs: Sequence[FieldDiagnosticSpec]) -> dict[str, Mapping[str, Any]]:
    store: dict[str, Mapping[str, Any]] = {}
    for s in specs:
        rid = diagnostic_request_id(s.candidate_digest, s.field, s.field_evidence_sha256)
        store[rid] = {
            "candidate_digest": s.candidate_digest,
            "field_evidence_sha256": s.field_evidence_sha256,
            "field_name": s.field,
            "allowed_evidence_ids": list(s.allowed_evidence_ids),
            "case_id": s.case_id,
        }
    return store


def attach_response(store: Mapping[str, Mapping[str, Any]], request_id: str,
                    parsed: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, str]:
    """Kalama-side association: harness owns digests; LLM never echoes them."""
    entry = store.get(request_id)
    if entry is None:
        return None, "reject: unknown request id"
    refs = parsed.get("evidence_refs") if isinstance(parsed, Mapping) else None
    if not isinstance(refs, list):
        return None, "reject: bad evidence_refs"
    allowed = set(entry["allowed_evidence_ids"])
    for r in refs:
        if str(r) not in allowed:
            return None, "reject: evidence ref not in request set: %s" % r
    envelope = {
        "request_id": request_id,
        "candidate_digest": entry["candidate_digest"],
        "field_evidence_sha256": entry["field_evidence_sha256"],
        "field_name": entry["field_name"],
        "value": parsed.get("value"),
        "evidence_refs": [str(r) for r in refs],
    }
    return envelope, "accept"


def check_cross_field(store: Mapping[str, Mapping[str, Any]], request_id: str,
                      parsed: Mapping[str, Any], claimed_field: str) -> tuple[bool, str]:
    """Reject a response that attempts another field than the request's field."""
    entry = store.get(request_id)
    if entry is None:
        return False, "reject: unknown request id"
    if claimed_field != entry["field_name"]:
        return False, "reject: field mismatch: claimed=%s request=%s" % (
            claimed_field, entry["field_name"])
    env, msg = attach_response(store, request_id, parsed)
    return (env is not None), msg


# ---------------- live Ollama call (field-level, think=false) --------------

def ollama_field_call(*, base_url: str = BASE_URL, model: str = MODEL_PRIMARY,
                      prompt: str, timeout: float = TIMEOUT_S,
                      num_predict: int = NUM_PREDICT_FIELD,
                      ) -> dict[str, Any]:
    """Single field-level /api/chat call with exact counters when exposed."""
    body = {
        "model": model,
        "stream": False,
        "think": False,
        "options": {"temperature": TEMPERATURE, "num_predict": num_predict},
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/api/chat", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4 * 1024 * 1024)
        wall = time.monotonic() - started
        outer = json.loads(raw.decode("utf-8", "replace"))
    except TimeoutError as exc:
        raise TimeoutError("timed out") from exc
    except Exception as exc:
        name = type(exc).__name__.lower()
        if "timed out" in str(exc).lower() or "timeout" in name:
            raise TimeoutError("timed out") from exc
        raise
    msg = (outer.get("message") or {}) if isinstance(outer, Mapping) else {}
    content = msg.get("content") if isinstance(msg, Mapping) else None
    eval_count = outer.get("eval_count")
    prompt_eval = outer.get("prompt_eval_count")
    eval_dur_ns = outer.get("eval_duration")
    total_dur_ns = outer.get("total_duration")
    tok_per_s = None
    try:
        if isinstance(eval_count, int) and isinstance(eval_dur_ns, int) and eval_dur_ns > 0:
            tok_per_s = eval_count / (eval_dur_ns / 1e9)
    except Exception:
        tok_per_s = None
    return {
        "content": content if isinstance(content, str) else "",
        "eval_count": eval_count,
        "prompt_eval_count": prompt_eval,
        "eval_duration_ns": eval_dur_ns,
        "total_duration_ns": total_dur_ns,
        "tokens_per_sec": tok_per_s,
        "wall_s": wall,
        "done": outer.get("done"),
        "done_reason": outer.get("done_reason"),
        "outer_truncated": str(outer)[:0],  # placeholder, never stores full outer
    }
