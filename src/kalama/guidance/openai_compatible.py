"""OpenAI-compatible provider for optional, evidence-bounded LLM guidance."""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .ollama import PATCH_PROPOSAL_FORMAT, PATCH_SYSTEM_PROMPT, PROPOSAL_FORMAT, SYSTEM_PROMPT


COMPACT_ATTACK_SYSTEM_PROMPT = (
    "Use supplied evidence only. Return the structured JSON object. Propose only allowed fields; "
    "cite only supplied evidence_refs. A proposal is never confirmation. "
    "If unsupported, return INSUFFICIENT_EVIDENCE with empty proposals. Keep reasons short."
)


@dataclass(frozen=True)
class OpenAICompatibleConfig:
    """Connection details supplied by the user or environment.

    ``api_key`` is deliberately excluded from every artifact and never
    interpolated into an exception or diagnostic.
    """

    base_url: str
    model: str
    api_key: str
    timeout: float = 45
    max_response_bytes: int = 256 * 1024
    max_tokens: int = 384
    max_tokens_limit: int = 1024
    transient_retries: int = 2
    retry_backoff_seconds: float = 1.0


class OpenAICompatibleProvider:
    """Provider for the widely implemented ``/v1/chat/completions`` contract."""

    name = "openai-compatible"

    def __init__(self, config: OpenAICompatibleConfig, *, transport=None,
                 monotonic=time.monotonic):
        self.config = config
        self.transport = transport or self._transport
        self.monotonic = monotonic
        # Non-secret diagnostics for the most recent provider call.  These
        # remain process-local and are never written into run artifacts.
        self.last_call_metadata: dict[str, Any] = {}

    def _transport(self, body: bytes) -> bytes:
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        request = Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.config.api_key,
        })
        with urlopen(request, timeout=self.config.timeout) as response:
            data = response.read(self.config.max_response_bytes + 1)
        if len(data) > self.config.max_response_bytes:
            raise ValueError("provider response exceeded configured limit")
        return data

    def propose(self, evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        return self._call(PROPOSAL_FORMAT, SYSTEM_PROMPT, evidence, evidence_sha256)

    def propose_patch(self, evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        return self._call(PATCH_PROPOSAL_FORMAT, PATCH_SYSTEM_PROMPT, evidence, evidence_sha256)

    def _call(self, format_schema: Mapping[str, Any], system_prompt: str,
              evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        prompt = _compact_prompt(evidence, evidence_sha256)
        response_schema = _compact_attack_schema(evidence, format_schema)
        active_system_prompt = (COMPACT_ATTACK_SYSTEM_PROMPT
                                if response_schema is not format_schema else system_prompt)
        started = self.monotonic()
        budget = max(64, min(self.config.max_tokens, self.config.max_tokens_limit))
        use_schema = True
        transient_attempt = 0
        length_retries = 0
        while True:
            payload = {
                "model": self.config.model,
                "temperature": 0,
                "max_tokens": budget,
                "response_format": _response_format(response_schema) if use_schema else {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": active_system_prompt},
                    {"role": "user", "content": json.dumps(prompt, separators=(",", ":"), ensure_ascii=False)},
                ],
            }
            try:
                outer = json.loads(self.transport(json.dumps(payload).encode("utf-8")))
            except HTTPError as exc:
                # Providers differ in JSON-schema support.  A 400 only falls
                # back to json_object; transient failures use bounded retry.
                if exc.code == 400 and use_schema:
                    use_schema = False
                    continue
                if exc.code in {429, 500, 502, 503, 504} and transient_attempt < self.config.transient_retries:
                    time.sleep(self.config.retry_backoff_seconds * (2 ** transient_attempt))
                    transient_attempt += 1
                    continue
                self.last_call_metadata = {
                    "model": self.config.model, "max_tokens": budget,
                    "structured_output": use_schema, "transient_attempts": transient_attempt + 1,
                    "http_status": exc.code,
                }
                raise
            choices = outer.get("choices") if isinstance(outer, Mapping) else None
            choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], Mapping) else {}
            message = choice.get("message") if isinstance(choice, Mapping) else None
            content = message.get("content") if isinstance(message, Mapping) else None
            finish_reason = choice.get("finish_reason") if isinstance(choice, Mapping) else None
            usage = outer.get("usage") if isinstance(outer, Mapping) else None
            self.last_call_metadata = {
                "model": self.config.model, "max_tokens": budget,
                "structured_output": use_schema, "transient_attempts": transient_attempt + 1,
                "finish_reason": finish_reason, "usage": dict(usage) if isinstance(usage, Mapping) else None,
            }
            if finish_reason == "length" and budget < self.config.max_tokens_limit:
                budget = min(self.config.max_tokens_limit, budget * 2)
                length_retries += 1
                continue
            proposal = json.loads(content) if isinstance(content, str) else content
            if not isinstance(proposal, Mapping):
                raise ValueError("provider returned no JSON proposal")
            return proposal, self.monotonic() - started


def _response_format(schema: Mapping[str, Any]) -> Mapping[str, Any]:
    """Use structured output when available; callers fall back on HTTP 400."""
    return {"type": "json_schema", "json_schema": {
        "name": "kalama_guidance", "strict": True, "schema": dict(schema)}}


def _compact_attack_schema(evidence: Mapping[str, Any], fallback: Mapping[str, Any]) -> Mapping[str, Any]:
    """Keep provider-side structured output proportional to model authority."""
    if fallback.get("properties", {}).get("schema", {}).get("const") != "kalama.llm-proposal/v1":
        return fallback
    allowed = [field for field in evidence.get("allowed_proposal_fields", ())
               if field in {"target", "targeturi", "rport", "payload"}]
    value_schema = {
        "target": {"type": "object", "additionalProperties": False,
                   "properties": {"index": {"type": "integer"}, "name": {"type": "string"}}},
        "targeturi": {"type": "string"}, "rport": {"type": "integer"},
        "payload": {"type": "string"},
    }
    proposal_properties = {
        field: {"type": "object", "additionalProperties": False,
                "required": ["value", "evidence_refs", "reason"],
                "properties": {"value": value_schema[field],
                               "evidence_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                               "reason": {"type": "string", "maxLength": 160}}}
        for field in allowed
    }
    return {
        "type": "object", "additionalProperties": False,
        "required": ["schema", "status", "run_id", "cve_id", "evidence_pack_sha256",
                     "candidate_digest", "field_evidence_sha256", "proposals",
                     "missing_evidence", "guidance_notes", "reasoning_summary"],
        "properties": {
            "schema": {"type": "string", "const": "kalama.llm-proposal/v1"},
            "status": {"type": "string", "enum": ["PROPOSED", "INSUFFICIENT_EVIDENCE"]},
            "run_id": {"type": "string"}, "cve_id": {"type": "string"},
            "evidence_pack_sha256": {"type": "string"}, "candidate_digest": {"type": "string"},
            "field_evidence_sha256": {"type": "string"},
            "proposals": {"type": "object", "additionalProperties": False,
                          "properties": proposal_properties, "maxProperties": min(3, len(proposal_properties))},
            "missing_evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 4},
            "guidance_notes": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
            "reasoning_summary": {"type": "string", "maxLength": 240},
        },
    }


def _compact_prompt(evidence: Mapping[str, Any], evidence_sha256: str) -> Mapping[str, Any]:
    """Minimise model input without changing the validator's evidence pack.

    The provider sees only the fields it may propose, MSF module facts and the
    already-collected field evidence.  The full envelope remains local and is
    still what the validator uses after the response returns.
    """
    field_pack = evidence.get("field_evidence_pack")
    items = field_pack.get("items", []) if isinstance(field_pack, Mapping) else []
    compact_items = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, Mapping):
            continue
        compact_items.append({key: item.get(key) for key in
                              ("source_kind", "resource_identity", "facts", "provenance_ref")})
    metasploit = evidence.get("metasploit") if isinstance(evidence.get("metasploit"), Mapping) else {}
    resolver = evidence.get("resolver") if isinstance(evidence.get("resolver"), Mapping) else {}
    return {
        "task": "Return one compact JSON proposal using only allowed fields and cited evidence_refs.",
        "run_id": evidence.get("run_id"), "cve_id": evidence.get("cve_id"),
        "evidence_pack_sha256": evidence_sha256,
        "candidate_digest": evidence.get("candidate_digest"),
        "field_evidence_sha256": evidence.get("field_evidence_sha256"),
        "allowed_proposal_fields": evidence.get("allowed_proposal_fields", []),
        "module": {key: metasploit.get(key) for key in
                   ("selected_module", "targets", "default_target_index", "module_options",
                    "compatible_payload_subset", "payload_discovery_status")},
        "current_fields": {key: resolver.get(key) for key in ("target", "targeturi", "rport")},
        "field_evidence": compact_items,
    }
