from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Mapping
from urllib.request import Request, urlopen


SYSTEM_PROMPT = """You are a configuration guidance assistant for Kalama. Use only supplied evidence.
Do not invent modules, targets, payloads, ports, options, paths, runtime facts, outcomes, or evidence refs.
A proposal is not confirmation. Return null and missing evidence when unsupported. Never change deterministic
facts, claim exploit outcomes, create commands, or set confirmation/readiness/oracle states. Return compact
one-line JSON only. Propose at most 3 fields. Reasons are at most 20 words. Notes at most 2. Summary at most
30 words. Use exactly: {"schema":"kalama.llm-proposal/v1","status":"PROPOSED|INSUFFICIENT_EVIDENCE",
"run_id":"...","cve_id":"...","evidence_pack_sha256":"...","proposals":{},
"missing_evidence":[],"guidance_notes":[],"reasoning_summary":"..."}. Prefer supported payload,
targeturi, and rport guidance before other fields."""

def _proposal_schema(value_schema):
    return {"type": "object", "additionalProperties": False,
            "required": ["value", "evidence_refs", "reason"],
            "properties": {"value": value_schema,
                "evidence_refs": {"type": "array", "maxItems": 3,
                                  "items": {"type": "string"}},
                "reason": {"type": "string"}}}

PROPOSAL_FORMAT = {
    "type": "object", "additionalProperties": False,
    "required": ["schema", "status", "run_id", "cve_id", "evidence_pack_sha256",
                 "proposals", "missing_evidence", "guidance_notes", "reasoning_summary"],
    "properties": {
        "schema": {"type": "string", "const": "kalama.llm-proposal/v1"},
        "status": {"type": "string", "enum": ["PROPOSED", "INSUFFICIENT_EVIDENCE"]},
        "run_id": {"type": "string"}, "cve_id": {"type": "string"},
        "evidence_pack_sha256": {"type": "string"},
        "proposals": {"type": "object", "additionalProperties": False, "maxProperties": 3,
            "properties": {
                "module": _proposal_schema({"type": "string"}),
                "target": _proposal_schema({"type": "object", "additionalProperties": False,
                    "properties": {"index": {"type": "integer"}, "name": {"type": "string"}}}),
                "targeturi": _proposal_schema({"type": "string"}),
                "rport": _proposal_schema({"type": "integer"}),
                "payload": _proposal_schema({"type": "string"}),
                "module_options": _proposal_schema({"type": "object"}),
                "payload_options": _proposal_schema({"type": "object"}),
                "execution_protocol": _proposal_schema({"type": "string", "enum": [
                    "check-first", "check-only", "check-then-exploit"]}),
                "preconditions": _proposal_schema({"type": "string"})}},
        "missing_evidence": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
        "guidance_notes": {"type": "array", "maxItems": 2, "items": {"type": "string"}},
        "reasoning_summary": {"type": "string"}}}


@dataclass(frozen=True)
class OllamaConfig:
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.2:3b"
    timeout: float = 45
    max_response_bytes: int = 256 * 1024


class OllamaProvider:
    name = "ollama"
    def __init__(self, config: OllamaConfig = OllamaConfig(), *, transport=None,
                 monotonic=time.monotonic):
        self.config, self.transport, self.monotonic = config, transport or self._transport, monotonic

    def _transport(self, body: bytes) -> bytes:
        request = Request(self.config.base_url.rstrip("/") + "/api/chat", data=body,
                          headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=self.config.timeout) as response:
            data = response.read(self.config.max_response_bytes + 1)
        if len(data) > self.config.max_response_bytes:
            raise ValueError("Ollama response exceeded configured limit")
        return data

    def propose(self, evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        prompt = {"task": "Propose only allowed guidance fields using mandatory evidence_refs.",
                  "evidence_pack_sha256": evidence_sha256, "evidence": evidence}
        body = json.dumps({"model": self.config.model, "stream": False,
                           "format": PROPOSAL_FORMAT,
                           "options": {"temperature": 0, "num_predict": 512},
                           "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                        {"role": "user", "content": json.dumps(prompt,
                                         separators=(",", ":"), ensure_ascii=False)}]}).encode()
        started = self.monotonic()
        outer = json.loads(self.transport(body))
        elapsed = self.monotonic() - started
        content = outer.get("message", {}).get("content") if isinstance(outer, Mapping) else None
        proposal = json.loads(content) if isinstance(content, str) else content
        if not isinstance(proposal, Mapping): raise ValueError("Ollama returned no JSON proposal")
        return proposal, elapsed
