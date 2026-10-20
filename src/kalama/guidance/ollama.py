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
"missing_evidence":[],"guidance_notes":[],"reasoning_summary":"..."}. When the evidence carries
candidate_digest or field_evidence_sha256, echo each value unchanged. Prefer supported payload,
targeturi, and rport guidance before other fields."""

PATCH_SYSTEM_PROMPT = """You are a patch guidance assistant for Kalama. Use only supplied evidence.
Do not invent versions, sources, identifiers, build systems, checksums, commands, image
references, or evidence refs. A suggestion is not confirmation and never sets trust,
authority, readiness, or execution. Only these fields may be proposed: fix_type (A/B/C),
strategy (a PatchStrategy value), target_version, artifact_source, source_identifier,
build_system (maven only), notes. Never propose command, validation_command,
replacement_target, checksum, trusted, source_authority, or any status/readiness field.
Return null and missing evidence when unsupported. Echo candidate_digest,
field_evidence_sha256, action_id, and patch_binding unchanged. Return compact one-line
JSON only. Propose at most 3 fields. Reasons are at most 20 words. Notes at most 2.
Summary at most 30 words. Use exactly: {"schema":"kalama.patch-llm-proposal/v1",
"status":"PROPOSED|INSUFFICIENT_EVIDENCE","run_id":"...","cve_id":"...","action_id":"...",
"candidate_digest":"...","field_evidence_sha256":"...","patch_binding":{...},
"proposals":{},"missing_evidence":[],"guidance_notes":[],"reasoning_summary":"..."}."""


def _proposal_schema(value_schema):
    return {"type": "object", "additionalProperties": False,
            "required": ["value", "evidence_refs", "reason"],
            "properties": {"value": value_schema,
                "evidence_refs": {"type": "array", "maxItems": 3,
                                  "items": {"type": "string"}},
                "reason": {"type": "string"}}}


def _patch_value_schema(kind):
    if kind == "fix_type":
        return {"type": "string", "enum": ["A", "B", "C"]}
    if kind == "build_system":
        return {"type": "string", "enum": ["maven"]}
    return {"type": "string"}


PATCH_PROPOSAL_FORMAT = {
    "type": "object", "additionalProperties": False,
    "required": ["schema", "status", "run_id", "cve_id", "action_id",
                 "candidate_digest", "field_evidence_sha256", "patch_binding",
                 "proposals", "missing_evidence", "guidance_notes",
                 "reasoning_summary"],
    "properties": {
        "schema": {"type": "string", "const": "kalama.patch-llm-proposal/v1"},
        "status": {"type": "string", "enum": ["PROPOSED", "INSUFFICIENT_EVIDENCE"]},
        "run_id": {"type": "string"}, "cve_id": {"type": "string"},
        "action_id": {"type": "string"},
        "candidate_digest": {"type": "string"},
        "field_evidence_sha256": {"type": "string"},
        "patch_binding": {"type": "object"},
        "proposals": {"type": "object", "additionalProperties": False, "maxProperties": 3,
            "properties": {
                "fix_type": _proposal_schema(_patch_value_schema("fix_type")),
                "strategy": _proposal_schema({"type": "string"}),
                "target_version": _proposal_schema({"type": "string"}),
                "artifact_source": _proposal_schema({"type": "string"}),
                "source_identifier": _proposal_schema({"type": "string"}),
                "build_system": _proposal_schema(_patch_value_schema("build_system")),
                "notes": _proposal_schema({"type": "string"})}},
        "missing_evidence": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
        "guidance_notes": {"type": "array", "maxItems": 2, "items": {"type": "string"}},
        "reasoning_summary": {"type": "string"}}}

PROPOSAL_FORMAT = {
    "type": "object", "additionalProperties": False,
    "required": ["schema", "status", "run_id", "cve_id", "evidence_pack_sha256",
                 "proposals", "missing_evidence", "guidance_notes", "reasoning_summary"],
    "properties": {
        "schema": {"type": "string", "const": "kalama.llm-proposal/v1"},
        "status": {"type": "string", "enum": ["PROPOSED", "INSUFFICIENT_EVIDENCE"]},
        "run_id": {"type": "string"}, "cve_id": {"type": "string"},
        "evidence_pack_sha256": {"type": "string"},
        "candidate_digest": {"type": "string"},
        "field_evidence_sha256": {"type": "string"},
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
    # Task 7.3: Ollama thinking control for reasoning models (e.g. qwen3).
    # None (default) omits the API option entirely, preserving historical
    # request bytes.  Explicit True/False is forwarded as "think".
    think: bool | None = None


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
        return self._call(PROPOSAL_FORMAT, SYSTEM_PROMPT, evidence, evidence_sha256)

    def propose_patch(self, evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        """Patch-shaped proposal call (Task 7 narrow integration fix).

        The default ``propose`` path is unchanged and remains Attack-shaped.
        Patch live evaluation needs the patch contract; without this the
        provider could never emit a schema-valid Patch proposal.
        """
        return self._call(PATCH_PROPOSAL_FORMAT, PATCH_SYSTEM_PROMPT, evidence, evidence_sha256)

    def _call(self, format_schema: Mapping[str, Any], system_prompt: str,
              evidence: Mapping[str, Any], evidence_sha256: str) -> tuple[Mapping[str, Any], float]:
        prompt = {"task": "Propose only allowed guidance fields using mandatory evidence_refs.",
                  "evidence_pack_sha256": evidence_sha256, "evidence": evidence}
        payload: dict[str, Any] = {"model": self.config.model, "stream": False,
                           "format": dict(format_schema),
                           "options": {"temperature": 0, "num_predict": 512},
                           "messages": [{"role": "system", "content": system_prompt},
                                        {"role": "user", "content": json.dumps(prompt,
                                         separators=(",", ":"), ensure_ascii=False)}]}
        if self.config.think is not None:
            payload["think"] = bool(self.config.think)
        body = json.dumps(payload).encode()
        started = self.monotonic()
        outer = json.loads(self.transport(body))
        elapsed = self.monotonic() - started
        content = outer.get("message", {}).get("content") if isinstance(outer, Mapping) else None
        proposal = json.loads(content) if isinstance(content, str) else content
        if not isinstance(proposal, Mapping): raise ValueError("Ollama returned no JSON proposal")
        return proposal, elapsed
