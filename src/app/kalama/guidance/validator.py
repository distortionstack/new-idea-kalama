from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

from .models import EvidencePack, PROPOSAL_SCHEMA, ProposalValidationState


ALLOWED_TOP = {"schema", "status", "run_id", "cve_id", "evidence_pack_sha256",
               "proposals", "missing_evidence", "guidance_notes", "reasoning_summary"}
ALLOWED_FIELDS = {"module", "target", "targeturi", "rport", "payload",
                  "module_options", "payload_options", "execution_protocol", "preconditions"}


def _supported_ports(pack: EvidencePack) -> set[int]:
    document = pack.document
    ports = document["target"]["ports"]
    supported = {int(value) for values in ports.values() for value in values}
    default = document["resolver"]["rport"].get("suggested_value")
    if isinstance(default, int) and not isinstance(default, bool): supported.add(default)
    return supported


def validate_proposal(pack: EvidencePack, raw: Any) -> tuple[ProposalValidationState, dict[str, Any], tuple[str, ...]]:
    if not isinstance(raw, Mapping):
        return ProposalValidationState.REJECTED, {}, ("proposal must be an object",)
    unknown = set(raw) - ALLOWED_TOP
    if unknown:
        return ProposalValidationState.REJECTED, {}, (f"unknown top-level fields: {sorted(unknown)}",)
    if (raw.get("schema") != PROPOSAL_SCHEMA or raw.get("status") not in
            {"PROPOSED", "INSUFFICIENT_EVIDENCE"}):
        return ProposalValidationState.REJECTED, {}, ("invalid schema or status",)
    if (raw.get("run_id"), raw.get("cve_id"), raw.get("evidence_pack_sha256")) != (
            pack.run_id, pack.cve_id, pack.sha256):
        return ProposalValidationState.REJECTED, {}, ("proposal identity/evidence digest mismatch",)
    if raw.get("status") == "INSUFFICIENT_EVIDENCE":
        return ProposalValidationState.INSUFFICIENT_EVIDENCE, {}, ()
    proposals = raw.get("proposals")
    if not isinstance(proposals, Mapping):
        return ProposalValidationState.REJECTED, {}, ("proposals must be an object",)
    invalid_fields = set(proposals) - ALLOWED_FIELDS
    if invalid_fields:
        return ProposalValidationState.REJECTED, {}, (f"forbidden proposal fields: {sorted(invalid_fields)}",)
    allowed = set(pack.document["allowed_proposal_fields"])
    accepted: dict[str, Any] = {}
    issues = []
    meta = pack.document["metasploit"]
    for field, proposal in proposals.items():
        if field not in allowed:
            issues.append(f"{field}: field is already resolved or not allowed")
            continue
        if not isinstance(proposal, Mapping) or set(proposal) - {"value", "evidence_refs", "reason"}:
            issues.append(f"{field}: malformed proposal")
            continue
        refs, value = proposal.get("evidence_refs"), proposal.get("value")
        if (not isinstance(refs, list) or any(not isinstance(x, str) for x in refs)
                or any(x not in pack.references for x in refs) or (value is not None and not refs)):
            issues.append(f"{field}: invalid or fabricated evidence reference")
            continue
        valid = True
        if field == "module": valid = isinstance(value, str) and value in meta["candidate_modules"]
        elif field == "payload": valid = (isinstance(value, str) and
            meta["payload_discovery_status"] == "FOUND" and value in pack.full_compatible_payloads)
        elif field == "rport": valid = (isinstance(value, int) and not isinstance(value, bool)
                                          and value in _supported_ports(pack))
        elif field == "target":
            valid = isinstance(value, Mapping) and set(value) <= {"index", "name"} and any(
                value.get("index") == item["index"] and
                (value.get("name") is None or value.get("name") == item["name"])
                for item in meta["targets"])
        elif field == "targeturi":
            valid = isinstance(value, str) and value.startswith("/") and not urlsplit(value).scheme
        elif field in {"module_options", "payload_options"}:
            schema = (pack.full_module_options if field == "module_options"
                      else pack.full_payload_options)
            valid = isinstance(value, Mapping) and all(name in schema for name in value)
        elif field == "execution_protocol":
            valid = value in {"check-first", "check-only", "check-then-exploit"}
        elif field == "preconditions":
            valid = isinstance(value, str) and "\n" not in value and not any(
                token in value.casefold() for token in ("curl ", "docker ", "rm ", "touch ",
                                                        "python -c", "bash ", "sh "))
        if not valid:
            issues.append(f"{field}: unsupported value")
            continue
        accepted[field] = {"value": value, "evidence_refs": list(refs),
                           "reason": str(proposal.get("reason") or "")[:1000]}
    if accepted and issues: state = ProposalValidationState.PARTIALLY_ACCEPTED
    elif accepted: state = ProposalValidationState.ACCEPTED_AS_SUGGESTION
    else: state = ProposalValidationState.REJECTED
    return state, accepted, tuple(issues)
