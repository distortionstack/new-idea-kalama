"""Task 6 Patch-specific LLM proposal contract and deterministic validator.

This module is the Patch analogue of the Attack ``guidance/validator.py``
path.  It intentionally does NOT reuse the Attack proposal field schema:
Patch suggestions use their own locked vocabulary, their own evidence
envelope, and their own action/plan binding.  Nothing here writes
``confirmed`` values, touches the trust boundary, or executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import hashlib
import json

from ..remediation.models import PatchStrategy
from .models import ProposalValidationState


PATCH_EVIDENCE_SCHEMA = "kalama.patch-llm-evidence/v1"
PATCH_PROPOSAL_SCHEMA = "kalama.patch-llm-proposal/v1"
PATCH_LLM_GUIDANCE_SCHEMA = "kalama.patch-llm-guidance/v1"

# Locked Task 6 MVP vocabulary.  Do not expand without a new task.
PATCH_LLM_ELIGIBLE_FIELDS: tuple[str, ...] = (
    "fix_type",
    "strategy",
    "target_version",
    "artifact_source",
    "source_identifier",
    "build_system",
    "notes",
)
PATCH_ELIGIBLE_SET = frozenset(PATCH_LLM_ELIGIBLE_FIELDS)
_PATCH_ELIGIBLE_SET = PATCH_ELIGIBLE_SET

# Fields the LLM must NEVER be allowed to set (proposal keys or smuggled
# nested keys).  The validator rejects any proposal carrying them.
# NOTE: "status" here means plan/action status; the proposal envelope's own
# "status" (PROPOSED/INSUFFICIENT_EVIDENCE) is part of the contract and is
# validated separately, so it is intentionally absent from this set.
PATCH_FORBIDDEN_FIELDS = frozenset({
    "command",
    "validation_command",
    "replacement_target",
    "checksum",
    "trusted",
    "source_authority",
    "source_type",
    "human_confirmed_fields",
    "major_version_approved",
    "execution_target",
    "disposition",
    "disposition_reason",
    "readiness",
    "remediation_verified",
})

ALLOWED_PROPOSAL_TOP = frozenset({
    "schema",
    "status",
    "run_id",
    "cve_id",
    "action_id",
    "candidate_digest",
    "field_evidence_sha256",
    "patch_binding",
    "proposals",
    "missing_evidence",
    "guidance_notes",
    "reasoning_summary",
})

ALLOWED_SUGGESTION_KEYS = frozenset({"value", "evidence_refs", "reason"})

_FIX_TYPES = frozenset({"A", "B", "C"})
_STRATEGIES = frozenset(x.value for x in PatchStrategy)

# Minimal fix_type/strategy compatibility derived from current
# discovery/executor semantics (discovery/service.py, docker_backend.py):
#   A = source build   -> REBUILD-family, never package-manager/prebuilt.
#   B = prebuilt image -> replacement-family, never package/build.
#   C = OS package     -> package-manager-family, never source/prebuilt build.
# HUMAN_COMMAND is human-executed and allowed with any fix type; the
# remaining executor-less strategies (COPACETIC/MUTATION/DOCKER_COMMIT/
# ARTIFACT_REPLACEMENT/IMAGE_REPLACEMENT) are not rejected here because
# their executors are simply unconfigured downstream.
_INVALID_PAIRINGS = frozenset({
    ("C", "REBUILD"),
    ("C", "PREBUILT_IMAGE_REPLACEMENT"),
    ("A", "PACKAGE_MANAGER"),
    ("A", "PREBUILT_IMAGE_REPLACEMENT"),
    ("A", "IMAGE_REPLACEMENT"),
    ("B", "PACKAGE_MANAGER"),
    ("B", "REBUILD"),
})

# Bounded build-system vocabulary: the only value deterministic discovery
# emits (discovery/source_build.py).  DockerPatchBackend has no REBUILD
# executor, so nothing else may be invented.
_BUILD_SYSTEMS = frozenset({"maven"})

# Execution-relevant fields: each accepted suggestion must cite evidence
# from the exact supplied EvidencePack.  ``notes`` is display-only and may
# summarize without creating new authority.
_EVIDENCE_BACKED_FIELDS = frozenset({
    "fix_type",
    "strategy",
    "target_version",
    "artifact_source",
    "source_identifier",
    "build_system",
})


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class PatchEvidenceEnvelope:
    """Deterministic envelope binding one PatchAction to one EvidencePack."""

    run_id: str
    cve_id: str
    action_id: str
    document: Mapping[str, Any]
    references: frozenset[str]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(dict(self.document))).hexdigest()


def build_patch_envelope(
    *,
    run_id: str,
    cve_id: str,
    action_id: str,
    package_key: str,
    candidate_digest: str,
    candidate_context: Mapping[str, Any],
    field_pack: Any,
    allowed_fields: Any,
    resolved_fields: Mapping[str, Any] | None = None,
    target_cves: Any = (),
    plan_revision: int | None = None,
    base_patch_plan_sha256: str | None = None,
) -> PatchEvidenceEnvelope:
    """Build the envelope the provider sees and the validator enforces."""
    try:
        field_dict = field_pack.to_dict()
        field_sha = field_pack.sha256
    except Exception as exc:
        raise ValueError(f"field pack is not serializable: {exc}") from exc
    allowed = sorted(set(allowed_fields) & _PATCH_ELIGIBLE_SET)
    if not allowed:
        raise ValueError("patch envelope requires eligible allowed fields")
    references: set[str] = set()
    try:
        for ref in getattr(field_pack, "snapshot_refs", ()):
            if isinstance(ref, str) and ref:
                references.add(ref)
        for item in getattr(field_pack, "items", ()):
            provenance = getattr(item, "provenance_ref", None)
            if isinstance(provenance, str) and provenance:
                references.add(provenance)
            snapshot = getattr(item, "snapshot_sha256", None)
            if isinstance(snapshot, str) and snapshot:
                references.add(snapshot)
            kind = getattr(item, "source_kind", None)
            kind_value = getattr(kind, "value", kind)
            if isinstance(kind_value, str) and kind_value:
                references.add(f"field_evidence.{kind_value}")
    except Exception as exc:
        raise ValueError(f"field pack references unreadable: {exc}") from exc
    document = {
        "schema": PATCH_EVIDENCE_SCHEMA,
        "run_id": run_id,
        "phase": "patch",
        "cve_id": cve_id,
        "action_id": action_id,
        "package_key": package_key,
        "target_cves": list(target_cves),
        "candidate_digest": candidate_digest,
        "candidate_context": dict(candidate_context),
        "field_evidence_pack": field_dict,
        "field_evidence_sha256": field_sha,
        "allowed_proposal_fields": allowed,
        "resolved_fields": dict(resolved_fields or {}),
        "patch_binding": {
            "action_id": action_id,
            "package_key": package_key,
            "plan_revision": plan_revision,
            "base_patch_plan_sha256": base_patch_plan_sha256,
        },
    }
    return PatchEvidenceEnvelope(run_id, cve_id, action_id, document,
                                 frozenset(sorted(references)))


def _installed_majors(document: Mapping[str, Any]) -> set[str]:
    try:
        context = document.get("candidate_context") or {}
        versions = context.get("installed_versions") or ()
        return {str(v).split(".", 1)[0] for v in versions if str(v)[:1].isdigit()}
    except Exception:
        return set()


def validate_patch_proposal(
    envelope: PatchEvidenceEnvelope, raw: Any
) -> tuple[ProposalValidationState, dict[str, Any], tuple[str, ...]]:
    """Deterministic validation of a Patch LLM proposal."""
    if not isinstance(raw, Mapping):
        return ProposalValidationState.REJECTED, {}, ("proposal must be an object",)
    unknown = set(raw) - ALLOWED_PROPOSAL_TOP
    if unknown:
        return ProposalValidationState.REJECTED, {}, (
            f"unknown top-level fields: {sorted(unknown)}",)
    # Hard prohibition: forbidden keys must never appear, even nested at top.
    forbidden_top = set(raw) & PATCH_FORBIDDEN_FIELDS
    if forbidden_top:
        return ProposalValidationState.REJECTED, {}, (
            f"forbidden proposal fields: {sorted(forbidden_top)}",)
    if raw.get("schema") != PATCH_PROPOSAL_SCHEMA or raw.get("status") not in {
            "PROPOSED", "INSUFFICIENT_EVIDENCE"}:
        return ProposalValidationState.REJECTED, {}, ("invalid schema or status",)
    if (raw.get("run_id"), raw.get("cve_id"), raw.get("action_id")) != (
            envelope.run_id, envelope.cve_id, envelope.action_id):
        return ProposalValidationState.REJECTED, {}, (
            "proposal identity mismatch",)
    if raw.get("candidate_digest") != envelope.document.get("candidate_digest"):
        return ProposalValidationState.REJECTED, {}, (
            "candidate binding mismatch: proposal is not bound to this patch candidate",)
    if raw.get("field_evidence_sha256") != envelope.document.get("field_evidence_sha256"):
        return ProposalValidationState.REJECTED, {}, (
            "field evidence digest mismatch: proposal is not bound to this evidence pack",)
    if raw.get("patch_binding") != envelope.document.get("patch_binding"):
        return ProposalValidationState.REJECTED, {}, (
            "patch action/plan binding mismatch",)
    if raw.get("status") == "INSUFFICIENT_EVIDENCE":
        return ProposalValidationState.INSUFFICIENT_EVIDENCE, {}, ()
    proposals = raw.get("proposals")
    if not isinstance(proposals, Mapping):
        return ProposalValidationState.REJECTED, {}, ("proposals must be an object",)
    invalid_fields = set(proposals) - _PATCH_ELIGIBLE_SET
    if invalid_fields:
        # Forbidden/unknown suggestion keys invalidate the whole proposal:
        # a model attempting command/checksum/trust escalation must not get
        # partial acceptance for anything else.
        return ProposalValidationState.REJECTED, {}, (
            f"forbidden proposal fields: {sorted(invalid_fields)}",)
    allowed = set(envelope.document.get("allowed_proposal_fields") or ())
    accepted: dict[str, Any] = {}
    issues: list[str] = []
    for field, proposal in proposals.items():
        if field not in allowed:
            issues.append(f"{field}: field is already resolved or not allowed")
            continue
        if not isinstance(proposal, Mapping) or set(proposal) - ALLOWED_SUGGESTION_KEYS:
            issues.append(f"{field}: malformed proposal")
            continue
        refs, value = proposal.get("evidence_refs"), proposal.get("value")
        if not isinstance(refs, list) or any(not isinstance(x, str) for x in refs):
            issues.append(f"{field}: invalid evidence reference list")
            continue
        if any(x not in envelope.references for x in refs):
            issues.append(f"{field}: invalid or fabricated evidence reference")
            continue
        if field in _EVIDENCE_BACKED_FIELDS and not refs:
            issues.append(f"{field}: evidence reference required")
            continue
        if value is not None and not refs and field in _EVIDENCE_BACKED_FIELDS:
            issues.append(f"{field}: value without evidence")
            continue
        valid = _validate_value(envelope, field, value, proposals)
        if not valid:
            issues.append(f"{field}: unsupported value")
            continue
        accepted[field] = {"value": value, "evidence_refs": list(refs),
                           "reason": str(proposal.get("reason") or "")[:1000]}
    if accepted and issues:
        state = ProposalValidationState.PARTIALLY_ACCEPTED
    elif accepted:
        state = ProposalValidationState.ACCEPTED_AS_SUGGESTION
    else:
        state = ProposalValidationState.REJECTED
    return state, accepted, tuple(issues)


def _validate_value(envelope: PatchEvidenceEnvelope, field: str,
                    value: Any, proposals: Mapping[str, Any]) -> bool:
    if field == "fix_type":
        if value not in _FIX_TYPES:
            return False
    elif field == "strategy":
        if not isinstance(value, str) or value not in _STRATEGIES:
            return False
        fix_proposal = proposals.get("fix_type")
        fix_value = fix_proposal.get("value") if isinstance(fix_proposal, Mapping) else None
        if fix_value is None:
            fix_value = (envelope.document.get("resolved_fields") or {}).get("fix_type")
        if isinstance(fix_value, str) and (fix_value, value) in _INVALID_PAIRINGS:
            return False
    elif field == "target_version":
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            return False
        if any(ch.isspace() for ch in value):
            return False
        majors = _installed_majors(envelope.document)
        if majors and value[:1].isdigit() and value.split(".", 1)[0] not in majors:
            # Same-branch safety: an LLM suggestion must never silently jump
            # the major release branch (that needs human major_version_approved).
            return False
    elif field == "artifact_source":
        if not isinstance(value, str) or not value.strip() or len(value) > 2000:
            return False
        if "\n" in value:
            return False
    elif field == "source_identifier":
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            return False
        if "\n" in value:
            return False
    elif field == "build_system":
        if value not in _BUILD_SYSTEMS:
            return False
    elif field == "notes":
        if not isinstance(value, str) or not value.strip() or len(value) > 2000:
            return False
    else:
        return False
    return True


@dataclass(frozen=True)
class PatchGuidanceOutcome:
    """Audit record for one PatchAction field-level LLM call."""

    action_id: str
    cve_id: str
    envelope: PatchEvidenceEnvelope
    provider_status: str
    provider: str | None = None
    model: str | None = None
    elapsed_seconds: float | None = None
    raw_proposal: Mapping[str, Any] | None = None
    validation_state: ProposalValidationState = ProposalValidationState.INSUFFICIENT_EVIDENCE
    accepted: Mapping[str, Any] | None = None
    issues: tuple[str, ...] = ()
    field_evidence_pack: Any = None

    def __post_init__(self) -> None:
        if self.accepted is None:
            object.__setattr__(self, "accepted", {})

    def to_dict(self) -> dict[str, Any]:
        document = self.envelope.document
        return {"action_id": self.action_id,
                "cve_id": self.cve_id,
                "evidence_pack_sha256": self.envelope.sha256,
                "candidate_digest": document.get("candidate_digest"),
                "field_evidence_sha256": document.get("field_evidence_sha256"),
                "patch_binding": dict(document.get("patch_binding") or {}),
                "allowed_proposal_fields": list(document.get("allowed_proposal_fields") or []),
                "provider_status": self.provider_status,
                "provider": self.provider,
                "model": self.model,
                "elapsed_seconds": self.elapsed_seconds,
                "proposal": dict(self.raw_proposal) if self.raw_proposal else None,
                "validation_state": self.validation_state.value,
                "accepted_suggestions": dict(self.accepted or {}),
                "issues": list(self.issues)}
