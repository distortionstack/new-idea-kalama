from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Mapping


EVIDENCE_SCHEMA = "kalama.llm-evidence-pack/v1"
PROPOSAL_SCHEMA = "kalama.llm-proposal/v1"
GUIDANCE_SCHEMA = "kalama.llm-guidance/v1"


class ProposalValidationState(str, Enum):
    ACCEPTED_AS_SUGGESTION = "ACCEPTED_AS_SUGGESTION"
    PARTIALLY_ACCEPTED = "PARTIALLY_ACCEPTED"
    REJECTED = "REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class EvidencePack:
    run_id: str
    cve_id: str
    document: Mapping[str, Any]
    references: frozenset[str]
    full_compatible_payloads: frozenset[str]
    full_module_options: frozenset[str] = frozenset()
    full_payload_options: frozenset[str] = frozenset()

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.document, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class GuidanceOutcome:
    cve_id: str
    evidence_pack: EvidencePack
    provider_status: str
    provider: str | None = None
    model: str | None = None
    elapsed_seconds: float | None = None
    raw_proposal: Mapping[str, Any] | None = None
    validation_state: ProposalValidationState = ProposalValidationState.INSUFFICIENT_EVIDENCE
    accepted: Mapping[str, Any] = None  # type: ignore[assignment]
    issues: tuple[str, ...] = ()

    def __post_init__(self):
        if self.accepted is None:
            object.__setattr__(self, "accepted", {})

    def to_dict(self) -> dict[str, Any]:
        return {"cve_id": self.cve_id,
                "evidence_pack": dict(self.evidence_pack.document),
                "evidence_pack_sha256": self.evidence_pack.sha256,
                "provider_status": self.provider_status, "provider": self.provider,
                "model": self.model, "elapsed_seconds": self.elapsed_seconds,
                "proposal": dict(self.raw_proposal) if self.raw_proposal else None,
                "validation_state": self.validation_state.value,
                "accepted_suggestions": dict(self.accepted), "issues": list(self.issues)}
