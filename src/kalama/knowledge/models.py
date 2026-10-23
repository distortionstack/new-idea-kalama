from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

class TrustState(str, Enum):
    LAB_VALIDATED = "LAB_VALIDATED"
    OBSERVED = "OBSERVED"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    VALIDATED = "VALIDATED"
    REVOKED = "REVOKED"

@dataclass(frozen=True)
class KnowledgeRecord:
    cve_id: str
    component: str
    context: Mapping[str, Any]
    kind: str
    fields: Mapping[str, Any]
    trust: TrustState
    run_id: str
    evidence: Mapping[str, Any]
    record_id: int | None = None
