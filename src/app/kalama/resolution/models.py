"""Step 4 result contracts; no exploit outcome states exist here."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from resolver_config_models import ConfigValidationResult, ExploitConfig
from resolver_models import CandidateRankingResult, DiscoveryResult


class ResolverCVEStatus(str, Enum):
    READY_TO_EXECUTE = "READY_TO_EXECUTE"
    WAITING_FOR_USER_INPUT = "WAITING_FOR_USER_INPUT"
    NO_MSF_MODULE = "NO_MSF_MODULE"
    UNRESOLVED_CONFIG = "UNRESOLVED_CONFIG"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    USER_SKIPPED = "USER_SKIPPED"


@dataclass(frozen=True)
class RankedCVEInput:
    rank: int
    cve_id: str
    occurrences: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ResolverCVEResult:
    input: RankedCVEInput
    status: ResolverCVEStatus
    discovery: DiscoveryResult | None
    ranking: CandidateRankingResult | None
    exploit_config: ExploitConfig | None
    validation: ConfigValidationResult | None
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.input.rank, "cve_id": self.input.cve_id,
            "status": self.status.value,
            "prioritization": {"occurrences": list(self.input.occurrences)},
            "discovery": self.discovery.to_dict() if self.discovery else None,
            "ranking": self.ranking.to_dict() if self.ranking else None,
            "exploit_config": self.exploit_config.to_dict() if self.exploit_config else None,
            "validation": self.validation.to_dict() if self.validation else None,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class Step4Analysis:
    cves: tuple[ResolverCVEResult, ...]

    @property
    def needs_form(self) -> bool:
        return any(x.status == ResolverCVEStatus.WAITING_FOR_USER_INPUT for x in self.cves)

    def summary(self) -> dict[str, int]:
        values = {"selected_count": len(self.cves)}
        for status in ResolverCVEStatus:
            values[status.value.lower()] = sum(x.status == status for x in self.cves)
        return values
