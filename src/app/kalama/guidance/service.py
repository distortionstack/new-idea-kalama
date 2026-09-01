from __future__ import annotations

from typing import Any, Mapping, Protocol

from ..resolution.models import Step4Analysis
from .evidence import build_evidence_pack
from .models import GuidanceOutcome, ProposalValidationState
from .validator import validate_proposal


class GuidanceProvider(Protocol):
    name: str
    config: Any
    def propose(self, evidence: Mapping[str, Any], evidence_sha256: str): ...


class GuidanceService:
    def __init__(self, provider: GuidanceProvider | None, *, cve_ids: frozenset[str] | None = None):
        self.provider, self.cve_ids = provider, cve_ids

    def guide(self, run_id: str, analysis: Step4Analysis,
              target: Mapping[str, Any]) -> tuple[GuidanceOutcome, ...]:
        outcomes = []
        for item in analysis.cves:
            if self.cve_ids is not None and item.input.cve_id not in self.cve_ids:
                continue
            pack = build_evidence_pack(run_id, item, target)
            if pack is None: continue
            if self.provider is None:
                outcomes.append(GuidanceOutcome(item.input.cve_id, pack, "DISABLED"))
                continue
            try:
                proposal, elapsed = self.provider.propose(pack.document, pack.sha256)
                state, accepted, issues = validate_proposal(pack, proposal)
                outcomes.append(GuidanceOutcome(
                    item.input.cve_id, pack, "AVAILABLE", self.provider.name,
                    getattr(self.provider.config, "model", None), elapsed, proposal,
                    state, accepted, issues))
            except Exception as exc:
                outcomes.append(GuidanceOutcome(
                    item.input.cve_id, pack, "UNAVAILABLE", self.provider.name,
                    getattr(self.provider.config, "model", None), issues=(
                        f"{type(exc).__name__}: {str(exc)[:500]}",)))
        return tuple(outcomes)
