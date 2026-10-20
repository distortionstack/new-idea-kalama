"""Deterministic, failure-isolating collection of existing evidence."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from .models import EvidencePack, EvidenceResult, EvidenceResultState, FieldRequest, SourceKind
from .policy import SourcePolicy

@dataclass(frozen=True)
class Collection:
    pack: EvidencePack
    results: tuple[EvidenceResult, ...]

class EvidenceCollector:
    def __init__(self, policy: SourcePolicy, sources: Mapping[SourceKind, object]):
        self.policy, self.sources = policy, dict(sources)
    def collect(self, request: FieldRequest) -> Collection:
        selected = []
        for field in request.unresolved_fields:
            for kind in self.policy.ordered_sources(request, field):
                if kind not in selected: selected.append(kind)
        results = []
        for kind in selected:
            source = self.sources.get(kind)
            if source is None:
                results.append(EvidenceResult(EvidenceResultState.NOT_APPLICABLE, kind, detail="adapter not configured")); continue
            try: results.append(source.collect(request))
            except Exception as exc: results.append(EvidenceResult(EvidenceResultState.UNAVAILABLE, kind, detail=f"{type(exc).__name__}: {str(exc)[:300]}"))
        items = tuple(item for result in results if result.state in {EvidenceResultState.AVAILABLE, EvidenceResultState.STALE_CACHE_FALLBACK} for item in result.items)
        return Collection(EvidencePack(request, items), tuple(results))
