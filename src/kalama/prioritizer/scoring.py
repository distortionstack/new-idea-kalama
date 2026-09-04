"""Pure Decimal scoring and deterministic ranking."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Sequence

from .models import EnrichedCVE, EvidenceState, KEVState, PrioritizedCVE, ScoreBreakdown


EPSS_WEIGHT = Decimal("3")
KEV_BONUS = Decimal("3")
SCORE_MODEL = "kalama-priority-v1"


def score_cve(cvss: Decimal, epss: Decimal, kev_listed: bool) -> ScoreBreakdown:
    if not cvss.is_finite() or not Decimal("0") <= cvss <= Decimal("10"):
        raise ValueError("CVSS must be between 0 and 10")
    if not epss.is_finite() or not Decimal("0") <= epss <= Decimal("1"):
        raise ValueError("EPSS must be between 0 and 1")
    epss_contribution = epss * EPSS_WEIGHT
    kev_contribution = KEV_BONUS if kev_listed else Decimal("0")
    total = cvss + epss_contribution + kev_contribution
    return ScoreBreakdown(cvss, epss, epss_contribution, kev_listed,
                          kev_contribution, total,
                          total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def rank_cves(enriched: Sequence[EnrichedCVE], top_n: int = 30) -> tuple[PrioritizedCVE, ...]:
    if top_n < 0:
        raise ValueError("top_n must be non-negative")
    scored = []
    for item in enriched:
        if item.cvss.state != EvidenceState.AVAILABLE or item.cvss.score is None:
            raise ValueError(f"{item.aggregate.cve_id}: CVSS incomplete")
        if item.epss.state != EvidenceState.AVAILABLE or item.epss.score is None:
            raise ValueError(f"{item.aggregate.cve_id}: EPSS incomplete")
        if item.kev.state not in (KEVState.LISTED, KEVState.NOT_LISTED):
            raise ValueError(f"{item.aggregate.cve_id}: KEV incomplete")
        breakdown = score_cve(item.cvss.score, item.epss.score,
                              item.kev.state == KEVState.LISTED)
        scored.append((item, breakdown))
    scored.sort(key=lambda pair: (
        -pair[1].total_raw,
        0 if pair[0].kev.state == KEVState.LISTED else 1,
        -pair[0].epss.score,
        -pair[0].cvss.score,
        pair[0].aggregate.cve_id,
    ))
    return tuple(PrioritizedCVE(rank, item, breakdown)
                 for rank, (item, breakdown) in enumerate(scored[:top_n], start=1))
