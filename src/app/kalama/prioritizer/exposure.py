"""Target-level contextual exposure interpretation; never performs probes."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .models import ExposureContext, ExposureState


KNOWN_EVIDENCE = {
    "container_running", "published_port", "listening_port", "tcp_reachable",
    "http_response", "tls_handshake",
}


def exposure_from_facts(facts: Mapping[str, Any] | None) -> ExposureContext:
    if facts is None:
        return ExposureContext()
    observations = facts.get("observations", [])
    if not isinstance(observations, list):
        return ExposureContext(ExposureState.UNKNOWN)
    evidence = tuple(sorted(
        (dict(item) for item in observations
         if isinstance(item, Mapping) and item.get("kind") in KNOWN_EVIDENCE),
        key=lambda item: json.dumps(item, sort_keys=True, default=str),
    ))
    collection_complete = facts.get("collection_complete") is True
    if evidence and collection_complete:
        state = ExposureState.OBSERVED
    elif evidence:
        state = ExposureState.PARTIAL
    elif collection_complete:
        state = ExposureState.NOT_OBSERVED
    else:
        state = ExposureState.UNKNOWN
    return ExposureContext(state, evidence)
