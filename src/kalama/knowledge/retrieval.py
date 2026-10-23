from __future__ import annotations
from typing import Any, Mapping
from .models import KnowledgeRecord, TrustState

CONTEXT_KEYS = ("package_purl", "package_name", "ecosystem", "installed_version", "application_path", "image_family")
def compatible(record: KnowledgeRecord, context: Mapping[str, Any]) -> bool:
    # Every known record constraint must match; absent request facts never widen reuse.
    return all(not record.context.get(k) or (context.get(k) and record.context.get(k) == context.get(k)) for k in CONTEXT_KEYS)
def retrieve_compatible(store, *, cve_id: str, component: str, kind: str, context: Mapping[str, Any]):
    return tuple(x for x in store.candidates(cve_id, component, kind) if compatible(x, context))

def retrieve_related(store, *, cve_id: str, component_names: tuple[str, ...], kind: str):
    """Return lab knowledge for review, without claiming compatibility."""
    found = []
    for name in component_names:
        # System-validated records remain governed by exact compatibility;
        # only repository Lab Notes are surfaced as mismatch guidance.
        found.extend(store.candidates(cve_id, name, kind, trusts=(TrustState.LAB_VALIDATED,)))
    return tuple(found)
