"""Knowledge-aware adapter for the existing remediation provider contract."""
from __future__ import annotations
from dataclasses import replace
from typing import Any, Mapping, Sequence
from .models import FixType, PatchStrategy, RemediationCandidate
from ..knowledge import retrieve_compatible

class KnowledgeRemediationProvider:
    def __init__(self, deterministic, store):
        self.deterministic, self.store = deterministic, store

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]], target_facts=None):
        base = self.deterministic.candidate(package_name=package_name, ecosystem=ecosystem,
            installed_versions=installed_versions, scanner_fixed_versions=scanner_fixed_versions,
            occurrences=occurrences, target_facts=target_facts)
        first = next((x for x in occurrences if isinstance(x, Mapping)), None)
        cve = str(first.get("canonical_cve_id") or "") if first else ""
        component = (first.get("package_purl") or first.get("package_name")) if first else None
        if not cve or not component:
            return base
        context = {"package_purl": first.get("package_purl"), "package_name": first.get("package_name"),
                   "ecosystem": first.get("result_type"), "installed_version": first.get("installed_version")}
        records = retrieve_compatible(self.store, cve_id=cve, component=str(component), kind="remediation", context=context)
        if not records:
            return base
        record = records[0]
        values = record.fields
        # deterministic values always win; knowledge fills only blanks.
        if base is None:
            base = RemediationCandidate()
        def enum(value, cls):
            return cls(value) if isinstance(value, str) and value in {x.value for x in cls} else None
        updates = {
            "target_version": base.target_version or values.get("target_version"),
            "fix_type": base.fix_type or enum(values.get("fix_type"), FixType),
            "strategy": base.strategy or enum(values.get("strategy"), PatchStrategy),
            "source_type": base.source_type or values.get("source_type"),
            "source_authority": base.source_authority or values.get("source_authority"),
            "source_identifier": base.source_identifier or values.get("source_identifier"),
            "source_url": base.source_url or values.get("source_url"),
            "checksum": base.checksum or values.get("checksum"),
            "same_branch": base.same_branch if base.same_branch is not None else values.get("same_branch"),
            "build_system": base.build_system or values.get("build_system"),
        }
        evidence = tuple(base.evidence) + ({"source": "knowledge", "record_id": record.record_id,
            "origin_run_id": record.run_id, "evidence": dict(record.evidence)},)
        return replace(base, **updates, evidence=evidence)
