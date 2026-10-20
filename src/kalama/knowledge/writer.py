"""Validated-only write helpers used after evidence evaluation."""
from __future__ import annotations
from typing import Mapping
from .models import KnowledgeRecord, TrustState

def validated_attack_record(*, cve_id: str, occurrence: Mapping, config: Mapping,
                            run_id: str, evidence: Mapping) -> KnowledgeRecord | None:
    if not occurrence.get("package_purl") and not occurrence.get("package_name"):
        return None
    component = str(occurrence.get("package_purl") or occurrence.get("package_name"))
    fields = {k: config.get(k) for k in ("module", "targeturi", "rport", "payload") if config.get(k) is not None}
    if not fields: return None
    context = {k: occurrence.get(k) for k in ("package_purl", "package_name", "result_type", "installed_version")}
    return KnowledgeRecord(cve_id, component, context, "attack_config", fields, TrustState.VALIDATED, run_id, dict(evidence))

def validated_remediation_record(*, cve_id: str, occurrence: Mapping, action: Mapping,
                                 run_id: str, evidence: Mapping) -> KnowledgeRecord | None:
    component = occurrence.get("package_purl") or occurrence.get("package_name")
    candidate = action.get("candidate") if isinstance(action.get("candidate"), Mapping) else {}
    if not component or not candidate or cve_id not in (action.get("target_cves") or ()):
        return None
    fields = {key: candidate.get(key) for key in ("target_version", "fix_type", "strategy",
              "source_type", "source_authority", "source_identifier", "source_url", "checksum",
              "same_branch", "build_system") if candidate.get(key) is not None}
    if not fields:
        return None
    context = {"package_purl": occurrence.get("package_purl"), "package_name": occurrence.get("package_name"),
               "ecosystem": occurrence.get("result_type"), "installed_version": occurrence.get("installed_version")}
    return KnowledgeRecord(cve_id, str(component), context, "remediation", fields,
                           TrustState.VALIDATED, run_id, dict(evidence))
