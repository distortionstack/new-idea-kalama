"""Pure scoped vs global remediation evidence for Step 8 evaluation.

ScopedRemediationEvidence judges the executed PatchAction (the specific
deployment that was exploited BEFORE). GlobalAfterEvidence preserves the
image-wide residual risk separately.

No scanner, prioritizer, resolver, attack-form, patch-execution, retry, or
exploit-oracle semantics live here. This module only reinterprets already
committed Step 6 / Step 7 artifacts for evaluation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping


class ScopedScannerStatus(str, Enum):
    SCOPED_NOT_FOUND = "SCOPED_NOT_FOUND"
    SCOPED_PRESENT = "SCOPED_PRESENT"
    SCOPED_MAPPING_UNKNOWN = "SCOPED_MAPPING_UNKNOWN"


class ScopedFinalStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"


def _occurrence_key(item: Mapping[str, Any]) -> str | None:
    """Stable identity for a scanner occurrence.

    Prefer package_uid (per-file instance) when present, else fall back to
    package_purl + target + result_type. Return None when unmappable.
    """
    uid = item.get("package_uid")
    if isinstance(uid, str) and uid:
        return f"uid:{uid}"
    purl = item.get("package_purl") or item.get("package_name")
    if isinstance(purl, str) and purl:
        target = str(item.get("target") or "")
        result_type = str(item.get("result_type") or "")
        installed = str(item.get("installed_version") or "")
        return f"purl:{purl}|{target}|{result_type}|{installed}"
    return None


def derive_scoped_status(
    scan_entry: Mapping[str, Any] | None,
    *,
    patch_action_status: str | None,
    patch_disposition: str | None = None,
) -> dict[str, Any]:
    """Derive scoped scanner status from an already-committed scan entry.

    scan_entry is one element of REMEDIATION_SCAN_RESULT intended_targets.
    It contains scanner_status (global), before_occurrences, after_occurrences.
    """
    if scan_entry is None:
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
            "reason": "SCAN_ENTRY_ABSENT",
            "same_cve_found_elsewhere": False,
        }
    global_status = scan_entry.get("scanner_status")
    before = scan_entry.get("before_occurrences") or []
    after = scan_entry.get("after_occurrences") or []
    if global_status == "NOT_FOUND":
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_NOT_FOUND.value,
            "reason": "GLOBAL_NOT_FOUND_IMPLIES_SCOPED_CLEAN",
            "same_cve_found_elsewhere": False,
        }
    if global_status == "UNKNOWN":
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
            "reason": "GLOBAL_UNKNOWN",
            "same_cve_found_elsewhere": False,
        }
    if global_status != "FOUND":
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
            "reason": "GLOBAL_STATUS_UNRECOGNIZED",
            "same_cve_found_elsewhere": False,
        }
    # Global FOUND: determine whether the executed target is clean while
    # the same CVE persists elsewhere.
    if not isinstance(before, list) or not before:
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
            "reason": "BEFORE_OCCURRENCES_UNMAPPABLE",
            "same_cve_found_elsewhere": True,
        }
    before_keys = set()
    for item in before:
        if not isinstance(item, Mapping):
            continue
        key = _occurrence_key(item)
        if key is None:
            return {
                "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
                "reason": "BEFORE_OCCURRENCE_UNMAPPABLE",
                "same_cve_found_elsewhere": True,
            }
        before_keys.add(key)
    if not before_keys:
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
            "reason": "BEFORE_OCCURRENCES_UNMAPPABLE",
            "same_cve_found_elsewhere": True,
        }
    after_keys = set()
    for item in after:
        if not isinstance(item, Mapping):
            continue
        key = _occurrence_key(item)
        if key is None:
            return {
                "scoped_status": ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value,
                "reason": "AFTER_OCCURRENCE_UNMAPPABLE",
                "same_cve_found_elsewhere": True,
            }
        after_keys.add(key)
    removed = before_keys - after_keys
    if patch_action_status == "SUCCEEDED" and removed:
        # The executed target lost at least one vulnerable instance while
        # the same CVE persists elsewhere in the image.
        return {
            "scoped_status": ScopedScannerStatus.SCOPED_NOT_FOUND.value,
            "reason": "PATCHED_INSTANCES_REMOVED_WHILE_CVE_PERSISTS_ELSEWHERE",
            "same_cve_found_elsewhere": True,
            "removed_occurrences": len(removed),
            "before_occurrences": len(before_keys),
            "after_occurrences": len(after_keys),
        }
    # Patch did not remove any mapped instance, or patch did not succeed.
    return {
        "scoped_status": ScopedScannerStatus.SCOPED_PRESENT.value,
        "reason": "NO_MAPPED_INSTANCE_REMOVED",
        "same_cve_found_elsewhere": True,
        "removed_occurrences": len(removed),
        "before_occurrences": len(before_keys),
        "after_occurrences": len(after_keys),
    }


def derive_global_evidence(scan_entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Preserve image-wide residual risk separately from scoped judgment."""
    status = (scan_entry or {}).get("scanner_status")
    if status == "FOUND":
        return {"global_status": "FOUND", "residual_risk": True}
    if status == "UNKNOWN":
        return {"global_status": "UNKNOWN", "residual_risk": True}
    if status == "NOT_FOUND":
        return {"global_status": "NOT_FOUND", "residual_risk": False}
    return {"global_status": "UNKNOWN", "residual_risk": True}


_VALID_NEGATIVE_DISPOSITIONS = {"EXPLOIT_FAILED"}
_VALID_NEGATIVE_ORACLES = {"NOT_VULNERABLE"}
_POSITIVE_DISPOSITIONS = {"EXPLOIT_SUCCEEDED"}
_POSITIVE_ORACLES = {"VULNERABLE"}


def classify_scoped_remediation(
    *,
    cve_id: str,
    before_disposition: str | None,
    patch_status: str | None,
    patch_disposition: str | None = None,
    scoped_status: str | None,
    global_status: str | None = None,
    same_cve_found_elsewhere: bool = False,
    after_disposition: str | None,
    after_oracle: str | None,
    metric_eligible: bool,
    comparable: bool,
) -> dict[str, Any]:
    """Final scoped evaluation for one CVE.

    Rules (in order):
    - BEFORE != EXPLOIT_SUCCEEDED -> NOT_EVALUATED
    - SKIP_OUT_OF_SCOPE -> NOT_EVALUATED + residual visible
    - patch != SUCCEEDED or not comparable -> INCONCLUSIVE
    - SCOPED_MAPPING_UNKNOWN -> INCONCLUSIVE
    - reproduced attributable AFTER (SUCCEEDED+VULNERABLE+eligible) -> FAILED
    - AFTER env/backend failure (non-eligible or non-binary) -> INCONCLUSIVE
      even if scoped clean
    - SCOPED_PRESENT -> must not validate -> INCONCLUSIVE (when AFTER negative)
    - SCOPED_NOT_FOUND + valid negative AFTER -> VERIFIED (validated true)
      even when global FOUND elsewhere (residual true)
    """
    global_residual = (global_status in {"FOUND", "UNKNOWN"}) or same_cve_found_elsewhere
    if patch_disposition == "SKIP_OUT_OF_SCOPE":
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.NOT_EVALUATED.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "SKIP_OUT_OF_SCOPE_NOT_EVALUATED",
        }
    if before_disposition != "EXPLOIT_SUCCEEDED":
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.NOT_EVALUATED.value,
            "remediation_validated": False,
            "residual_risk": bool(global_residual),
            "reason": "BEFORE_NOT_EXPLOIT_SUCCEEDED",
        }
    if patch_status != "SUCCEEDED" or not comparable:
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.INCONCLUSIVE.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "PATCH_NOT_SUCCEEDED_OR_INCOMPARABLE",
        }
    if scoped_status == ScopedScannerStatus.SCOPED_MAPPING_UNKNOWN.value:
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.INCONCLUSIVE.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "SCOPED_MAPPING_UNKNOWN",
        }
    # Reproduced attributable impact AFTER invalidates remediation.
    if (
        after_disposition in _POSITIVE_DISPOSITIONS
        and after_oracle in _POSITIVE_ORACLES
        and metric_eligible
    ):
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.FAILED.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "AFTER_REPRODUCED_ATTRIBUTABLE_IMPACT",
        }
    # AFTER env/backend failure remains INCONCLUSIVE even if scoped clean.
    # Valid negative requires binary eligible negative with comparable config.
    is_valid_negative = (
        after_disposition in _VALID_NEGATIVE_DISPOSITIONS
        and after_oracle in _VALID_NEGATIVE_ORACLES
        and metric_eligible
        and comparable
    )
    if not is_valid_negative:
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.INCONCLUSIVE.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "AFTER_NOT_VALID_NEGATIVE",
        }
    if scoped_status == ScopedScannerStatus.SCOPED_PRESENT.value:
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.INCONCLUSIVE.value,
            "remediation_validated": False,
            "residual_risk": True,
            "reason": "SCOPED_PRESENT_MUST_NOT_VALIDATE",
        }
    if scoped_status == ScopedScannerStatus.SCOPED_NOT_FOUND.value:
        return {
            "cve_id": cve_id,
            "before_disposition": before_disposition,
            "patch_status": patch_status,
            "patch_disposition": patch_disposition,
            "scoped_status": scoped_status,
            "global_status": global_status,
            "same_cve_found_elsewhere": same_cve_found_elsewhere,
            "after_disposition": after_disposition,
            "after_oracle": after_oracle,
            "metric_eligible": metric_eligible,
            "comparable": comparable,
            "final_status": ScopedFinalStatus.VERIFIED.value,
            "remediation_validated": True,
            "residual_risk": bool(global_residual),
            "reason": "SCOPED_NOT_FOUND_WITH_VALID_NEGATIVE_REEXPLOIT",
        }
    return {
        "cve_id": cve_id,
        "before_disposition": before_disposition,
        "patch_status": patch_status,
        "patch_disposition": patch_disposition,
        "scoped_status": scoped_status,
        "global_status": global_status,
        "same_cve_found_elsewhere": same_cve_found_elsewhere,
        "after_disposition": after_disposition,
        "after_oracle": after_oracle,
        "metric_eligible": metric_eligible,
        "comparable": comparable,
        "final_status": ScopedFinalStatus.INCONCLUSIVE.value,
        "remediation_validated": False,
        "residual_risk": True,
        "reason": "UNRECOGNIZED_SCOPED_STATUS",
    }
