"""Pure evidence-dataset construction and methodologically explicit metrics."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence


TOP_N_ONLY = "TOP_N_ONLY"
FULL_EMPIRICAL_UNIVERSE = "FULL_EMPIRICAL_UNIVERSE"


def _unique(items: Sequence[Mapping[str, Any]], name: str) -> dict[str, Mapping[str, Any]]:
    output = {}
    for item in items:
        cve = item.get("cve_id")
        if not isinstance(cve, str) or cve in output:
            raise ValueError(f"{name} has missing or duplicate CVE identity")
        output[cve] = item
    return output


def build_evaluation_records(top: Mapping[str, Any], attack: Mapping[str, Any],
                             remediation: Mapping[str, Any]) -> list[dict[str, Any]]:
    ranked = top.get("ranked_cves")
    attacks, remediations = attack.get("cves"), remediation.get("cves")
    if not isinstance(ranked, list) or not isinstance(attacks, list) or not isinstance(remediations, list):
        raise ValueError("evaluation inputs must contain CVE arrays")
    attack_by_cve = _unique(attacks, "ATTACK_BEFORE")
    remediation_by_cve = _unique(remediations, "REMEDIATION_RESULT")
    ranked_by_cve = _unique(ranked, "TOP30_BEFORE")
    if set(attack_by_cve) != set(ranked_by_cve):
        raise ValueError("ATTACK_BEFORE does not represent the selected Top N exactly")
    if not set(remediation_by_cve).issubset(ranked_by_cve):
        raise ValueError("REMEDIATION_RESULT contains a CVE outside the selected Top N")
    remediation_counts = Counter((item.get("final") or {}).get("status")
                                 for item in remediations)
    remediation_summary = remediation.get("summary") or {}
    if (remediation_summary.get("targets") != len(remediations)
            or any(remediation_summary.get(status.casefold()) != remediation_counts[status]
                   for status in ("VERIFIED", "FAILED", "INCONCLUSIVE", "NOT_EVALUATED"))):
        raise ValueError("REMEDIATION_RESULT summary is inconsistent")
    records = []
    for item in sorted(ranked, key=lambda value: (value.get("rank", 10**9), value.get("cve_id", ""))):
        cve, rank = item["cve_id"], item.get("rank")
        attack_item = attack_by_cve[cve]
        if attack_item.get("rank") != rank:
            raise ValueError(f"rank mismatch for {cve}")
        eligibility = attack_item.get("metric_eligibility") or {}
        eligible = bool(eligibility.get("eligible"))
        disposition = attack_item.get("disposition")
        actual = (True if eligible and disposition == "EXPLOIT_SUCCEEDED" else
                  False if eligible and disposition == "EXPLOIT_FAILED" else None)
        if eligible and actual is None:
            raise ValueError(f"metric-eligible {cve} has no binary disposition")
        exclusion = None if eligible else (eligibility.get("exclusion_reason") or disposition
                                             or attack_item.get("config_status") or "UNKNOWN")
        confusion = "TP" if actual is True else "FP" if actual is False else None
        score = item.get("score") or {}
        components = score.get("components") or {}
        rem = remediation_by_cve.get(cve) or {}
        records.append({"cve_id": cve,
            "prediction": {"in_candidate_universe": True, "selected_top_n": True,
                "rank": rank, "score": score.get("total_display"),
                "score_model": score.get("model"), "cvss": components.get("cvss"),
                "epss": components.get("epss"), "kev": components.get("kev")},
            "empirical_before": {"disposition": disposition,
                "oracle": (attack_item.get("oracle") or {}).get("verdict"),
                "evidence_basis": (attack_item.get("oracle") or {}).get("evidence_basis"),
                "metric_eligible": eligible},
            "binary_evaluation": {"eligible": eligible, "predicted_positive": True,
                "actual_positive": actual, "confusion_class": confusion},
            "exclusion_reason": exclusion,
            "metasploit": {"module_available": attack_item.get("config_status") != "NO_MSF_MODULE"},
            "remediation": {"after_scan_status": (rem.get("after_scan") or {}).get("status"),
                "after_exploit_disposition": (rem.get("after_exploit") or {}).get("disposition"),
                "final_remediation_status": (rem.get("final") or {}).get("status")}})
    return records


def _metric(value: float | None, *, reason: str | None = None,
            name: str | None = None) -> dict[str, Any]:
    result = {"available": value is not None, "value": value}
    if name: result["name"] = name
    if reason: result["reason"] = reason
    return result


def compute_metrics(dataset: Mapping[str, Any]) -> dict[str, Any]:
    records = dataset.get("records")
    scope = dataset.get("evaluation_universe", {}).get("scope")
    if not isinstance(records, list) or scope not in {TOP_N_ONLY, FULL_EMPIRICAL_UNIVERSE}:
        raise ValueError("invalid canonical evaluation dataset")
    eligible = [item for item in records if item["binary_evaluation"]["eligible"]]
    classes = Counter(item["binary_evaluation"]["confusion_class"] for item in eligible)
    tp, fp = classes["TP"], classes["FP"]
    fn = classes["FN"] if scope == FULL_EMPIRICAL_UNIVERSE else None
    tn = classes["TN"] if scope == FULL_EMPIRICAL_UNIVERSE else None
    positive_denominator = tp + fp
    precision_value = tp / positive_denominator if positive_denominator else None
    precision = _metric(precision_value,
        reason=None if precision_value is not None else "ZERO_ELIGIBLE_POSITIVE_PREDICTIONS",
        name=f"Precision@{dataset['prediction']['top_n_returned']}")
    if scope == FULL_EMPIRICAL_UNIVERSE:
        recall_denominator = tp + (fn or 0)
        recall_value = tp / recall_denominator if recall_denominator else None
        recall = _metric(recall_value,
            reason=None if recall_value is not None else "ZERO_EMPIRICAL_POSITIVES")
    else:
        recall = _metric(None, reason="PREDICTED_NEGATIVES_NOT_EMPIRICALLY_EVALUATED")
    if precision["available"] and recall["available"]:
        p, r = precision["value"], recall["value"]
        f1 = _metric(0.0 if p + r == 0 else 2 * p * r / (p + r))
    else:
        f1 = _metric(None, reason="RECALL_UNAVAILABLE" if not recall["available"]
                     else "PRECISION_UNAVAILABLE")
    if None not in (fn, tn):
        total = tp + fp + fn + tn
        accuracy = _metric((tp + tn) / total if total else None,
                           reason=None if total else "ZERO_ELIGIBLE_UNIVERSE")
    else:
        accuracy = _metric(None, reason="INCOMPLETE_CONFUSION_MATRIX")
    selected = [item for item in records if item["prediction"]["selected_top_n"]]
    selected_eligible = [item for item in selected if item["binary_evaluation"]["eligible"]]
    exclusions = Counter(item["exclusion_reason"] for item in records
                         if not item["binary_evaluation"]["eligible"])
    empirically_tested = sum(item["empirical_before"]["disposition"] in
                             {"EXPLOIT_SUCCEEDED", "EXPLOIT_FAILED"} for item in records)
    module_available = sum(item["metasploit"]["module_available"] for item in records)
    remediation_counts = Counter(item["remediation"]["final_remediation_status"]
                                 for item in records
                                 if item["remediation"]["final_remediation_status"])
    remediation_targets = sum(remediation_counts.values())
    evaluable = remediation_counts["VERIFIED"] + remediation_counts["FAILED"]
    remediation_rate = _metric(remediation_counts["VERIFIED"] / evaluable if evaluable else None,
        reason=None if evaluable else "NO_EVALUABLE_REMEDIATION_TARGETS")
    remediation_coverage = (evaluable / remediation_targets if remediation_targets else None)
    cross = Counter()
    for item in records:
        scan, final = (item["remediation"]["after_scan_status"],
                       item["remediation"]["final_remediation_status"])
        if scan and final: cross[f"{scan}+{final}"] += 1
    top_n = dataset["prediction"]
    if tp + fp != len(selected_eligible):
        raise ValueError("TP + FP does not equal eligible selected records")
    if len(selected_eligible) + (len(selected) - len(selected_eligible)) != len(selected):
        raise ValueError("selected coverage counts are inconsistent")
    if scope == FULL_EMPIRICAL_UNIVERSE and tp + fp + fn + tn != len(eligible):
        raise ValueError("full confusion matrix is inconsistent")
    return {"prioritization": {"scope": scope,
            "top_n_requested": top_n["top_n_requested"],
            "top_n_returned": top_n["top_n_returned"],
            "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy},
        "coverage": {"candidate_universe_total": dataset["evaluation_universe"].get("candidate_universe_total"),
            "candidate_universe_available": dataset["evaluation_universe"].get("candidate_universe_available"),
            "selected_total": len(selected), "empirically_tested_total": empirically_tested,
            "binary_metric_eligible_total": len(eligible),
            "selected_binary_metric_eligible": len(selected_eligible),
            "excluded_total": len(records) - len(eligible),
            "selected_empirical_coverage": len(selected_eligible) / len(selected) if selected else None},
        "exclusions": dict(sorted((str(key), value) for key, value in exclusions.items())),
        "metasploit_coverage": {"msf_module_available": module_available,
                                "no_msf_module": len(records) - module_available},
        "remediation": {"targets": remediation_targets,
            "verified": remediation_counts["VERIFIED"], "failed": remediation_counts["FAILED"],
            "inconclusive": remediation_counts["INCONCLUSIVE"],
            "not_evaluated": remediation_counts["NOT_EVALUATED"],
            "empirical_success_rate": remediation_rate,
            "evaluation_coverage": remediation_coverage,
            "scanner_empirical_cross_tab": dict(sorted(cross.items()))}}
