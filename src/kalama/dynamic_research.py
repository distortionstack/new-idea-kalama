"""Wave 4A research export: BEFORE-phase dynamic-shadow evidence vs exploit ground truth.

Read-only measurement preparation. This module never modifies pipeline
state, scores, rankings, or dispositions; it assembles one research row
per Top-N candidate CVE per run from immutable artifacts:

    priority-v1 Top-N committed
      -> Nuclei dynamic shadow evidence
      -> BEFORE exploit disposition (ATTACK_BEFORE)

Temporal order (Top-N, then shadow, then exploit) is recorded from
artifact timestamps and reported as a boolean; BEFORE-phase only, AFTER
evidence is never consumed. No conclusions are drawn here: counts,
coverage, cross-tabs, and descriptive conditional proportions only.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from .state import ArtifactKind, StateStore


RESEARCH_SCHEMA = "kalama.dynamic-research/v1"

TOP30_SCHEMA = "kalama.prioritization/v1"
SHADOW_SCHEMA = "kalama.dynamic-shadow/v1"
ATTACK_SCHEMA = "kalama.attack-result/v1"

DYNAMIC_PROVIDER = "nuclei"
DYNAMIC_PROFILE = "safe-cve-http"

# Scope labels so later analysis can stratify path-sensitive observations.
SCOPE_NONE = "none"
SCOPE_MULTI_PATH = "v2-multi-path"
SCOPE_ROOT_ONLY = "v2-root-only"
SCOPE_ROOT_ONLY_LEGACY = "v1-root-only-legacy"


class ResearchExportError(RuntimeError):
    """Structured research-export failure with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Integrity helpers (read-only)
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path, *, what: str) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ResearchExportError("RESEARCH_ARTIFACT_UNREADABLE",
                                  f"cannot read {what} at {path}: {exc}") from exc


def _parse_instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Source collection (read-only; never writes pipeline state)
# ---------------------------------------------------------------------------

def collect_run_sources(output_root: Path | str, run_id: str) -> dict[str, Any]:
    """Locate and integrity-check a run's research inputs.

    TOP30_BEFORE is required. DYNAMIC_SHADOW_BEFORE and ATTACK_BEFORE are
    optional and represented honestly when absent. Any hash mismatch, wrong
    schema, or wrong-run artifact aborts the export fail-closed.
    """
    store = StateStore(Path(output_root))
    try:
        state = store.load(run_id)
    except Exception as exc:
        raise ResearchExportError("RESEARCH_RUN_NOT_FOUND",
                                  f"cannot load run {run_id}: {exc}") from exc
    sources: dict[str, Any] = {"run_id": run_id, "state": state,
                               "top30": None, "shadow": None, "attack": None}

    def _load(key: str, kind: ArtifactKind, *, required: bool, schema: str) -> None:
        ref = state.artifact(kind)
        if ref is None:
            if required:
                raise ResearchExportError("RESEARCH_SOURCE_MISSING",
                                          f"run {run_id} has no {kind.value} artifact")
            return
        path = Path(ref.path)
        if not path.is_file():
            raise ResearchExportError("RESEARCH_ARTIFACT_UNREADABLE",
                                      f"{kind.value} path is missing: {path}")
        actual = sha256_file(path)
        if actual != ref.sha256:
            raise ResearchExportError("RESEARCH_ARTIFACT_TAMPERED",
                                      f"{kind.value} hash mismatch for run {run_id}")
        document = _read_json(path, what=kind.value)
        if not isinstance(document, Mapping) or document.get("schema") != schema:
            raise ResearchExportError("RESEARCH_ARTIFACT_INVALID",
                                      f"{kind.value} has an incompatible schema")
        artifact = document.get("artifact") if isinstance(
            document.get("artifact"), Mapping) else {}
        artifact_run = artifact.get("run_id")
        if artifact_run is not None and artifact_run != run_id:
            raise ResearchExportError("RESEARCH_WRONG_RUN",
                                      f"{kind.value} belongs to run {artifact_run}, "
                                      f"not {run_id}")
        sources[key] = {
            "path": str(path), "sha256": actual,
            "created_at": ref.created_at, "document": document}

    _load("top30", ArtifactKind.TOP30_BEFORE, required=True, schema=TOP30_SCHEMA)
    _load("shadow", ArtifactKind.DYNAMIC_SHADOW_BEFORE, required=False,
          schema=SHADOW_SCHEMA)
    _load("attack", ArtifactKind.ATTACK_BEFORE, required=False, schema=ATTACK_SCHEMA)
    return sources


def load_dynamic_result_records(output_root: Path | str, run_id: str) -> list[dict[str, Any]]:
    """All persisted per-binding Nuclei execution manifests for a run.

    Each record is self-consistency checked (its raw artifact must exist
    with matching SHA-256) and wrong-run records are rejected. Returns
    records sorted deterministically; latest attempt wins per binding at
    row-assembly time.
    """
    base_dir = Path(output_root) / "dynamic" / "before" / run_id
    records: list[dict[str, Any]] = []
    if not base_dir.is_dir():
        return records
    for path in sorted(base_dir.glob(f"dynamic_nuclei_result_{run_id}_attempt_*.json")):
        record = _read_json(path, what="dynamic result manifest")
        if not isinstance(record, Mapping):
            raise ResearchExportError("RESEARCH_ARTIFACT_INVALID",
                                      f"dynamic result manifest is malformed: {path}")
        if record.get("run_id") != run_id:
            raise ResearchExportError("RESEARCH_WRONG_RUN",
                                      f"dynamic result {path} belongs to another run")
        raw = record.get("raw_artifact")
        raw = raw if isinstance(raw, Mapping) else {}
        raw_path, raw_sha = raw.get("path"), raw.get("sha256")
        if not isinstance(raw_path, str) or not isinstance(raw_sha, str):
            raise ResearchExportError("RESEARCH_ARTIFACT_INVALID",
                                      f"dynamic result {path} lacks raw provenance")
        try:
            actual = sha256_file(Path(raw_path))
        except OSError as exc:
            raise ResearchExportError("RESEARCH_ARTIFACT_UNREADABLE",
                                      f"raw Nuclei artifact is missing: {raw_path}") from exc
        if actual != raw_sha:
            raise ResearchExportError("RESEARCH_ARTIFACT_TAMPERED",
                                      f"raw Nuclei artifact hash mismatch: {raw_path}")
        records.append({"manifest_path": str(path),
                        "manifest_sha256": sha256_file(path),
                        "record": dict(record)})
    return records


# ---------------------------------------------------------------------------
# Row assembly (pure)
# ---------------------------------------------------------------------------

def _binding_counts(candidate: Mapping[str, Any],
                    execution_refs: Sequence[Mapping[str, Any]],
                    result_index: Mapping[tuple[str, str], Mapping[str, Any]]
                    ) -> dict[str, Any]:
    bindings = candidate.get("applicable_bindings")
    bindings = list(bindings) if isinstance(bindings, list) else []
    counts = {"approved_template_count": len(candidate.get("applicable_templates") or []),
              "executed_binding_count": 0, "matched_binding_count": 0,
              "clean_binding_count": 0, "incomplete_binding_count": 0,
              "application_paths": [], "path_sources": {},
              "matched_paths": [], "execution_refs": []}
    seen_paths: list[str] = []
    for ref in execution_refs:
        if not isinstance(ref, Mapping):
            continue
        template_id = ref.get("template_id")
        base_path = ref.get("base_path", "/")
        counts["executed_binding_count"] += 1
        if isinstance(base_path, str) and base_path not in seen_paths:
            seen_paths.append(base_path)
        entry = {"template_id": template_id, "base_path": base_path,
                 "base_path_source": ref.get("base_path_source"),
                 "attempt": ref.get("attempt"), "status": ref.get("status"),
                 "reused": ref.get("reused"), "error_code": ref.get("error_code")}
        stored = result_index.get((template_id, base_path)
                                  if isinstance(base_path, str) else (None, None))
        if isinstance(stored, Mapping):
            manifest = stored.get("record", {})
            entry.update({
                "result_path": stored.get("manifest_path"),
                "result_sha256": stored.get("manifest_sha256"),
                "raw_path": (manifest.get("raw_artifact") or {}).get("path"),
                "raw_sha256": (manifest.get("raw_artifact") or {}).get("sha256"),
                "match_count": manifest.get("match_count"),
                "reachable": manifest.get("reachable"),
                "effective_target_url": manifest.get("effective_target_url")})
            status, reachable, matches = (manifest.get("execution_status"),
                                          manifest.get("reachable"),
                                          manifest.get("match_count"))
            if status == "SUCCEEDED" and reachable is True and isinstance(matches, int):
                if matches > 0:
                    counts["matched_binding_count"] += 1
                    if isinstance(base_path, str) and base_path not in counts["matched_paths"]:
                        counts["matched_paths"].append(base_path)
                else:
                    counts["clean_binding_count"] += 1
            else:
                counts["incomplete_binding_count"] += 1
        else:
            counts["incomplete_binding_count"] += 1
        counts["execution_refs"].append(entry)
    for item in bindings:
        if not isinstance(item, Mapping):
            continue
        path = item.get("base_path")
        if isinstance(path, str) and path not in seen_paths:
            seen_paths.append(path)
        if isinstance(path, str):
            counts["path_sources"][path] = item.get("base_path_source")
    for ref in execution_refs:
        if isinstance(ref, Mapping) and isinstance(ref.get("base_path"), str):
            counts["path_sources"].setdefault(ref["base_path"],
                                              ref.get("base_path_source"))
    counts["application_paths"] = seen_paths
    return counts


def dynamic_scope_version(shadow_doc: Mapping[str, Any] | None,
                          result_records: Sequence[Mapping[str, Any]]) -> str:
    """Stratify root-only history from explicit multi-path scopes."""
    if shadow_doc is None:
        return SCOPE_NONE
    paths: set[str] = set()
    for candidate in shadow_doc.get("candidates", []):
        if not isinstance(candidate, Mapping):
            continue
        for item in candidate.get("applicable_bindings") or []:
            if isinstance(item, Mapping) and isinstance(item.get("base_path"), str):
                paths.add(item["base_path"])
    for stored in result_records:
        record = stored.get("record", {})
        if isinstance(record.get("base_path"), str):
            paths.add(record["base_path"])
    if len(paths) > 1:
        return SCOPE_MULTI_PATH
    inputs = shadow_doc.get("inputs")
    inputs = inputs if isinstance(inputs, Mapping) else {}
    if inputs.get("application_endpoints") or any(
            isinstance(stored.get("record", {}).get("base_path"), str)
            for stored in result_records):
        return SCOPE_ROOT_ONLY
    return SCOPE_ROOT_ONLY_LEGACY


def build_candidate_row(*, rank: Any, top_entry: Mapping[str, Any],
                        run_meta: Mapping[str, Any],
                        dynamic_info: Mapping[str, Any],
                        attack_info: Mapping[str, Any] | None) -> dict[str, Any]:
    """One Top-N candidate CVE in one run. Copies, never recomputes."""
    cve_id = top_entry.get("cve_id")
    score = top_entry.get("score") if isinstance(top_entry.get("score"), Mapping) else {}
    components = score.get("components") if isinstance(score.get("components"), Mapping) else {}
    occurrences = top_entry.get("occurrences")
    occurrences = list(occurrences) if isinstance(occurrences, list) else []
    sources: list[str] = []
    for occurrence in occurrences:
        if not isinstance(occurrence, Mapping):
            continue
        source = occurrence.get("data_source")
        source = source if isinstance(source, Mapping) else {}
        identifier = source.get("ID")
        if isinstance(identifier, str) and identifier not in sources:
            sources.append(identifier)
    attack = attack_info if isinstance(attack_info, Mapping) else None
    available = attack is not None
    disposition = attack.get("disposition") if available else None
    oracle = attack.get("oracle") if isinstance(
        (attack or {}).get("oracle"), Mapping) else {}
    eligibility = attack.get("metric_eligibility") if isinstance(
        (attack or {}).get("metric_eligibility"), Mapping) else {}
    eligible = eligibility.get("eligible") if available else None
    # Binary mapping mirrors evaluation/metrics.py exactly: eligible success
    # is positive, eligible failure is negative, anything else is unmapped.
    if eligible is True and disposition == "EXPLOIT_SUCCEEDED":
        exploit_positive: bool | None = True
    elif eligible is True and disposition == "EXPLOIT_FAILED":
        exploit_positive = False
    else:
        exploit_positive = None
    signal = dynamic_info.get("signal")
    return {
        "run_id": run_meta.get("run_id"), "rank": rank, "canonical_cve": cve_id,
        "run": dict(run_meta),
        "priority_v1": {
            "score_model": score.get("model"), "score_display": score.get("total_display"),
            "score_raw": score.get("total_raw"), "score_components": dict(components),
            "cvss": top_entry.get("cvss"), "epss": top_entry.get("epss"),
            "kev": top_entry.get("kev"), "exposure": top_entry.get("exposure")},
        "scanner": {
            "occurrences": occurrences, "sources": sorted(sources),
            "scanner_context": top_entry.get("scanner_context")},
        "dynamic": {
            "observed": dynamic_info.get("observed", False),
            "provider": dynamic_info.get("provider"),
            "profile": dynamic_info.get("profile"),
            "signal": signal,
            "dynamic_positive": signal == "CORROBORATED",
            "score_delta": dynamic_info.get("score_delta", 0),
            "scope_version": dynamic_info.get("scope_version", SCOPE_NONE),
            **{key: dynamic_info.get(key) for key in (
                "approved_template_count", "executed_binding_count",
                "matched_binding_count", "clean_binding_count",
                "incomplete_binding_count", "application_paths",
                "path_sources", "matched_paths")},
            "applicable_bindings": dynamic_info.get("applicable_bindings", []),
            "execution_refs": dynamic_info.get("execution_refs", []),
            "evidence_refs": dynamic_info.get("evidence_refs", [])},
        "before_exploit": {
            "available": available,
            "absence_reason": None if available else dynamic_info.get(
                "ground_absence_reason", "ATTACK_BEFORE_UNAVAILABLE"),
            "disposition": disposition,
            "oracle_verdict": oracle.get("verdict"),
            "config_status": (attack or {}).get("config_status"),
            "metric_eligible": eligible,
            "exclusion_reason": eligibility.get("exclusion_reason"),
            "attempt_id": ((attack or {}).get("attempt") or {}).get("attempt_id")
            if isinstance((attack or {}).get("attempt"), Mapping) else None},
        "research": {
            "eligible": eligible,
            "exploit_positive": exploit_positive,
            "dynamic_positive": signal == "CORROBORATED"},
    }


def build_research_dataset(*, run_id: str, run_meta: Mapping[str, Any],
                           top_doc: Mapping[str, Any], top_sha256: str,
                           top_created_at: str | None,
                           shadow_doc: Mapping[str, Any] | None,
                           shadow_sha256: str | None,
                           shadow_created_at: str | None,
                           attack_doc: Mapping[str, Any] | None,
                           attack_sha256: str | None,
                           attack_created_at: str | None,
                           result_records: Sequence[Mapping[str, Any]],
                           generated_at: str) -> dict[str, Any]:
    """Assemble every Top-N candidate row deterministically."""
    ranked = top_doc.get("ranked_cves")
    if not isinstance(ranked, list) or not ranked:
        raise ResearchExportError("RESEARCH_TOP30_INVALID",
                                  "Top30 artifact has no ranked candidates")
    attack_index: dict[str, Mapping[str, Any]] = {}
    if attack_doc is not None:
        entries = attack_doc.get("cves")
        if not isinstance(entries, list):
            raise ResearchExportError("RESEARCH_ATTACK_INVALID",
                                      "ATTACK_BEFORE has no CVE array")
        for entry in entries:
            if isinstance(entry, Mapping) and isinstance(entry.get("cve_id"), str):
                attack_index.setdefault(entry["cve_id"], entry)
    shadow_index: dict[str, Mapping[str, Any]] = {}
    if shadow_doc is not None:
        for candidate in shadow_doc.get("candidates", []):
            if isinstance(candidate, Mapping) and isinstance(candidate.get("cve_id"), str):
                shadow_index.setdefault(candidate["cve_id"], candidate)
    # Latest attempt wins per (template, base path) binding.
    result_index: dict[tuple[str, str], Mapping[str, Any]] = {}
    for stored in result_records:
        record = stored.get("record", {})
        key = (record.get("template_id"), record.get("base_path", "/"))
        current = result_index.get(key)
        try:
            newer = current is None or str(record.get("attempt")) > str(
                current.get("record", {}).get("attempt"))
        except (TypeError, ValueError):
            newer = False
        if newer:
            result_index[key] = stored
    scope = dynamic_scope_version(shadow_doc, result_records)
    rows: list[dict[str, Any]] = []
    for entry in sorted(ranked, key=lambda item: (
            item.get("rank", 10**9) if isinstance(item, Mapping) else 10**9,
            item.get("cve_id", "") if isinstance(item, Mapping) else "")):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("cve_id"), str):
            raise ResearchExportError("RESEARCH_TOP30_INVALID",
                                      "Top30 entry lacks cve_id")
        cve_id = entry["cve_id"]
        shadow_candidate = shadow_index.get(cve_id, {})
        validation = shadow_candidate.get("dynamic_validation")
        validation = validation if isinstance(validation, Mapping) else {}
        execution_refs = validation.get("execution_refs")
        execution_refs = list(execution_refs) if isinstance(execution_refs, list) else []
        counts = _binding_counts(shadow_candidate, execution_refs, result_index)
        observed = shadow_doc is not None
        dynamic_info = {
            "observed": observed,
            "provider": validation.get("provider") if observed else None,
            "profile": validation.get("profile") if observed else None,
            "signal": shadow_candidate.get("signal", "NOT_RUN") if observed else "NOT_RUN",
            "score_delta": validation.get("score_delta", 0),
            "scope_version": scope,
            "approved_template_count": counts["approved_template_count"],
            "executed_binding_count": counts["executed_binding_count"],
            "matched_binding_count": counts["matched_binding_count"],
            "clean_binding_count": counts["clean_binding_count"],
            "incomplete_binding_count": counts["incomplete_binding_count"],
            "application_paths": counts["application_paths"],
            "path_sources": counts["path_sources"],
            "matched_paths": counts["matched_paths"],
            "applicable_bindings": list(shadow_candidate.get("applicable_bindings", []))
            if isinstance(shadow_candidate.get("applicable_bindings"), list) else [],
            "execution_refs": counts["execution_refs"],
            "evidence_refs": list(validation.get("evidence_refs", []))
            if isinstance(validation.get("evidence_refs"), list) else [],
            "ground_absence_reason": (
                None if cve_id in attack_index else "CVE_ABSENT_FROM_ATTACK_ARTIFACT"
                if attack_doc is not None else "ATTACK_BEFORE_UNAVAILABLE"),
        }
        rows.append(build_candidate_row(
            rank=entry.get("rank"), top_entry=entry, run_meta=run_meta,
            dynamic_info=dynamic_info,
            attack_info=attack_index.get(cve_id)))
    stamps = [(_parse_instant(top_created_at), "top30"),
              (_parse_instant(shadow_created_at), "shadow"),
              (_parse_instant(attack_created_at), "attack")]
    ordered = [name for instant, name in stamps if instant is not None]
    instants = [instant for instant, _ in stamps if instant is not None]
    temporal_order_ok: bool | None = (
        None if len(instants) < 2 else all(
            first <= second for first, second in zip(instants, instants[1:])))
    return {
        "schema": RESEARCH_SCHEMA, "generated_at": generated_at, "run_id": run_id,
        "sources": {
            "top30": {"sha256": top_sha256, "created_at": top_created_at},
            "dynamic_shadow": ({"sha256": shadow_sha256, "created_at": shadow_created_at}
                               if shadow_doc is not None else None),
            "attack_before": ({"sha256": attack_sha256, "created_at": attack_created_at}
                              if attack_doc is not None else None)},
        "temporal": {"top30_created_at": top_created_at,
                     "shadow_created_at": shadow_created_at,
                     "attack_created_at": attack_created_at,
                     "observed_order": ordered,
                     "temporal_order_ok": temporal_order_ok,
                     "before_phase_only": True},
        "rows": rows,
        "metrics": dataset_metrics(rows),
    }


# ---------------------------------------------------------------------------
# Descriptive metrics (counts, coverage, cross-tabs, proportions only)
# ---------------------------------------------------------------------------

def _is_applicable(row: Mapping[str, Any]) -> bool:
    dynamic = row.get("dynamic", {})
    if dynamic.get("signal") in {"CORROBORATED", "NOT_OBSERVED"}:
        return True
    return (dynamic.get("signal") == "INCONCLUSIVE"
            and (dynamic.get("approved_template_count") or 0) > 0)


def dataset_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Descriptive counts only. No weights, ranking, or significance."""
    rows = list(rows)
    signals: dict[str, int] = {}
    dispositions: dict[str, int] = {}
    cross: dict[str, dict[str, int]] = {}
    applicable = 0
    bindings = {"applicable": 0, "executed": 0, "matched": 0,
                "clean": 0, "incomplete": 0}
    positives = 0
    eligible_rows = 0
    for row in rows:
        dynamic = row.get("dynamic", {})
        research = row.get("research", {})
        before = row.get("before_exploit", {})
        signal = dynamic.get("signal", "NOT_RUN")
        signals[signal] = signals.get(signal, 0) + 1
        disposition = before.get("disposition")
        disposition_key = disposition if isinstance(disposition, str) else (
            "GROUND_TRUTH_UNAVAILABLE")
        dispositions[disposition_key] = dispositions.get(disposition_key, 0) + 1
        cell = cross.setdefault(signal, {})
        cell[disposition_key] = cell.get(disposition_key, 0) + 1
        if _is_applicable(row):
            applicable += 1
        bindings["applicable"] += len(dynamic.get("applicable_bindings", []) or [])
        for key in ("executed", "matched", "clean", "incomplete"):
            bindings[key] += dynamic.get(f"{key}_binding_count", 0) or 0
        if research.get("exploit_positive") is True:
            positives += 1
        if research.get("eligible") is True:
            eligible_rows += 1
    total = len(rows)
    proportions: dict[str, Any] = {}
    for signal in sorted(signals):
        subset = [row for row in rows if row.get("dynamic", {}).get("signal") == signal]
        mapped = [row for row in subset
                  if row.get("research", {}).get("exploit_positive") is not None]
        hits = sum(1 for row in mapped
                   if row.get("research", {}).get("exploit_positive") is True)
        proportions[signal] = {
            "kind": "descriptive_empirical_proportion",
            "numerator": hits, "denominator": len(mapped),
            "value": (hits / len(mapped)) if mapped else None,
            "note": ("P(exploit_positive | dynamic_signal=%s) over rows with "
                     "a mapped binary disposition; NOT_OBSERVED is an observation "
                     "state, not proof of non-vulnerability." % signal)}
    return {
        "candidate_total": total,
        "signal_counts": dict(sorted(signals.items())),
        "dynamic_applicable_count": applicable,
        "dynamic_coverage_rate": (applicable / total) if total else None,
        "dynamic_applicable_definition": (
            "CORROBORATED OR NOT_OBSERVED OR "
            "(INCONCLUSIVE with approved templates present)"),
        "binding_totals": bindings,
        "eligible_total": eligible_rows,
        "exploit_positive_total": positives,
        "disposition_counts": dict(sorted(dispositions.items())),
        "signal_by_disposition": {signal: dict(sorted(cell.items()))
                                  for signal, cell in sorted(cross.items())},
        "conditional_proportions": proportions,
    }


# ---------------------------------------------------------------------------
# Serialization: JSON + CSV (same rows)
# ---------------------------------------------------------------------------

def _canonical_payload(dataset: Mapping[str, Any]) -> bytes:
    reduced = {"schema": dataset.get("schema"), "run_id": dataset.get("run_id"),
               "sources": dataset.get("sources"), "rows": dataset.get("rows"),
               "metrics": dataset.get("metrics")}
    return json.dumps(reduced, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def export_sha256(dataset: Mapping[str, Any]) -> str:
    """Reproducible content hash (excludes generation metadata)."""
    return hashlib.sha256(_canonical_payload(dataset)).hexdigest()


CSV_COLUMNS: tuple[str, ...] = (
    "run_id", "rank", "canonical_cve", "requested_image", "image_id",
    "top_n_returned", "priority_v1_sha256", "score_model", "score_display",
    "score_raw", "cvss_score", "cvss_version", "epss_score", "epss_state",
    "kev_listed", "exposure_state", "package_names", "installed_versions",
    "scanner_sources", "dynamic_provider", "dynamic_profile", "dynamic_signal",
    "dynamic_positive", "dynamic_scope_version", "approved_template_count",
    "executed_binding_count", "matched_binding_count", "clean_binding_count",
    "incomplete_binding_count", "application_paths", "matched_paths",
    "before_disposition", "oracle_verdict", "config_status", "metric_eligible",
    "exclusion_reason", "exploit_positive", "ground_truth_available",
    "evidence_ref_paths", "result_manifest_paths",
    "top30_created_at", "shadow_created_at", "attack_created_at",
    "temporal_order_ok",
)


def _join(values: Any) -> str:
    if values is None:
        return ""
    if isinstance(values, (list, tuple)):
        return "|".join("" if item is None else str(item) for item in values)
    return str(values)


def _cell(value: Any) -> str:
    return "" if value is None else str(value)


def row_to_csv_record(row: Mapping[str, Any], *,
                      priority_v1_sha256: str,
                      temporal: Mapping[str, Any]) -> dict[str, str]:
    run = row.get("run", {})
    priority = row.get("priority_v1", {})
    scanner = row.get("scanner", {})
    dynamic = row.get("dynamic", {})
    before = row.get("before_exploit", {})
    research = row.get("research", {})
    cvss = priority.get("cvss") if isinstance(priority.get("cvss"), Mapping) else {}
    epss = priority.get("epss") if isinstance(priority.get("epss"), Mapping) else {}
    kev = priority.get("kev") if isinstance(priority.get("kev"), Mapping) else {}
    exposure = priority.get("exposure") if isinstance(priority.get("exposure"), Mapping) else {}
    occurrences = scanner.get("occurrences")
    occurrences = occurrences if isinstance(occurrences, list) else []
    packages = [item.get("package_name") for item in occurrences
                if isinstance(item, Mapping)]
    installed = [item.get("installed_version") for item in occurrences
                 if isinstance(item, Mapping)]
    evidence_paths = [ref.get("path") for ref in dynamic.get("evidence_refs", [])
                      if isinstance(ref, Mapping)]
    manifest_paths = [ref.get("result_path") for ref in dynamic.get("execution_refs", [])
                      if isinstance(ref, Mapping) and ref.get("result_path")]
    return {
        "run_id": _cell(row.get("run_id")),
        "rank": _cell(row.get("rank")),
        "canonical_cve": _cell(row.get("canonical_cve")),
        "requested_image": _cell(run.get("requested_image")),
        "image_id": _cell(run.get("image_id")),
        "top_n_returned": _cell(run.get("top_n_returned")),
        "priority_v1_sha256": priority_v1_sha256,
        "score_model": _cell(priority.get("score_model")),
        "score_display": _cell(priority.get("score_display")),
        "score_raw": _cell(priority.get("score_raw")),
        "cvss_score": _cell(cvss.get("score")),
        "cvss_version": _cell(cvss.get("version")),
        "epss_score": _cell(epss.get("score")),
        "epss_state": _cell(epss.get("state")),
        "kev_listed": _cell(kev.get("listed")),
        "exposure_state": _cell(exposure.get("state")),
        "package_names": _join(packages),
        "installed_versions": _join(installed),
        "scanner_sources": _join(scanner.get("sources", [])),
        "dynamic_provider": _cell(dynamic.get("provider")),
        "dynamic_profile": _cell(dynamic.get("profile")),
        "dynamic_signal": _cell(dynamic.get("signal")),
        "dynamic_positive": _cell(dynamic.get("dynamic_positive")),
        "dynamic_scope_version": _cell(dynamic.get("scope_version")),
        "approved_template_count": _cell(dynamic.get("approved_template_count")),
        "executed_binding_count": _cell(dynamic.get("executed_binding_count")),
        "matched_binding_count": _cell(dynamic.get("matched_binding_count")),
        "clean_binding_count": _cell(dynamic.get("clean_binding_count")),
        "incomplete_binding_count": _cell(dynamic.get("incomplete_binding_count")),
        "application_paths": _join(dynamic.get("application_paths", [])),
        "matched_paths": _join(dynamic.get("matched_paths", [])),
        "before_disposition": _cell(before.get("disposition")),
        "oracle_verdict": _cell(before.get("oracle_verdict")),
        "config_status": _cell(before.get("config_status")),
        "metric_eligible": _cell(before.get("metric_eligible")),
        "exclusion_reason": _cell(before.get("exclusion_reason")),
        "exploit_positive": _cell(research.get("exploit_positive")),
        "ground_truth_available": _cell(before.get("available")),
        "evidence_ref_paths": _join(evidence_paths),
        "result_manifest_paths": _join(manifest_paths),
        "top30_created_at": _cell(temporal.get("top30_created_at")),
        "shadow_created_at": _cell(temporal.get("shadow_created_at")),
        "attack_created_at": _cell(temporal.get("attack_created_at")),
        "temporal_order_ok": _cell(temporal.get("temporal_order_ok")),
    }


def dataset_to_csv(dataset: Mapping[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS),
                            lineterminator="\n")
    writer.writeheader()
    temporal = dataset.get("temporal", {})
    top_sha = (dataset.get("sources", {}) or {}).get("top30", {}) or {}
    for row in dataset.get("rows", []):
        writer.writerow(row_to_csv_record(
            row, priority_v1_sha256=str(top_sha.get("sha256", "")),
            temporal=temporal if isinstance(temporal, Mapping) else {}))
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Top-level export (read-only)
# ---------------------------------------------------------------------------

def export_run(output_root: Path | str, run_id: str, *,
               now: datetime | None = None) -> dict[str, Any]:
    """Build the full research dataset for one run. No state is written."""
    sources = collect_run_sources(output_root, run_id)
    state = sources["state"]
    top_entry = sources["top30"]
    shadow_entry = sources["shadow"]
    attack_entry = sources["attack"]
    top_doc = top_entry["document"]
    shadow_doc = shadow_entry["document"] if shadow_entry else None
    attack_doc = attack_entry["document"] if attack_entry else None
    result_records = (load_dynamic_result_records(output_root, run_id)
                      if shadow_entry else [])
    target = getattr(state, "target", None)
    facts = getattr(target, "facts", None) or {}
    if not isinstance(facts, Mapping):
        facts = {}
    top_artifact = top_doc.get("artifact") if isinstance(
        top_doc.get("artifact"), Mapping) else {}
    run_meta = {
        "run_id": run_id,
        "created_at": getattr(state, "created_at", None),
        "requested_image": facts.get("requested_image_reference"),
        "image_id": facts.get("image_id"),
        "image_digest": facts.get("image_digest"),
        "container_id": facts.get("container_id"),
        "container_name": facts.get("container_name"),
        "top_n_requested": top_artifact.get("top_n_requested"),
        "top_n_returned": top_artifact.get("top_n_returned"),
        "priority_v1_sha256": top_entry["sha256"],
    }
    generated = (now or datetime.now(timezone.utc)).isoformat()
    dataset = build_research_dataset(
        run_id=run_id, run_meta=run_meta, top_doc=top_doc,
        top_sha256=top_entry["sha256"], top_created_at=top_entry["created_at"],
        shadow_doc=shadow_doc,
        shadow_sha256=shadow_entry["sha256"] if shadow_entry else None,
        shadow_created_at=shadow_entry["created_at"] if shadow_entry else None,
        attack_doc=attack_doc,
        attack_sha256=attack_entry["sha256"] if attack_entry else None,
        attack_created_at=attack_entry["created_at"] if attack_entry else None,
        result_records=result_records, generated_at=generated)
    dataset["export_sha256"] = export_sha256(dataset)
    return dataset


def write_export(dataset: Mapping[str, Any], out_dir: Path | str,
                 stem: str | None = None) -> dict[str, str]:
    """Persist JSON + CSV side by side. Research output only."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stem = stem or f"dynamic_research_{dataset.get('run_id', 'unknown')}"
    json_path = directory / f"{stem}.json"
    csv_path = directory / f"{stem}.csv"
    for path in (json_path, csv_path):
        if path.exists():
            raise ResearchExportError("RESEARCH_EXPORT_EXISTS",
                                      f"refusing to overwrite research export {path}")
    json_path.write_text(json.dumps(dataset, ensure_ascii=False, indent=2,
                                    sort_keys=True) + "\n", encoding="utf-8")
    csv_path.write_text(dataset_to_csv(dataset), encoding="utf-8")
    return {"json": str(json_path), "csv": str(csv_path)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kalama-dynamic-research",
        description="Export a read-only BEFORE-phase research dataset for one run.")
    parser.add_argument("--output-root", required=True,
                        help="canonical pipeline output root holding the run")
    parser.add_argument("--run", required=True, help="run_id to export")
    parser.add_argument("--out-dir", required=True,
                        help="directory receiving the JSON + CSV export")
    args = parser.parse_args(argv)
    try:
        dataset = export_run(args.output_root, args.run)
        paths = write_export(dataset, args.out_dir)
    except ResearchExportError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"run_id": dataset["run_id"], "rows": len(dataset["rows"]),
                      "export_sha256": dataset["export_sha256"], **paths},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
