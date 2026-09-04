"""Thin Step 3 coordinator and deterministic atomic artifact writer."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from .enrichment import CVSSProvider, EPSSProvider, KEVProvider, enrich_cves
from .exposure import exposure_from_facts
from .models import FailureCode, PrioritizationResult, StageIssue
from .scoring import rank_cves
from .trivy_parser import TrivyArtifactError, aggregate_unique_cves, parse_trivy_report


SCHEMA = "kalama.prioritization/v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def prioritize_trivy(
    trivy_data: Mapping[str, Any], *, run_id: str, created_at: str,
    epss_data_date: date, trivy_path: str, trivy_sha256: str,
    epss_provider: EPSSProvider, kev_provider: KEVProvider,
    cvss_provider: CVSSProvider | None = None, phase: str = "before",
    target_facts_reference: Mapping[str, Any] | None = None,
    exposure_facts: Mapping[str, Any] | None = None, top_n: int = 30,
) -> PrioritizationResult:
    try:
        parsed = parse_trivy_report(trivy_data)
    except TrivyArtifactError as exc:
        return PrioritizationResult(False, issues=(exc.issue,))
    aggregates = aggregate_unique_cves(parsed.occurrences)
    enrichment = enrich_cves(
        aggregates, epss_data_date=epss_data_date, epss_provider=epss_provider,
        kev_provider=kev_provider, cvss_provider=cvss_provider,
    )
    if enrichment.issues:
        return PrioritizationResult(False, issues=enrichment.issues)
    exposure = exposure_from_facts(exposure_facts)
    enriched = tuple(replace(item, exposure=exposure) for item in enrichment.enriched)
    try:
        ranked = rank_cves(enriched, top_n)
    except ValueError as exc:
        issue = StageIssue(FailureCode.SCORING_INPUT_INVALID, "scoring", str(exc))
        return PrioritizationResult(False, issues=(issue,))

    trivy_input = {
        "path": trivy_path, "sha256": trivy_sha256,
        "schema_version": parsed.schema_version, "trivy_version": parsed.trivy_version,
        "report_id": parsed.report_id, "created_at": parsed.created_at,
        "artifact_name": parsed.artifact_name, "artifact_id": parsed.artifact_id,
    }
    inputs: dict[str, Any] = {"trivy": trivy_input}
    if target_facts_reference is not None:
        inputs["target_facts"] = dict(target_facts_reference)
    epss_provenance = None
    if enriched:
        first = enriched[0].epss
        epss_provenance = {"source": first.source, "data_date": first.data_date,
                           "effective_date": first.data_date,
                           "as_of_date": first.as_of_date or epss_data_date.isoformat(),
                           "date_resolution": first.date_resolution,
                           "retrieved_at": first.retrieved_at}
    else:
        epss_provenance = {"source": "FIRST", "data_date": None,
                           "effective_date": None,
                           "as_of_date": epss_data_date.isoformat(),
                           "date_resolution": None, "retrieved_at": None}
    artifact = {
        "schema": SCHEMA,
        "artifact": {"kind": f"{phase}_top_cves", "run_id": run_id, "phase": phase,
                     "created_at": created_at, "top_n_requested": top_n,
                     "top_n_returned": len(ranked)},
        "inputs": inputs,
        "enrichment_snapshot": {"epss": epss_provenance,
                                "kev": enrichment.kev_catalog.provenance_dict()},
        "score_model": {"id": "kalama-priority-v1",
                        "formula": "cvss + epss*3 + kev*3",
                        "parameters": {"epss_weight": "3", "kev_bonus": "3",
                                       "exposure_in_score": False}},
        "exposure_context": exposure.to_dict(),
        "ranked_cves": [item.to_dict() for item in ranked],
        "excluded_findings": [item.to_dict() for item in parsed.excluded_findings],
        "warnings": [item.to_dict() for item in parsed.warnings],
    }
    return PrioritizationResult(True, ranked, artifact=artifact)


def validate_artifact(artifact: Mapping[str, Any]) -> None:
    if artifact.get("schema") != SCHEMA:
        raise ValueError("invalid prioritization schema")
    meta = artifact.get("artifact")
    ranked = artifact.get("ranked_cves")
    if not isinstance(meta, Mapping) or not isinstance(ranked, list):
        raise ValueError("artifact metadata and ranked_cves are required")
    if meta.get("top_n_returned") != len(ranked):
        raise ValueError("top_n_returned does not match ranked_cves")
    if [item.get("rank") for item in ranked] != list(range(1, len(ranked) + 1)):
        raise ValueError("ranked_cves ranks are not ordinal")


def serialize_artifact(artifact: Mapping[str, Any]) -> bytes:
    validate_artifact(artifact)
    return (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def write_artifact_atomic(path: Path, artifact: Mapping[str, Any]) -> None:
    payload = serialize_artifact(artifact)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.",
                                         delete=False) as handle:
            temporary = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise RuntimeError(f"{FailureCode.OUTPUT_WRITE_FAILED.value}: {exc}") from exc


def prioritize_file(
    input_path: Path, output_path: Path, **kwargs: Any,
) -> PrioritizationResult:
    raw = input_path.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        issue = StageIssue(FailureCode.INVALID_TRIVY_ARTIFACT, "trivy_parse", str(exc))
        return PrioritizationResult(False, issues=(issue,))
    result = prioritize_trivy(data, trivy_path=str(input_path), trivy_sha256=_sha256(raw), **kwargs)
    if result.success and result.artifact is not None:
        write_artifact_atomic(output_path, result.artifact)
    return result
