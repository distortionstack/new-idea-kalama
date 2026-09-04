"""Resolver JSON and human-editable Attack Form projections."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

import yaml

from kalama.resolver.config_models import ExploitValue

from .models import ResolverCVEResult, ResolverCVEStatus, Step4Analysis


RESOLVER_SCHEMA = "kalama.resolver/v1"
ATTACK_FORM_SCHEMA = "kalama.attack-form/v1"
EXPLOIT_CONFIG_SET_SCHEMA = "kalama.exploit-config-set/v1"
ATTACK_RESULT_SCHEMA = "kalama.attack-result/v1"
PATCH_PLAN_SCHEMA = "kalama.patch-plan/v1"
PATCH_FORM_SCHEMA = "kalama.patch-form/v1"
PATCH_RESULT_SCHEMA = "kalama.patch-result/v1"
REMEDIATION_SCAN_RESULT_SCHEMA = "kalama.remediation-scan-result/v1"
REMEDIATION_RESULT_SCHEMA = "kalama.remediation-result/v1"
EVALUATION_DATASET_SCHEMA = "kalama.evaluation-dataset/v1"
EVALUATION_METRICS_SCHEMA = "kalama.metrics/v1"
RUN_SUMMARY_SCHEMA = "kalama.run-summary/v1"
LLM_GUIDANCE_SCHEMA = "kalama.llm-guidance/v1"


class ArtifactWriteError(RuntimeError):
    pass


class ImmutableArtifactConflict(ArtifactWriteError):
    pass


def resolver_artifact(analysis: Step4Analysis, *, run_id: str, created_at: str,
                      top30_path: str, top30_sha256: str) -> dict[str, Any]:
    return {
        "schema": RESOLVER_SCHEMA,
        "artifact": {"run_id": run_id, "phase": "before", "created_at": created_at,
                     "input_top30": {"path": top30_path, "sha256": top30_sha256}},
        "summary": analysis.summary(),
        "cves": [item.to_dict() for item in analysis.cves],
    }


def _value_projection(value: ExploitValue, *, default: Any = None) -> dict[str, Any]:
    return {"default": default, "suggested": value.suggested_value,
            "confirmed": value.value if value.confirmed else None,
            "source": value.source.value,
            "confirmation_status": value.confirmation_status.value,
            "required": value.required}


def _form_cve(item: ResolverCVEResult, guidance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    config, validation = item.exploit_config, item.validation
    assert config is not None and validation is not None
    invariant = config.invariant
    selection = invariant.module_selection
    candidates = []
    for ranked in selection.ranking.ranked_candidates:
        candidates.append({"rank_position": ranked.rank_position, "score": ranked.score,
                           "module_path": ranked.candidate.module_path,
                           "evidence": [x.to_dict() for x in ranked.evidence]})
    module_options = {}
    for option in sorted(invariant.module_options, key=lambda x: (x.name.casefold(), x.name)):
        if option.name.upper() in {"RHOSTS", "RPORT", "LHOST", "TARGETURI"}:
            continue
        module_options[option.name] = _value_projection(option.field, default=option.default)
        module_options[option.name]["type"] = option.type
    payload_options = {}
    for option in sorted(invariant.payload.options, key=lambda x: (x.name.casefold(), x.name)):
        payload_options[option.name] = _value_projection(option.field, default=option.default)
        payload_options[option.name]["type"] = option.type
    target = invariant.target_selection
    projected = {
        "rank": item.input.rank,
        "input_reasons": sorted({issue.reason.value for issue in validation.issues}),
        "module": {**_value_projection(selection.module), "candidates": candidates},
        "target": {"required": target.required,
                   "index": _value_projection(target.target_index, default=target.default_target_index),
                   "name": _value_projection(target.target_name, default=target.default_target_name)},
        "targeturi": _value_projection(invariant.targeturi, default=next(
            (x.default for x in invariant.module_options if x.name.upper() == "TARGETURI"), None)),
        "module_options": module_options,
        "payload": {**_value_projection(invariant.payload.payload),
                    "compatible": list(invariant.payload.compatible_payloads),
                    "compatibility_evidence": list(invariant.payload.compatibility_evidence),
                    "discovery_status": invariant.payload.discovery_status.value},
        "payload_options": payload_options,
        "preconditions": {"description": invariant.preconditions.description,
                          "commands": list(invariant.preconditions.commands),
                          "execution_target": invariant.preconditions.execution_target,
                          "required": invariant.preconditions.required,
                          "confirmation_status": invariant.preconditions.confirmation_status.value},
        "pre_attack": invariant.pre_attack.to_dict(),
        "execution_protocol": {
            **invariant.execution_protocol.to_dict(),
            "mode": ("check-then-exploit" if invariant.execution_protocol.run_check
                     and invariant.execution_protocol.run_exploit else
                     "check-only" if invariant.execution_protocol.run_check else
                     "exploit-only" if invariant.execution_protocol.run_exploit else "disabled"),
            "confirmed": None,
        },
        "environment": {"rhosts": _value_projection(config.environment.rhosts),
                        "rport": _value_projection(config.environment.rport),
                        "lhost": _value_projection(config.environment.lhost),
                        "binding_source": config.environment.port_binding_source},
    }
    if guidance:
        accepted = guidance.get("accepted_suggestions", {})
        if isinstance(accepted, Mapping):
            for field, destination in (("payload", projected["payload"]),
                                       ("targeturi", projected["targeturi"]),
                                       ("rport", projected["environment"]["rport"])):
                proposal = accepted.get(field)
                if isinstance(proposal, Mapping) and destination.get("confirmed") is None:
                    destination["suggested"] = proposal.get("value")
                    destination["confirmation_status"] = "SUGGESTED"
            target_proposal = accepted.get("target")
            if isinstance(target_proposal, Mapping) and isinstance(target_proposal.get("value"), Mapping):
                value = target_proposal["value"]
                if projected["target"]["index"]["confirmed"] is None and "index" in value:
                    projected["target"]["index"]["suggested"] = value["index"]
                if projected["target"]["name"]["confirmed"] is None and "name" in value:
                    projected["target"]["name"]["suggested"] = value["name"]
        projected["guidance"] = {
            "source": "LLM_PROPOSED", "provider_status": guidance.get("provider_status"),
            "model": guidance.get("model"),
            "evidence_pack_sha256": guidance.get("evidence_pack_sha256"),
            "validation_state": guidance.get("validation_state"),
            "accepted_suggestions": accepted, "issues": guidance.get("issues", [])}
    return projected


def attack_form(analysis: Step4Analysis, *, run_id: str, revision: int = 1,
                base_resolver_sha256: str | None = None,
                base_config_sha256: str | None = None,
                guidance_by_cve: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    cves = {}
    for item in analysis.cves:
        if item.status == ResolverCVEStatus.WAITING_FOR_USER_INPUT:
            cves[item.input.cve_id] = _form_cve(
                item, (guidance_by_cve or {}).get(item.input.cve_id))
    return {"schema": ATTACK_FORM_SCHEMA, "run_id": run_id, "phase": "before",
            "revision": revision, "base_resolver_sha256": base_resolver_sha256,
            "base_config_sha256": base_config_sha256, "cves": cves}


def _atomic_write(path: Path, payload: bytes) -> str:
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.",
                                         delete=False) as handle:
            temporary = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        if temporary:
            try: os.unlink(temporary)
            except OSError: pass
        raise ArtifactWriteError(str(exc)) from exc


def _immutable_write(path: Path, payload: bytes) -> str:
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.",
                                         delete=False) as handle:
            temporary = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ImmutableArtifactConflict(f"immutable artifact already exists: {path}") from exc
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except ImmutableArtifactConflict:
        raise
    except OSError as exc:
        raise ArtifactWriteError(str(exc)) from exc
    finally:
        if temporary:
            try: os.unlink(temporary)
            except OSError: pass


def write_resolver_artifact(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != RESOLVER_SCHEMA or not isinstance(artifact.get("cves"), list):
        raise ArtifactWriteError("invalid Resolver artifact")
    payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    return _atomic_write(path, payload)


def write_attack_form(path: Path, form: Mapping[str, Any]) -> str:
    if form.get("schema") != ATTACK_FORM_SCHEMA or not isinstance(form.get("cves"), Mapping):
        raise ArtifactWriteError("invalid Attack Form")
    payload = yaml.safe_dump(dict(form), sort_keys=False, allow_unicode=True).encode()
    return _atomic_write(path, payload)


def write_llm_guidance(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != LLM_GUIDANCE_SCHEMA or not isinstance(artifact.get("cves"), list):
        raise ArtifactWriteError("invalid LLM guidance artifact")
    return _atomic_write(path, (json.dumps(artifact, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n").encode())


def write_submission_snapshot(path: Path, payload: bytes) -> str:
    return _atomic_write(path, payload)


def write_submission_snapshot_immutable(path: Path, payload: bytes) -> str:
    return _immutable_write(path, payload)


def write_config_set(path: Path, artifact: Mapping[str, Any]) -> str:
    if (artifact.get("schema") != EXPLOIT_CONFIG_SET_SCHEMA
            or not isinstance(artifact.get("cves"), list)):
        raise ArtifactWriteError("invalid exploit config set")
    payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    return _atomic_write(path, payload)


def write_attack_result(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != ATTACK_RESULT_SCHEMA or not isinstance(artifact.get("cves"), list):
        raise ArtifactWriteError("invalid attack result")
    payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    return _atomic_write(path, payload)


def write_patch_plan(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != PATCH_PLAN_SCHEMA or not isinstance(artifact.get("actions"), list):
        raise ArtifactWriteError("invalid patch plan")
    payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    return _atomic_write(path, payload)


def write_patch_form(path: Path, form: Mapping[str, Any]) -> str:
    if form.get("schema") != PATCH_FORM_SCHEMA or not isinstance(form.get("actions"), Mapping):
        raise ArtifactWriteError("invalid patch form")
    return _atomic_write(path, yaml.safe_dump(dict(form), sort_keys=False,
                                              allow_unicode=True).encode())


def write_patch_form_immutable(path: Path, form: Mapping[str, Any]) -> str:
    if form.get("schema") != PATCH_FORM_SCHEMA or not isinstance(form.get("actions"), Mapping):
        raise ArtifactWriteError("invalid patch form")
    return _immutable_write(path, yaml.safe_dump(dict(form), sort_keys=False,
                                                 allow_unicode=True).encode())


def write_patch_result(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != PATCH_RESULT_SCHEMA or not isinstance(artifact.get("actions"), list):
        raise ArtifactWriteError("invalid patch result")
    return _atomic_write(path, (json.dumps(artifact, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n").encode())


def write_patch_result_immutable(path: Path, artifact: Mapping[str, Any]) -> str:
    if artifact.get("schema") != PATCH_RESULT_SCHEMA or not isinstance(artifact.get("actions"), list):
        raise ArtifactWriteError("invalid patch result")
    return _immutable_write(path, (json.dumps(artifact, ensure_ascii=False, indent=2,
                                             sort_keys=True) + "\n").encode())


def write_remediation_scan_result(path: Path, artifact: Mapping[str, Any]) -> str:
    if (artifact.get("schema") != REMEDIATION_SCAN_RESULT_SCHEMA
            or not isinstance(artifact.get("intended_targets"), list)
            or not isinstance(artifact.get("incidental_effects"), list)):
        raise ArtifactWriteError("invalid remediation scan result")
    return _atomic_write(path, (json.dumps(artifact, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n").encode())


def write_remediation_result(path: Path, artifact: Mapping[str, Any]) -> str:
    if (artifact.get("schema") != REMEDIATION_RESULT_SCHEMA
            or not isinstance(artifact.get("cves"), list)):
        raise ArtifactWriteError("invalid final remediation result")
    return _atomic_write(path, (json.dumps(artifact, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n").encode())


def _write_evaluation(path: Path, artifact: Mapping[str, Any], schema: str,
                      required: str) -> str:
    if artifact.get("schema") != schema or not isinstance(artifact.get(required), (list, dict)):
        raise ArtifactWriteError(f"invalid {schema} artifact")
    payload = (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True,
                          allow_nan=False) + "\n").encode()
    return _atomic_write(path, payload)


def write_evaluation_dataset(path: Path, artifact: Mapping[str, Any]) -> str:
    return _write_evaluation(path, artifact, EVALUATION_DATASET_SCHEMA, "records")


def write_evaluation_metrics(path: Path, artifact: Mapping[str, Any]) -> str:
    return _write_evaluation(path, artifact, EVALUATION_METRICS_SCHEMA, "prioritization")


def write_run_summary(path: Path, artifact: Mapping[str, Any]) -> str:
    return _write_evaluation(path, artifact, RUN_SUMMARY_SCHEMA, "artifact_index")
