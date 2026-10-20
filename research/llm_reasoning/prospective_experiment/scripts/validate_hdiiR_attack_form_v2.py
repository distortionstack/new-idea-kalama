"""Read-only replay of AttackFormOrchestrator validation through its apply loop.

No StateStore save or submission-artifact write is performed.  The script
checks form/run/revision binding and calls the same apply_human_confirmation
function and production MSF payload adapter used by submit_attack_form.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import yaml

from kalama.resolver.backend import resolver_backend
from kalama.resolver.config import validate_exploit_config
from kalama.resolution.artifacts import ATTACK_FORM_SCHEMA, EXPLOIT_CONFIG_SET_SCHEMA, RESOLVER_SCHEMA
from kalama.resolution.config_codec import exploit_config_from_dict
from kalama.resolution.confirmation_orchestrator import AttackFormOrchestrator
from kalama.resolution.submission import SubmissionValidationError, apply_human_confirmation
from kalama.state import ArtifactKind, PipelineStage, RunStatus, StateStore

ROOT = Path(__file__).resolve().parents[4]
OUTPUT = ROOT / "output/2d8ru-struts2-prospective"
FORM = ROOT / "research/llm_reasoning/prospective_experiment/runs/HdiiR/review/attack_form_HdiiR_r1_reviewed_v3.yaml"


def fail(message: str) -> None:
    raise RuntimeError(message)


def main() -> None:
    start = time.time()
    report: dict[str, object] = {"run_id": "HdiiR", "form": str(FORM), "started_at_epoch": start}
    try:
        store = StateStore(OUTPUT)
        state = store.load("HdiiR")
        validator = AttackFormOrchestrator(store)
        validator._assert_eligible(state)
        resolver_ref = state.artifact(ArtifactKind.RESOLVER_BEFORE)
        form_ref = state.artifact(ArtifactKind.ATTACK_FORM)
        if resolver_ref is None or form_ref is None:
            fail("missing resolver or canonical attack form")
        resolver = validator._verify_json(resolver_ref, RESOLVER_SCHEMA, state.run_id)
        generated = validator._verify_form(form_ref, state.run_id)
        entries = validator._base_entries(state, resolver)
        submitted = yaml.safe_load(FORM.read_bytes())
        if not isinstance(submitted, dict):
            fail("submission is not a YAML mapping")
        for key, expected in (("schema", ATTACK_FORM_SCHEMA), ("run_id", "HdiiR"), ("phase", "before")):
            if submitted.get(key) != expected:
                fail(f"{key} binding mismatch")
        revision = int(generated.get("revision", 1))
        current_config = state.artifact(ArtifactKind.EXPLOIT_CONFIG_BEFORE)
        if (submitted.get("revision", 1) != revision
                or submitted.get("base_resolver_sha256") != generated.get("base_resolver_sha256")
                or submitted.get("base_config_sha256") != generated.get("base_config_sha256")
                or generated.get("base_resolver_sha256") != resolver_ref.sha256
                or generated.get("base_config_sha256") != (current_config.sha256 if current_config else None)):
            fail("revision or base artifact binding mismatch")
        cves = submitted.get("cves")
        generated_cves = generated.get("cves")
        if not isinstance(cves, dict) or not isinstance(generated_cves, dict):
            fail("CVE mapping missing")
        known = {item.get("cve_id"): item for item in entries}
        if set(cves) - set(known) or set(cves) - set(generated_cves):
            fail("unknown or non-editable CVE")
        backend = resolver_backend()
        introspector = lambda module, payload: backend.introspect_payload(module, payload, "msf-resolver-host")
        outcomes = []
        for raw in entries:
            cve_id = raw.get("cve_id")
            config_raw = raw.get("exploit_config")
            if config_raw is None or cve_id not in cves:
                continue
            human = cves[cve_id]
            if not isinstance(human, dict):
                fail(f"{cve_id}: submission is not an object")
            generated_cve = generated_cves[cve_id]
            if (human.get("rank", generated_cve.get("rank")) != generated_cve.get("rank")
                    or human.get("guidance", generated_cve.get("guidance")) != generated_cve.get("guidance")
                    or ("candidates" in human.get("module", {}) and human["module"]["candidates"] != generated_cve["module"]["candidates"])):
                fail(f"{cve_id}: read-only identity/evidence changed")
            applied = apply_human_confirmation(exploit_config_from_dict(config_raw), human,
                                               payload_introspector=introspector)
            outcomes.append({"cve": cve_id, "skipped": applied.skip_reason is not None,
                             "ready": applied.validation.ready,
                             "readiness": applied.validation.readiness.value,
                             "issues": [issue.to_dict() for issue in applied.validation.issues]})
        report["outcome"] = "success"
        report["state_status"] = state.status.value
        report["stage"] = state.current_stage.value
        report["validation"] = outcomes
    except Exception as exc:
        report["outcome"] = "error"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
    finally:
        report["elapsed_seconds"] = round(time.time() - start, 3)
        print(json.dumps(report, sort_keys=True), flush=True)
    if report.get("outcome") != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
