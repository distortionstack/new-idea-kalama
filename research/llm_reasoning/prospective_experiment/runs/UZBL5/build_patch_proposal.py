from __future__ import annotations

import hashlib
import json
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import yaml


RUN_ID = "UZBL5"
RUN_ROOT = Path(__file__).resolve().parent
REPO_ROOT = RUN_ROOT.parents[4]
SEED = RUN_ROOT / "checkpoints" / "PATCH_REASONING_SEED"
FROZEN = SEED / "frozen_evidence"
RUNTIME = SEED / "runtime_evidence"
DISCOVERY = RUN_ROOT / "source_discovery"
HUMAN = RUN_ROOT / "human_patch_reasoning"
FORM_PATH = HUMAN / f"proposed_patch_form_{RUN_ID}_r1.yaml"
PLAN_PATH = FROZEN / "PATCH_PLAN__patch_plan_2026-09-16_UZBL5.json"
BASE_FORM_PATH = FROZEN / "PATCH_FORM__patch_form_UZBL5_r1.yaml"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


graph = json.loads((DISCOVERY / "source_graph.json").read_text(encoding="utf-8"))
sources = {source["source_id"]: source for source in graph["sources"]}


def graph_hash(source_id: str) -> str:
    value = sources[source_id]["content_hash"]
    assert value and value.startswith("sha256:")
    return value.removeprefix("sha256:")


runtime_hash_doc = json.loads((RUNTIME / "webapp_artifact_sha256.json").read_text(encoding="utf-8"))
runtime_hashes: dict[str, str] = {}
for line in runtime_hash_doc["stdout"].splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  (/.+)", line)
    if match:
        runtime_hashes[match.group(2)] = match.group(1)


DONOR = "/usr/local/tomcat/webapps/S2-048/WEB-INF/lib"


def donor_hash(filename: str) -> str:
    return runtime_hashes[f"{DONOR}/{filename}"]


CORE_2332 = [
    "struts2-core-2.3.32.jar",
    "xwork-core-2.3.32.jar",
    "freemarker-2.3.22.jar",
    "ognl-3.0.19.jar",
    "commons-fileupload-1.3.2.jar",
    "commons-io-2.2.jar",
    "commons-lang3-3.2.jar",
    "asm-3.3.jar",
    "asm-commons-3.3.jar",
]

SHOWCASE_2332 = [
    "commons-collections-3.2.2.jar",
    "commons-fileupload-1.3.2.jar",
    "commons-io-2.2.jar",
    "commons-lang-2.4.jar",
    "commons-lang3-3.2.jar",
    "commons-logging-1.1.3.jar",
    "freemarker-2.3.22.jar",
    "jcl-over-slf4j-1.5.8.jar",
    "log4j-1.2.17.jar",
    "ognl-3.0.19.jar",
    "slf4j-api-1.7.12.jar",
    "struts2-config-browser-plugin-2.3.32.jar",
    "struts2-convention-plugin-2.3.32.jar",
    "struts2-core-2.3.32.jar",
    "struts2-dojo-plugin-2.3.32.jar",
    "struts2-dwr-plugin-2.3.32.jar",
    "struts2-jsf-plugin-2.3.32.jar",
    "struts2-json-plugin-2.3.32.jar",
    "struts2-sitemesh-plugin-2.3.32.jar",
    "struts2-spring-plugin-2.3.32.jar",
    "struts2-struts1-plugin-2.3.32.jar",
    "struts2-tiles-plugin-2.3.32.jar",
    "tiles-api-2.2.2.jar",
    "tiles-core-2.2.2.jar",
    "tiles-el-2.2.2.jar",
    "tiles-freemarker-2.2.2.jar",
    "tiles-jsp-2.2.2.jar",
    "tiles-ognl-2.2.2.jar",
    "tiles-servlet-2.2.2.jar",
    "tiles-template-2.2.2.jar",
    "velocity-1.6.4.jar",
    "xwork-core-2.3.32.jar",
]


OLD = {
    "patch-001": [
        "commons-collections-3.1.jar", "commons-fileupload-1.2.2.jar", "commons-io-2.0.1.jar",
        "commons-lang-2.5.jar", "commons-logging-1.1.1.jar", "freemarker-2.3.18.jar",
        "log4j-1.2.9.jar", "ognl-3.0.3.jar", "struts2-config-browser-plugin-2.3.1.jar",
        "struts2-convention-plugin-2.3.1.jar", "struts2-core-2.3.1.jar",
        "struts2-dojo-plugin-2.3.1.jar", "struts2-dwr-plugin-2.3.1.jar",
        "struts2-jsf-plugin-2.3.1.jar", "struts2-json-plugin-2.3.1.jar",
        "struts2-sitemesh-plugin-2.3.1.jar", "struts2-spring-plugin-2.3.1.jar",
        "struts2-struts1-plugin-2.3.1.jar", "struts2-tiles-plugin-2.3.1.jar",
        "tiles-api-2.0.6.jar", "tiles-core-2.0.6.jar", "tiles-jsp-2.0.6.jar",
        "velocity-1.6.3.jar", "xwork-core-2.3.1.jar",
    ],
    "patch-002": [
        "struts2-core-2.3.14.2.jar", "xwork-core-2.3.14.2.jar", "freemarker-2.3.19.jar",
        "ognl-3.0.6.jar", "commons-fileupload-1.2.2.jar", "commons-io-2.0.1.jar",
        "commons-lang3-3.1.jar",
    ],
    "patch-003": [
        "struts2-core-2.3.15.1.jar", "xwork-core-2.3.15.1.jar", "freemarker-2.3.19.jar",
        "ognl-3.0.6.jar", "commons-fileupload-1.3.jar", "commons-io-2.0.1.jar",
        "commons-lang3-3.1.jar",
    ],
    "patch-005": [
        "struts2-core-2.3.24.1.jar", "xwork-core-2.3.24.1.jar", "ognl-3.0.6.jar",
        "commons-fileupload-1.3.1.jar",
    ],
    "patch-006": ["struts2-core-2.3.30.jar", "xwork-core-2.3.30.jar"],
}

APPS = {
    "patch-001": ["S2-009"],
    "patch-002": ["S2-015", "S2-016"],
    "patch-003": ["S2-019"],
    "patch-005": ["S2-029"],
    "patch-006": ["S2-046"],
}


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def patch_command(action_id: str) -> str:
    new_files = SHOWCASE_2332 if action_id == "patch-001" else CORE_2332
    lines = ["set -eu", f"donor={shell_quote(DONOR)}"]
    for filename in new_files:
        lines.append(
            "printf '%s  %s\\n' "
            + shell_quote(donor_hash(filename))
            + f' "$donor/{filename}" | sha256sum -c -'
        )
    for app in APPS[action_id]:
        root = f"/usr/local/tomcat/webapps/{app}"
        backup = f"/usr/local/tomcat/kalama-backup-{RUN_ID}/{app}"
        lines.extend(
            [
                f"root={shell_quote(root)}",
                'lib="$root/WEB-INF/lib"',
                f"backup={shell_quote(backup)}",
                'test -d "$lib"',
                'mkdir -p "$backup"',
                'war="$root.war"',
                f'disabled="$root.war.kalama-{RUN_ID}.disabled"',
                'if [ -f "$war" ]; then test ! -e "$disabled"; mv "$war" "$disabled"; fi',
            ]
        )
        for filename in OLD[action_id]:
            lines.append(f'if [ -f "$lib/{filename}" ]; then cp -p "$lib/{filename}" "$backup/{filename}"; rm -f "$lib/{filename}"; fi')
        for filename in new_files:
            lines.append(f'cp -p "$donor/{filename}" "$lib/{filename}"')
    return "\n".join(lines)


def validation_command(action_id: str) -> str:
    new_files = SHOWCASE_2332 if action_id == "patch-001" else CORE_2332
    lines = ["set -eu"]
    for app in APPS[action_id]:
        root = f"/usr/local/tomcat/webapps/{app}"
        lines.extend(
            [
                f"root={shell_quote(root)}",
                'lib="$root/WEB-INF/lib"',
                f'test -f "$root.war.kalama-{RUN_ID}.disabled"',
                'test ! -e "$root.war"',
            ]
        )
        for filename in OLD[action_id]:
            lines.append(f'test ! -e "$lib/{filename}"')
        for filename in new_files:
            lines.append(
                "printf '%s  %s\\n' "
                + shell_quote(donor_hash(filename))
                + f' "$lib/{filename}" | sha256sum -c -'
            )
    return "\n".join(lines)


target_versions = {
    "patch-001": "2.3.32",
    "patch-002": "2.3.32",
    "patch-003": "2.3.32",
    "patch-004": "2.3.34",
    "patch-005": "2.3.32",
    "patch-006": "2.3.32",
    "patch-007": "2.5.10.1",
    "patch-008": "2.3.34",
}
ready_actions = set(APPS)

primary_source = {
    "patch-001": "seed://UZBL5/runtime_evidence/webapp_artifact_sha256.json#/usr/local/tomcat/webapps/S2-048/WEB-INF/lib",
    "patch-002": "seed://UZBL5/runtime_evidence/webapp_artifact_sha256.json#/usr/local/tomcat/webapps/S2-048/WEB-INF/lib",
    "patch-003": "seed://UZBL5/runtime_evidence/webapp_artifact_sha256.json#/usr/local/tomcat/webapps/S2-048/WEB-INF/lib",
    "patch-004": sources["S106"]["url"],
    "patch-005": "seed://UZBL5/runtime_evidence/webapp_artifact_sha256.json#/usr/local/tomcat/webapps/S2-048/WEB-INF/lib",
    "patch-006": "seed://UZBL5/runtime_evidence/webapp_artifact_sha256.json#/usr/local/tomcat/webapps/S2-048/WEB-INF/lib",
    "patch-007": sources["S110"]["url"],
    "patch-008": sources["S155"]["url"],
}
primary_checksum = {
    **{action: f"sha256:{donor_hash('struts2-core-2.3.32.jar')}" for action in ready_actions},
    "patch-004": f"sha256:{graph_hash('S106')}",
    "patch-007": f"sha256:{graph_hash('S110')}",
    "patch-008": f"sha256:{graph_hash('S155')}",
}
source_identifier = {
    **{action: "PATCH_REASONING_SEED:S2-048 donor; SOURCE_GRAPH:S004,S013,S100-S103,S112-S114,S118-S147" for action in ready_actions},
    "patch-004": "SOURCE_GRAPH:S002,S006,S013,S104-S107,S115-S117,S148-S156; missing S208-S210,S241-S243",
    "patch-007": "SOURCE_GRAPH:S001,S005,S013,S108-S111; missing S226-S228",
    "patch-008": "SOURCE_GRAPH:S002,S006,S013,S104-S107,S115-S117,S148-S156; missing S208-S210,S241-S243",
}


def build_form() -> dict:
    form = yaml.safe_load(BASE_FORM_PATH.read_text(encoding="utf-8"))
    for action_id, action in form["actions"].items():
        action["fix_type"]["confirmed"] = "B"
        action["target_version"]["confirmed"] = target_versions[action_id]
        action["strategy"]["confirmed"] = "HUMAN_COMMAND"
        action["artifact"]["confirmed_source"] = primary_source[action_id]
        action["artifact"]["source_identifier"] = source_identifier[action_id]
        action["artifact"]["checksum"]["confirmed"] = primary_checksum[action_id]
        action["major_version_approved"] = None
        if action_id in ready_actions:
            action["command"]["confirmed"] = patch_command(action_id)
            action["validation_command"]["confirmed"] = validation_command(action_id)
            action["notes"] = (
                "Evidence-anchored local artifact replacement. Preserve the original WAR by renaming it, patch the "
                "exploded deployment while Tomcat is not running in patch-workspace, and verify every donor JAR "
                "against frozen runtime SHA-256. Tomcat 8.5.20 deployment semantics: SOURCE_GRAPH S014-S017. "
                "Upstream target/POM/repository: S001/S004/S013/S100-S114; related module metadata/artifacts S118-S147."
            )
        else:
            action["command"]["confirmed"] = None
            action["validation_command"]["confirmed"] = None
            if action_id in {"patch-004", "patch-008"}:
                action["notes"] = (
                    "Target 2.3.34 is selected to keep overlapping core and REST-plugin deployments aligned, but no "
                    "command is proposed: required OGNL 3.0.21 and XStream 1.4.10 artifacts were not retrievable "
                    "through the authorized Apache staging source (S208-S210, S241-S243 = HTTP 404)."
                )
            else:
                action["notes"] = (
                    "Target 2.5.10.1 is supported by S001/S005/S108-S111, but no command is proposed: its required "
                    "Freemarker 2.3.23 artifact was not retrievable through the authorized Apache staging source "
                    "(S226-S228 = HTTP 404), and it is absent from the frozen runtime inventory."
                )
    return form


def validate_form(form: dict) -> dict:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from kalama.remediation.codec import patch_plan_from_artifact
    from kalama.remediation.confirmation import apply_patch_confirmations

    base = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    try:
        result = apply_patch_confirmations(patch_plan_from_artifact(base), form)
        return {
            "schema": "kalama.task-7.5.5-production-validation/v1",
            "run_id": RUN_ID,
            "validated_at": utc_now(),
            "validator": "kalama.remediation.confirmation.apply_patch_confirmations + kalama.remediation.codec.validate_patch_plan",
            "canonical_state_mutated": False,
            "proposal_sha256": sha256(FORM_PATH.read_bytes()),
            "overall_readiness": result.readiness.value,
            "actions": [
                {
                    "action_id": action.action_id,
                    "status": action.status.value,
                    "validation_reasons": [reason.value for reason in action.input_reasons],
                    "target_version": action.candidate.target_version if action.candidate else None,
                    "strategy": action.strategy.value if action.strategy else None,
                }
                for action in result.actions
            ],
        }
    except Exception as exc:
        return {
            "schema": "kalama.task-7.5.5-production-validation/v1",
            "run_id": RUN_ID,
            "validated_at": utc_now(),
            "canonical_state_mutated": False,
            "overall_readiness": "VALIDATOR_EXCEPTION",
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    HUMAN.mkdir(parents=True, exist_ok=True)
    form = build_form()
    FORM_PATH.write_text(yaml.safe_dump(form, sort_keys=False, allow_unicode=True), encoding="utf-8")

    integrity = {
        "schema": "kalama.task-7.5.5-artifact-integrity/v1",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "checks": [
            {
                "artifact": "struts2-core-2.3.32.jar",
                "runtime_path": f"{DONOR}/struts2-core-2.3.32.jar",
                "runtime_sha256": donor_hash("struts2-core-2.3.32.jar"),
                "retrieved_source_id": "S102",
                "retrieved_sha256": graph_hash("S102"),
                "matches": donor_hash("struts2-core-2.3.32.jar") == graph_hash("S102"),
            },
            {
                "artifact": "xwork-core-2.3.32.jar",
                "runtime_path": f"{DONOR}/xwork-core-2.3.32.jar",
                "runtime_sha256": donor_hash("xwork-core-2.3.32.jar"),
                "retrieved_source_id": "S113",
                "retrieved_sha256": graph_hash("S113"),
                "matches": donor_hash("xwork-core-2.3.32.jar") == graph_hash("S113"),
            },
        ],
        "repository_sha1_sidecars": "Retrieved for all direct Struts artifacts; see source_graph.json and retrieved_sources_manifest.json",
    }
    write_json(HUMAN / "artifact_integrity.json", integrity)

    decision_log = {
        "schema": "kalama.task-7.5.5-decision-log/v1",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "decisions": [
            {
                "question": "Which CVEs are remediation targets?",
                "evidence_used": "Fresh BEFORE exploitation succeeded for CVE-2017-5638 and CVE-2017-9805; 14 other candidates were skipped because fresh endpoint/module binding was absent.",
                "source_ids": ["PATCH_REASONING_SEED:ATTACK_BEFORE", "PATCH_REASONING_SEED:ATTACK_FORM"],
                "conclusion": "Limit patch reasoning to the eight production Patch Actions for those two exploitation-confirmed CVEs.",
                "classification": "EXTRACTED",
                "confidence": "HIGH",
                "unresolved_assumptions": [],
            },
            {
                "question": "What versions should the 2.3.x core actions use?",
                "evidence_used": "S2-045 names 2.3.32 as the fixed 2.3 release. S2-052 names 2.3.34 for REST. POMs keep all modules on project.version.",
                "source_ids": ["S001", "S002", "S004", "S006", "S100", "S104", "S154"],
                "conclusion": "Use 2.3.32 for actions 001/002/003/005/006. Use 2.3.34 for action 004 because it overlaps four REST deployments that action 008 must move to 2.3.34.",
                "classification": "COMBINED_EVIDENCE",
                "confidence": "HIGH",
                "unresolved_assumptions": [],
            },
            {
                "question": "What version should the 2.5.10 core action use?",
                "evidence_used": "S2-045 and its 2.5.10.1 release notes identify 2.5.10.1; scanner reports the same fixed version.",
                "source_ids": ["S001", "S005", "S108", "S109"],
                "conclusion": "Select 2.5.10.1 for action 007, but do not draft execution without Freemarker 2.3.23.",
                "classification": "COMBINED_EVIDENCE",
                "confidence": "HIGH",
                "unresolved_assumptions": [],
            },
            {
                "question": "Can 2.3.32 artifacts be obtained without an unanchored source?",
                "evidence_used": "Frozen runtime contains S2-048 with a 2.3.32 module/dependency set and SHA-256 for every JAR. Retrieved upstream core/xwork JAR hashes match the frozen donor copies.",
                "source_ids": ["PATCH_REASONING_SEED:webapp_layout", "PATCH_REASONING_SEED:webapp_artifact_sha256", "S102", "S113"],
                "conclusion": "Use S2-048 as a current-runtime donor for actions 001/002/003/005/006; preserve and verify every copied file.",
                "classification": "OPERATOR_DECISION",
                "confidence": "HIGH",
                "unresolved_assumptions": ["Application-specific smoke behavior is intentionally deferred to AFTER/re-exploit and is not claimed here."],
            },
            {
                "question": "How should WAR and exploded deployments be handled?",
                "evidence_used": "Frozen layout shows each affected WAR and exploded directory. Tomcat 8.5.20 docs say exploded apps in appBase are deployed and a newer associated WAR may delete/re-expand the exploded directory.",
                "source_ids": ["PATCH_REASONING_SEED:webapp_layout", "S014", "S015", "S016", "S017"],
                "conclusion": "In the non-running patch workspace, rename the original WAR to a preserved non-.war filename, patch the exploded directory, and validate both states before finalization.",
                "classification": "OPERATOR_INFERENCE",
                "confidence": "MEDIUM_HIGH",
                "unresolved_assumptions": ["The final endpoint smoke test remains a downstream check and is not performed in Task 7.5.5."],
            },
            {
                "question": "Should commands be drafted for actions 004/007/008?",
                "evidence_used": "Target POMs require OGNL 3.0.21, XStream 1.4.10, or Freemarker 2.3.23. Authorized Apache staging paths returned 404 and frozen runtime has none of those versions.",
                "source_ids": ["S104", "S108", "S154", "S208", "S209", "S210", "S226", "S227", "S228", "S241", "S242", "S243", "PATCH_REASONING_SEED:webapp_layout"],
                "conclusion": "Leave command and validation_command unset for actions 004/007/008 rather than use Maven Central from model knowledge.",
                "classification": "OPERATOR_DECISION",
                "confidence": "HIGH",
                "unresolved_assumptions": [],
            },
        ],
    }
    write_json(HUMAN / "decision_log.json", decision_log)

    missing = {
        "schema": "kalama.task-7.5.5-missing-evidence/v1",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "items": [
            {
                "code": "DEPENDENCY_ARTIFACT_UNREACHABLE",
                "actions": ["patch-004", "patch-008"],
                "missing": ["ognl:ognl:3.0.21", "com.thoughtworks.xstream:xstream:1.4.10"],
                "evidence": ["S104", "S154", "S208-S210", "S241-S243"],
                "impact": "No evidence-supported executable 2.3.34 core/REST closure can be assembled.",
            },
            {
                "code": "DEPENDENCY_ARTIFACT_UNREACHABLE",
                "actions": ["patch-007"],
                "missing": ["org.freemarker:freemarker:2.3.23"],
                "evidence": ["S108", "S109", "S226-S228"],
                "impact": "No evidence-supported executable 2.5.10.1 core closure can be assembled.",
            },
            {
                "code": "SOURCE_PATH_MISSING",
                "actions": ["patch-004", "patch-007", "patch-008"],
                "missing": ["A valid evidence-anchored route from the current graph to a repository containing the missing third-party artifacts"],
                "evidence": ["S004-S007", "S013"],
                "impact": "Open-web/Maven-Central guessing is prohibited; correct abstention is required.",
            },
        ],
    }
    write_json(HUMAN / "missing_evidence.json", missing)

    validation = validate_form(form)
    write_json(HUMAN / "production_validation.json", validation)

    artifact_manifest = {
        "schema": "kalama.task-7.5.5-human-reasoning-manifest/v1",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "entries": [],
    }
    for path in sorted(HUMAN.iterdir()):
        if path.name in {"manifest.json", "manifest.sha256"} or not path.is_file():
            continue
        artifact_manifest["entries"].append(
            {"path": path.name, "sha256": sha256(path.read_bytes()), "size_bytes": path.stat().st_size}
        )
    manifest_bytes = (json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n").encode()
    (HUMAN / "manifest.json").write_bytes(manifest_bytes)
    (HUMAN / "manifest.sha256").write_text(sha256(manifest_bytes) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
