from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


RUN_ID = "UZBL5"
OUTPUT_ROOT = Path("output/2d8ru-struts2-evidence-anchored-755").resolve()
RUN_ROOT = Path("research/llm_reasoning/prospective_experiment/runs/UZBL5").resolve()
CHECKPOINT = RUN_ROOT / "checkpoints/PATCH_REASONING_SEED"
FROZEN = CHECKPOINT / "frozen_evidence"
RUNTIME = CHECKPOINT / "runtime_evidence"
STATE_PATH = OUTPUT_ROOT / f"state/run_{RUN_ID}.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if CHECKPOINT.exists():
    raise SystemExit(f"checkpoint already exists: {CHECKPOINT}")

FROZEN.mkdir(parents=True)
RUNTIME.mkdir(parents=True)
state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
if (
    state.get("run_id") != RUN_ID
    or state.get("status") != "WAITING_FOR_USER_INPUT"
    or state.get("current_stage") != "STEP_5_PATCH_PLAN"
    or state.get("waiting_reason") != "PATCH_FORM"
):
    raise SystemExit("run is not at the immutable patch-reasoning boundary")

provenance: dict[str, dict] = {}


def record(path: Path, value: dict) -> None:
    provenance[path.relative_to(CHECKPOINT).as_posix()] = value


def copy(source: Path, destination_name: str, *, kind: str) -> Path:
    destination = FROZEN / destination_name
    shutil.copy2(source, destination)
    record(destination, {"method": "COPY", "source": str(source.resolve()), "kind": kind})
    return destination


copy(STATE_PATH, STATE_PATH.name, kind="CANONICAL_RUN_STATE")
for kind, artifact in sorted(state["artifacts"].items()):
    source = Path(artifact["path"])
    copy(source, f"{kind}__{source.name}", kind=kind)

# Preserve the complete current-run Attack Form revision trail, not merely the
# latest canonical references.
extra_patterns = (
    "resolver/forms/attack_form_UZBL5_r*.yaml",
    "resolver/forms/submissions/*UZBL5*.yaml",
    "resolver/config/*UZBL5*.json",
)
already = {Path(item["source"]).resolve() for item in provenance.values() if item["method"] == "COPY"}
for pattern in extra_patterns:
    for source in sorted(OUTPUT_ROOT.glob(pattern)):
        if source.resolve() in already:
            continue
        copy(source, f"REVISION_TRAIL__{source.name}", kind="ATTACK_REVISION_TRAIL")
        already.add(source.resolve())


def run_capture(name: str, command: list[str], *, purpose: str) -> Path:
    completed = subprocess.run(command, text=True, encoding="utf-8", errors="replace",
                               capture_output=True, check=False)
    path = RUNTIME / name
    value = {
        "schema": "kalama.local-command-evidence/v1",
        "run_id": RUN_ID,
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "command": command,
        "purpose": purpose,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    record(path, {"method": "LOCAL_COMMAND", "command": command, "purpose": purpose})
    if completed.returncode != 0:
        raise SystemExit(f"runtime evidence command failed ({name}): {completed.stderr}")
    return path


run_capture("docker_container_inspect.json", ["docker", "inspect", "victim-UZBL5"],
            purpose="container identity, configuration, mounts, networking, and state")
run_capture(
    "docker_image_inspect.json",
    ["docker", "image", "inspect",
     "2d8ru/struts2@sha256:7aa386b4b606bec5f6a7f015bab6bd1cc84169beadb2a632b6939e6e703e47db"],
    purpose="image identity and immutable digest binding",
)
run_capture("docker_version.json", ["docker", "version", "--format", "{{json .}}"],
            purpose="Docker client/server identity")
run_capture("trivy_version.json",
            ["docker", "exec", "kalama-workbench-modern", "trivy", "--version"],
            purpose="scanner identity and version")
run_capture(
    "os_java_tomcat.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "uname -a; cat /etc/os-release; java -version; /usr/local/tomcat/bin/version.sh"],
    purpose="operating system, Java, and Tomcat runtime versions",
)
run_capture(
    "installed_packages.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "dpkg-query -W -f='${Package}\\t${Version}\\n' | LC_ALL=C sort"],
    purpose="installed OS package inventory",
)
run_capture(
    "webapp_artifact_sha256.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "find /usr/local/tomcat/webapps -type f \\( -name '*.jar' -o -name '*.war' \\) "
     "-exec sha256sum {} + | LC_ALL=C sort"],
    purpose="installed WAR/JAR paths and locally computed SHA-256 values",
)
run_capture(
    "webapp_layout.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "find /usr/local/tomcat/webapps -maxdepth 4 -type d -o -type f | LC_ALL=C sort"],
    purpose="WAR and exploded deployment layout",
)
run_capture(
    "relevant_configuration_sha256.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "find /usr/local/tomcat -type f \\( -name 'server.xml' -o -name 'context.xml' "
     "-o -name 'web.xml' -o -name 'struts.xml' -o -name '*.properties' \\) "
     "-exec sha256sum {} + | LC_ALL=C sort"],
    purpose="relevant local configuration paths and hashes",
)
run_capture(
    "mounts.json",
    ["docker", "exec", "victim-UZBL5", "cat", "/proc/mounts"],
    purpose="runtime mount observations",
)
run_capture(
    "local_tool_inventory.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "for t in curl wget unzip zip jar mvn gradle sha256sum; do "
     "printf '%s\\t' \"$t\"; command -v \"$t\" || true; done"],
    purpose="locally available remediation and verification tools",
)
run_capture(
    "endpoint_observations.json",
    ["docker", "exec", "victim-UZBL5", "sh", "-lc",
     "curl -sS -o /dev/null -w 'S2-045 %{http_code}\\n' http://127.0.0.1:8080/S2-045/; "
     "curl -sS -o /dev/null -w 'S2-052 %{http_code}\\n' http://127.0.0.1:8080/S2-052/orders/3"],
    purpose="fresh reachable endpoints used by the reviewed Attack Form",
)

# Create a convenient, strictly derived root-source index without adding any
# URL absent from the raw scanner output.
raw_scan = Path(state["artifacts"]["TRIVY_BEFORE"]["path"])
scan = json.loads(raw_scan.read_text(encoding="utf-8"))
target_cves = {"CVE-2017-5638", "CVE-2017-9805"}
roots = []
seen = set()
for result in scan.get("Results", []):
    for vulnerability in result.get("Vulnerabilities") or []:
        if vulnerability.get("VulnerabilityID") not in target_cves:
            continue
        key = (
            vulnerability.get("VulnerabilityID"),
            vulnerability.get("PkgName"),
            vulnerability.get("InstalledVersion"),
            vulnerability.get("PkgPath"),
        )
        if key in seen:
            continue
        seen.add(key)
        roots.append({
            "cve_id": vulnerability.get("VulnerabilityID"),
            "package": vulnerability.get("PkgName"),
            "installed_version": vulnerability.get("InstalledVersion"),
            "fixed_version": vulnerability.get("FixedVersion"),
            "package_path": vulnerability.get("PkgPath"),
            "purl": (vulnerability.get("PkgIdentifier") or {}).get("PURL"),
            "primary_url": vulnerability.get("PrimaryURL"),
            "data_source": vulnerability.get("DataSource"),
            "references": vulnerability.get("References") or [],
        })
roots_path = FROZEN / "scanner_source_roots.json"
roots_path.write_text(json.dumps({
    "schema": "kalama.patch-reasoning-source-roots/v1",
    "run_id": RUN_ID,
    "derivation": "Exact URL fields from TRIVY_BEFORE records for exploitation-confirmed CVEs",
    "records": roots,
}, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
record(roots_path, {"method": "DERIVED_FROM_FROZEN_SCANNER",
                    "source": str(raw_scan.resolve()),
                    "fields": ["PrimaryURL", "DataSource", "References"]})

entries = []
for path in sorted(p for p in CHECKPOINT.rglob("*") if p.is_file()):
    relative = path.relative_to(CHECKPOINT).as_posix()
    entries.append({
        "path": relative,
        "sha256": sha256(path),
        "size": path.stat().st_size,
        "provenance": provenance[relative],
    })

manifest = {
    "schema": "kalama.patch-reasoning-seed-manifest/v1",
    "checkpoint": "PATCH_REASONING_SEED",
    "immutable_after_creation": True,
    "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "run_id": RUN_ID,
    "image_binding": state["target"]["image_identity"],
    "container_binding": {
        "container_id": state["target"]["facts"]["container_id"],
        "container_name": state["target"]["facts"]["container_name"],
        "ip_address": state["target"]["facts"]["ip_address"],
    },
    "pipeline_boundary": {
        "status": state["status"],
        "current_stage": state["current_stage"],
        "waiting_reason": state["waiting_reason"],
    },
    "entries": entries,
}
manifest_path = CHECKPOINT / "manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                         encoding="utf-8")
manifest_hash = sha256(manifest_path)
(CHECKPOINT / "manifest.sha256").write_text(
    f"{manifest_hash}  manifest.json\n", encoding="utf-8")

for path in CHECKPOINT.rglob("*"):
    if path.is_file():
        os.chmod(path, stat.S_IREAD)

print(json.dumps({
    "checkpoint": str(CHECKPOINT),
    "manifest_sha256": manifest_hash,
    "entries": len(entries),
    "root_records": len(roots),
}, indent=2))
