"""Research-only upstream source resolver replay for Task 7.5.6A.

This script intentionally does not import or modify Kalama production modules.
It reads frozen UZBL5 artifacts, derives native Maven registry paths only from
baseline structured evidence, retrieves POM/JAR/checksum sources, and writes a
separate replay source graph.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


RUN_ID = "UZBL5"
SCHEMA_GRAPH = "kalama.task-7.5.6a-replay-source-graph/v1"
SCHEMA_VALIDATION = "kalama.task-7.5.6a-replay-source-graph-validation/v1"
SCHEMA_REACHABILITY = "kalama.task-7.5.6a-artifact-reachability/v1"
SCHEMA_COMPARISON = "kalama.task-7.5.6a-missing-evidence-comparison/v1"
SCHEMA_IDENTITIES = "kalama.task-7.5.6a-upstream-identities/v1"

MAVEN_NATIVE_ROOT = "https://repo.maven.apache.org/maven2"
DEPS_DEV_ROOT = "https://api.deps.dev/v3"
USER_AGENT = "kalama-task-7.5.6a-replay/1.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def coordinate_to_path(group_id: str, artifact_id: str, version: str, suffix: str) -> str:
    group_path = group_id.replace(".", "/")
    base = f"{group_path}/{artifact_id}/{version}/{artifact_id}-{version}"
    return f"{base}{suffix}"


def coordinate_to_purl(group_id: str, artifact_id: str, version: str) -> str:
    return f"pkg:maven/{group_id}/{artifact_id}@{version}"


def coordinate_to_name(group_id: str, artifact_id: str) -> str:
    return f"{group_id}:{artifact_id}"


def parse_coordinate(text: str) -> tuple[str, str, str] | None:
    match = re.search(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)", text)
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3)


def fetch(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            final_url = resp.geturl()
            return {
                "ok": True,
                "status": getattr(resp, "status", 200),
                "data": data,
                "content_type": resp.headers.get("content-type"),
                "final_url": final_url,
                "redirect_chain": [] if final_url == url else [url, final_url],
                "elapsed_ms": int((time.time() - started) * 1000),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return {
            "ok": False,
            "status": exc.code,
            "data": body,
            "content_type": exc.headers.get("content-type") if exc.headers else None,
            "final_url": exc.geturl(),
            "redirect_chain": [] if exc.geturl() == url else [url, exc.geturl()],
            "elapsed_ms": int((time.time() - started) * 1000),
            "error": f"HTTPError: {exc.code} {exc.reason}",
        }
    except Exception as exc:  # noqa: BLE001 - research harness records failures
        return {
            "ok": False,
            "status": None,
            "data": b"",
            "content_type": None,
            "final_url": None,
            "redirect_chain": [],
            "elapsed_ms": int((time.time() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def source_record(
    *,
    source_id: str,
    url: str,
    parent_source_id: str | None,
    parent_evidence: str | None,
    root_class: str,
    derivation: str,
    discovery_method: str,
    allowed_operations: list[str],
    authority_class: str,
    confidence: str,
    purpose: str,
    status: str,
    retrieved_at: str | None = None,
    http_status: int | None = None,
    final_url: str | None = None,
    redirect_chain: list[str] | None = None,
    content_hash: str | None = None,
    artifact_path: str | None = None,
    error: str | None = None,
) -> dict:
    return {
        "source_id": source_id,
        "url": url,
        "parent_source_id": parent_source_id,
        "parent_evidence": parent_evidence,
        "root_class": root_class,
        "derivation": derivation,
        "discovery_method": discovery_method,
        "allowed_operations": allowed_operations,
        "authority_class": authority_class,
        "confidence": confidence,
        "purpose": purpose,
        "status": status,
        "retrieved_at": retrieved_at,
        "http_status": http_status,
        "final_url": final_url,
        "redirect_chain": redirect_chain or [],
        "content_hash": content_hash,
        "artifact_path": artifact_path,
        "error": error,
    }


def main() -> int:
    repo = Path.cwd()
    out_dir = repo / "research" / "llm_reasoning" / "prospective_experiment" / "task_7_5_6a_upstream_replay"
    sources_dir = out_dir / "retrieved_sources"
    seed_dir = repo / "research" / "llm_reasoning" / "prospective_experiment" / "runs" / RUN_ID / "checkpoints" / "PATCH_REASONING_SEED"
    baseline_graph_path = repo / "research" / "llm_reasoning" / "prospective_experiment" / "runs" / RUN_ID / "source_discovery" / "source_graph.json"
    missing_path = repo / "research" / "llm_reasoning" / "prospective_experiment" / "runs" / RUN_ID / "human_patch_reasoning" / "missing_evidence.json"
    validation_path = repo / "research" / "llm_reasoning" / "prospective_experiment" / "runs" / RUN_ID / "human_patch_reasoning" / "production_validation.json"
    design_review_path = repo / "research" / "llm_reasoning" / "prospective_experiment" / "task_7_5_6_upstream_source_resolver_review.md"

    baseline_graph = read_json(baseline_graph_path)
    missing = read_json(missing_path)
    production_validation = read_json(validation_path)

    baseline_sources = {src["source_id"]: src for src in baseline_graph["sources"]}
    dependencies: dict[tuple[str, str, str], dict] = {}
    for item in missing["items"]:
        for missing_coord in item.get("missing", []):
            coord = parse_coordinate(missing_coord)
            if not coord:
                continue
            dependencies.setdefault(
                coord,
                {
                    "actions": set(),
                    "codes": set(),
                    "baseline_evidence": set(),
                },
            )
            dependencies[coord]["actions"].update(item.get("actions", []))
            dependencies[coord]["codes"].add(item.get("code"))
            dependencies[coord]["baseline_evidence"].update(item.get("evidence", []))

    # Attach concrete baseline fetch-failed source ids for parentage.
    for src in baseline_graph["sources"]:
        coord = parse_coordinate(src.get("purpose", ""))
        if coord and coord in dependencies:
            dependencies[coord].setdefault("baseline_source_ids", set()).add(src["source_id"])
            parent = src.get("parent_source_id")
            if parent:
                dependencies[coord].setdefault("parent_pom_source_ids", set()).add(parent)

    replay_sources: list[dict] = []
    identities: list[dict] = []
    reachability: list[dict] = []
    retrieved_manifest: list[dict] = []
    source_counter = 1

    for (group_id, artifact_id, version), meta in sorted(dependencies.items()):
        name = coordinate_to_name(group_id, artifact_id)
        purl = coordinate_to_purl(group_id, artifact_id, version)
        coord_slug = f"{group_id}-{artifact_id}-{version}".replace(".", "_").replace(":", "_")
        baseline_source_ids = sorted(meta.get("baseline_source_ids", []))
        parent_pom_source_ids = sorted(meta.get("parent_pom_source_ids", []))
        parent_evidence = (
            f"baseline_source_graph:{','.join(baseline_source_ids)}"
            f"; parent_poms:{','.join(parent_pom_source_ids)}"
        )

        version_root = f"{MAVEN_NATIVE_ROOT}/{group_id.replace('.', '/')}/{artifact_id}/{version}/"
        root_id = f"RROOT-{source_counter:03d}"
        source_counter += 1
        replay_sources.append(
            source_record(
                source_id=root_id,
                url=version_root,
                parent_source_id=None,
                parent_evidence=parent_evidence,
                root_class="DEPENDENCY_COORDINATE_DERIVED_NATIVE_REGISTRY_ROOT",
                derivation="DEPENDENCY_COORDINATE_DERIVED_MAVEN_PATH",
                discovery_method="STRUCTURED_BASELINE_COORDINATE",
                allowed_operations=["metadata", "pom", "artifact", "checksum"],
                authority_class="DERIVED_PACKAGE_AUTHORITY",
                confidence="HIGH",
                purpose=f"Native Maven registry root for {name}:{version}",
                status="DERIVED_ROOT",
            )
        )

        identity = {
            "schema": "kalama.upstream-identity.replay/v1",
            "package_identity": {
                "ecosystem": "maven",
                "name": name,
                "version": version,
                "purl": purl,
                "normalized_name": name,
            },
            "roots": [
                {
                    "root_id": root_id,
                    "kind": "native_registry",
                    "url": version_root,
                    "authority_class": "DERIVED_PACKAGE_AUTHORITY",
                    "derivation": "DEPENDENCY_COORDINATE_DERIVED_MAVEN_PATH",
                    "parent_evidence": parent_evidence,
                    "confidence": "HIGH",
                    "allowed_operations": ["metadata", "pom", "artifact", "checksum"],
                    "retrieved_at": None,
                    "http_status": None,
                    "final_url": None,
                    "redirect_chain": [],
                    "content_hash": None,
                }
            ],
            "candidates": [],
            "warnings": [],
        }

        operations = [
            ("pom", ".pom", "POM metadata", "metadata"),
            ("jar", ".jar", "artifact JAR", "artifact"),
            ("jar_sha1", ".jar.sha1", "artifact SHA-1 checksum", "checksum"),
        ]
        result = {
            "coordinate": f"{name}:{version}",
            "purl": purl,
            "actions": sorted(meta["actions"]),
            "baseline_missing_codes": sorted(code for code in meta["codes"] if code),
            "coordinate_parentage": {
                "baseline_source_ids": baseline_source_ids,
                "parent_pom_source_ids": parent_pom_source_ids,
                "parent_evidence": parent_evidence,
            },
            "native_registry_root": version_root,
            "retrieved": {},
            "artifact_reachable": False,
            "checksum_reachable": False,
            "artifact_sha1_matches_sidecar": None,
            "would_resolve_missing_evidence": False,
        }
        artifact_bytes = None
        checksum_text = None

        for op_name, suffix, label, allowed_operation in operations:
            url = f"{MAVEN_NATIVE_ROOT}/{coordinate_to_path(group_id, artifact_id, version, suffix)}"
            fetched = fetch(url)
            src_id = f"R{source_counter:03d}"
            source_counter += 1
            artifact_rel = None
            content_hash = None
            status = "RETRIEVED" if fetched["ok"] else "FETCH_FAILED"
            if fetched["ok"]:
                ext = suffix.replace(".", "_").strip("_")
                artifact_rel = f"retrieved_sources/{src_id}_{coord_slug}_{ext}"
                artifact_path = out_dir / artifact_rel
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_bytes(fetched["data"])
                content_hash = f"sha256:{sha256_bytes(fetched['data'])}"
                retrieved_manifest.append(
                    {
                        "source_id": src_id,
                        "path": artifact_rel,
                        "sha256": sha256_bytes(fetched["data"]),
                        "size_bytes": len(fetched["data"]),
                    }
                )
                if op_name == "jar":
                    artifact_bytes = fetched["data"]
                if op_name == "jar_sha1":
                    checksum_text = fetched["data"].decode("utf-8", errors="replace").strip()

            replay_sources.append(
                source_record(
                    source_id=src_id,
                    url=url,
                    parent_source_id=root_id,
                    parent_evidence=None,
                    root_class="DEPENDENCY_COORDINATE_DERIVED_NATIVE_REGISTRY_ROOT",
                    derivation="DEPENDENCY_COORDINATE_DERIVED_MAVEN_PATH",
                    discovery_method="NATIVE_REGISTRY_DETERMINISTIC_PATH",
                    allowed_operations=[allowed_operation],
                    authority_class="DERIVED_PACKAGE_AUTHORITY",
                    confidence="HIGH" if fetched["ok"] and not fetched["redirect_chain"] else "NEEDS_REVIEW" if fetched["redirect_chain"] else "MEDIUM",
                    purpose=f"Replay retrieval of {label} for {name}:{version}",
                    status=status,
                    retrieved_at=utc_now(),
                    http_status=fetched["status"],
                    final_url=fetched["final_url"],
                    redirect_chain=fetched["redirect_chain"],
                    content_hash=content_hash,
                    artifact_path=artifact_rel,
                    error=fetched["error"],
                )
            )
            result["retrieved"][op_name] = {
                "source_id": src_id,
                "url": url,
                "status": status,
                "http_status": fetched["status"],
                "final_url": fetched["final_url"],
                "content_hash": content_hash,
                "artifact_path": artifact_rel,
                "error": fetched["error"],
            }

        deps_name = urllib.parse.quote(name, safe="")
        deps_version = urllib.parse.quote(version, safe="")
        deps_url = f"{DEPS_DEV_ROOT}/systems/maven/packages/{deps_name}/versions/{deps_version}"
        deps_fetch = fetch(deps_url)
        deps_src_id = f"R{source_counter:03d}"
        source_counter += 1
        deps_artifact_rel = None
        deps_hash = None
        if deps_fetch["ok"]:
            deps_artifact_rel = f"retrieved_sources/{deps_src_id}_{coord_slug}_deps_dev.json"
            (out_dir / deps_artifact_rel).write_bytes(deps_fetch["data"])
            deps_hash = f"sha256:{sha256_bytes(deps_fetch['data'])}"
            retrieved_manifest.append(
                {
                    "source_id": deps_src_id,
                    "path": deps_artifact_rel,
                    "sha256": sha256_bytes(deps_fetch["data"]),
                    "size_bytes": len(deps_fetch["data"]),
                }
            )
            try:
                deps_doc = json.loads(deps_fetch["data"].decode("utf-8"))
                links = deps_doc.get("links", [])
                identity["candidates"].extend(
                    {
                        "kind": link.get("label") or link.get("type") or "deps_dev_link",
                        "url": link.get("url"),
                        "source": deps_src_id,
                        "confidence": "LOW",
                        "status": "CANDIDATE_ONLY_NOT_PROMOTED",
                    }
                    for link in links
                    if link.get("url")
                )
            except Exception as exc:  # noqa: BLE001
                identity["warnings"].append(f"deps.dev JSON parse failed: {exc}")

        replay_sources.append(
            source_record(
                source_id=deps_src_id,
                url=deps_url,
                parent_source_id=root_id,
                parent_evidence=None,
                root_class="DEPS_DEV_DISCOVERY_ROOT",
                derivation="PURL_TO_DEPS_DEV_VERSION_RECORD",
                discovery_method="DEPS_DEV_PACKAGE_VERSION_QUERY",
                allowed_operations=["discovery", "corroboration"],
                authority_class="DISCOVERY_OR_CORROBORATION",
                confidence="MEDIUM" if deps_fetch["ok"] and not deps_fetch["redirect_chain"] else "NEEDS_REVIEW" if deps_fetch["redirect_chain"] else "LOW",
                purpose=f"deps.dev corroboration record for {name}:{version}",
                status="RETRIEVED" if deps_fetch["ok"] else "FETCH_FAILED",
                retrieved_at=utc_now(),
                http_status=deps_fetch["status"],
                final_url=deps_fetch["final_url"],
                redirect_chain=deps_fetch["redirect_chain"],
                content_hash=deps_hash,
                artifact_path=deps_artifact_rel,
                error=deps_fetch["error"],
            )
        )
        result["retrieved"]["deps_dev"] = {
            "source_id": deps_src_id,
            "url": deps_url,
            "status": "RETRIEVED" if deps_fetch["ok"] else "FETCH_FAILED",
            "http_status": deps_fetch["status"],
            "content_hash": deps_hash,
            "artifact_path": deps_artifact_rel,
            "error": deps_fetch["error"],
            "authority_note": "discovery/corroboration only; not used as final artifact authority",
        }

        if artifact_bytes is not None:
            result["artifact_reachable"] = True
        if checksum_text:
            result["checksum_reachable"] = True
        if artifact_bytes is not None and checksum_text:
            expected = checksum_text.split()[0].strip()
            actual = sha1_bytes(artifact_bytes)
            result["artifact_sha1_matches_sidecar"] = actual.lower() == expected.lower()
            result["artifact_sha1_actual"] = actual
            result["artifact_sha1_expected"] = expected

        result["would_resolve_missing_evidence"] = bool(
            result["artifact_reachable"]
            and result["checksum_reachable"]
            and result["artifact_sha1_matches_sidecar"] is True
        )
        reachability.append(result)
        identities.append(identity)

    graph = {
        "schema": SCHEMA_GRAPH,
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "policy": {
            "general_search_used": False,
            "llm_invented_domains_used": False,
            "native_maven_registry_root": MAVEN_NATIVE_ROOT,
            "native_maven_registry_root_policy": "Allowed as PURL/dependency-coordinate-derived native registry authority for metadata, POM, artifact, and checksum operations only.",
            "deps_dev_policy": "Discovery/corroboration only; links are candidates and are not promoted by this replay.",
        },
        "inputs": {
            "seed_manifest": str(seed_dir / "manifest.json"),
            "baseline_source_graph": str(baseline_graph_path),
            "baseline_missing_evidence": str(missing_path),
            "baseline_production_validation": str(validation_path),
            "design_review": str(design_review_path),
        },
        "sources": replay_sources,
    }

    ids = {src["source_id"] for src in replay_sources}
    missing_parents = [
        src["source_id"]
        for src in replay_sources
        if src.get("parent_source_id") and src["parent_source_id"] not in ids
    ]
    unparented = [
        src["source_id"]
        for src in replay_sources
        if not src.get("parent_source_id") and not src.get("parent_evidence")
    ]
    hash_mismatches = []
    for entry in retrieved_manifest:
        data = (out_dir / entry["path"]).read_bytes()
        actual = sha256_bytes(data)
        if actual != entry["sha256"]:
            hash_mismatches.append(
                {"source_id": entry["source_id"], "expected": entry["sha256"], "actual": actual}
            )

    validation = {
        "schema": SCHEMA_VALIDATION,
        "run_id": RUN_ID,
        "validated_at": utc_now(),
        "source_count": len(replay_sources),
        "retrieved_count": sum(1 for src in replay_sources if src["status"] == "RETRIEVED"),
        "fetch_failed_count": sum(1 for src in replay_sources if src["status"] == "FETCH_FAILED"),
        "derived_root_count": sum(1 for src in replay_sources if src["status"] == "DERIVED_ROOT"),
        "missing_parents": missing_parents,
        "unparented_sources": unparented,
        "content_hash_mismatches": hash_mismatches,
        "valid": not missing_parents and not unparented and not hash_mismatches,
    }

    comparison = {
        "schema": SCHEMA_COMPARISON,
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "baseline": {
            "source_count": len(baseline_graph["sources"]),
            "retrieved_count": 97,
            "fetch_failed_count": 34,
            "validator_ready_actions": 5,
            "abstained_actions": 3,
            "abstained_action_ids": ["patch-004", "patch-007", "patch-008"],
        },
        "replay": {
            "source_count": len(replay_sources),
            "retrieved_count": validation["retrieved_count"],
            "fetch_failed_count": validation["fetch_failed_count"],
            "dependencies_reached": [
                item["coordinate"]
                for item in reachability
                if item["would_resolve_missing_evidence"]
            ],
            "dependencies_unreached": [
                item["coordinate"]
                for item in reachability
                if not item["would_resolve_missing_evidence"]
            ],
            "resolved_missing_evidence_count": sum(
                1 for item in reachability if item["would_resolve_missing_evidence"]
            ),
        },
        "interpretation": "Replay reachability only. This does not mutate the UZBL5 proposal and does not establish validator-ready remediation commands.",
    }

    retrieved_manifest_doc = {
        "schema": "kalama.task-7.5.6a-retrieved-source-manifest/v1",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "entries": retrieved_manifest,
    }

    write_json(out_dir / "upstream_identities.json", {"schema": SCHEMA_IDENTITIES, "run_id": RUN_ID, "created_at": utc_now(), "identities": identities})
    write_json(out_dir / "replay_source_graph.json", graph)
    write_json(out_dir / "replay_source_graph_validation.json", validation)
    write_json(out_dir / "replay_artifact_reachability.json", {"schema": SCHEMA_REACHABILITY, "run_id": RUN_ID, "created_at": utc_now(), "items": reachability})
    write_json(out_dir / "replay_missing_evidence_comparison.json", comparison)
    write_json(out_dir / "retrieved_sources_manifest.json", retrieved_manifest_doc)

    graph_hash = sha256_bytes((out_dir / "replay_source_graph.json").read_bytes())
    manifest_hash = sha256_bytes((out_dir / "retrieved_sources_manifest.json").read_bytes())
    (out_dir / "replay_source_graph.sha256").write_text(f"{graph_hash}  replay_source_graph.json\n", encoding="utf-8")
    (out_dir / "retrieved_sources_manifest.sha256").write_text(f"{manifest_hash}  retrieved_sources_manifest.json\n", encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "dependencies": len(reachability),
        "dependencies_reached": comparison["replay"]["dependencies_reached"],
        "graph_valid": validation["valid"],
        "out_dir": str(out_dir),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
