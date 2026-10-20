from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


RUN_ROOT = Path(__file__).resolve().parent
DISCOVERY = RUN_ROOT / "source_discovery"
RETRIEVED = DISCOVERY / "retrieved_sources"
GRAPH_PATH = DISCOVERY / "source_graph.json"
MANIFEST_PATH = DISCOVERY / "retrieved_sources_manifest.json"
USER_AGENT = "Kalama-Task-7.5.5-evidence-anchored/1.0"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    by_id = {entry["source_id"]: entry for entry in graph["sources"]}
    next_id = max(int(key[1:]) for key in by_id if key.startswith("S") and key[1:].isdigit()) + 1

    # These two URLs were exact scanner References[] roots and were opened in
    # the bounded browsing phase before the canonical cwiki pages were used.
    for url, parent, purpose in (
        ("https://struts.apache.org/docs/s2-045.html", "ROOT-S2-045", "Scanner-root alias/redirect for S2-045"),
        ("https://struts.apache.org/docs/s2-052.html", "ROOT-S2-052", "Scanner-root alias/redirect for S2-052"),
    ):
        if any(entry.get("url") == url for entry in graph["sources"]):
            continue
        source_id = f"S{next_id}"
        next_id += 1
        record = {
            "source_id": source_id,
            "url": url,
            "parent_source_id": parent,
            "root_seed_reference": by_id[parent]["root_seed_reference"],
            "discovery_method": "SCANNER_REFERENCE",
            "retrieved_at": now(),
            "content_hash": None,
            "authority_class": "UPSTREAM_VENDOR",
            "purpose": purpose,
            "status": "FETCH_FAILED",
        }
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
                record.update(
                    http_status=response.status,
                    final_url=response.geturl(),
                    content_type=response.headers.get("Content-Type"),
                    size_bytes=len(data),
                )
            path = RETRIEVED / f"{source_id}.html"
            path.write_bytes(data)
            record["artifact_path"] = str(path.relative_to(RUN_ROOT)).replace("\\", "/")
            record["content_hash"] = f"sha256:{sha256(data)}"
            record["status"] = "RETRIEVED"
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        graph["sources"].append(record)
        by_id[source_id] = record

    # Record browser attempts that were not used for any factual premise.
    attempted = [
        {
            "url": "https://central.sonatype.com/artifact/org.apache.struts/struts2-core/2.3.34",
            "parent_source_id": None,
            "discovery_method": "UNANCHORED_SOURCE",
            "authority_class": "PACKAGE_REPOSITORY",
            "purpose": "Browser attempt; rejected because no valid provenance hop to this domain was established",
            "status": "UNANCHORED_SOURCE_REJECTED",
            "reason": "Not used in remediation reasoning or artifact selection",
        },
        {
            "url": "https://camo.githubusercontent.com/a5b90a658b8fc02e5436575d00008d54b510878327e40744e51827c6c617b88d/68747470733a2f2f6d6176656e2d6261646765732e6865726f6b756170702e636f6d2f6d6176656e2d63656e7472616c2f6f72672e6170616368652e7374727574732f737472757473322d636f72652f62616467652e737667",
            "parent_source_id": "S011",
            "discovery_method": "PAGE_LINK",
            "authority_class": "THIRD_PARTY",
            "purpose": "Maven badge image fetch attempt; cache miss and irrelevant to patch facts",
            "status": "FETCH_FAILED_NOT_USED",
            "reason": "No document bytes were returned; not used",
        },
    ]
    for item in attempted:
        if any(entry.get("url") == item["url"] for entry in graph["sources"]):
            continue
        source_id = f"S{next_id}"
        next_id += 1
        parent = item["parent_source_id"]
        graph["sources"].append(
            {
                "source_id": source_id,
                "url": item["url"],
                "parent_source_id": parent,
                "root_seed_reference": by_id[parent]["root_seed_reference"] if parent else None,
                "discovery_method": item["discovery_method"],
                "retrieved_at": None,
                "content_hash": None,
                "authority_class": item["authority_class"],
                "purpose": item["purpose"],
                "status": item["status"],
                "reason": item["reason"],
            }
        )

    by_id = {entry["source_id"]: entry for entry in graph["sources"]}

    def root_reference(source_id: str, seen: set[str] | None = None) -> str | None:
        seen = set() if seen is None else seen
        if source_id in seen:
            raise ValueError(f"source graph cycle at {source_id}")
        seen.add(source_id)
        entry = by_id[source_id]
        parent = entry.get("parent_source_id")
        if parent is None:
            return entry.get("root_seed_reference")
        if parent not in by_id:
            raise ValueError(f"missing parent {parent} for {source_id}")
        return root_reference(parent, seen)

    hash_mismatches = []
    missing_parents = []
    for entry in graph["sources"]:
        parent = entry.get("parent_source_id")
        if parent and parent not in by_id:
            missing_parents.append({"source_id": entry["source_id"], "parent": parent})
            continue
        if entry["status"] not in {"UNANCHORED_SOURCE_REJECTED"}:
            entry["root_seed_reference"] = root_reference(entry["source_id"])
        artifact_path = entry.get("artifact_path")
        if artifact_path:
            path = RUN_ROOT / artifact_path
            observed = sha256(path.read_bytes())
            expected = (entry.get("content_hash") or "").removeprefix("sha256:")
            if observed != expected:
                hash_mismatches.append(
                    {"source_id": entry["source_id"], "expected": expected, "observed": observed}
                )

    graph["updated_at"] = now()
    graph["policy"]["unanchored_sources_used"] = False
    graph["policy"]["unanchored_source_attempts"] = 1
    graph_bytes = (json.dumps(graph, indent=2, sort_keys=True) + "\n").encode()
    GRAPH_PATH.write_bytes(graph_bytes)

    manifest = {
        "schema": "kalama.task-7.5.5-retrieved-source-manifest/v1",
        "run_id": "UZBL5",
        "created_at": now(),
        "source_graph_sha256": sha256(graph_bytes),
        "entries": [
            {
                "source_id": entry["source_id"],
                "path": entry["artifact_path"],
                "sha256": entry["content_hash"].removeprefix("sha256:"),
                "size_bytes": entry.get("size_bytes"),
            }
            for entry in graph["sources"]
            if entry.get("artifact_path")
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    MANIFEST_PATH.write_bytes(manifest_bytes)
    (DISCOVERY / "retrieved_sources_manifest.sha256").write_text(sha256(manifest_bytes) + "\n", encoding="ascii")

    validation = {
        "schema": "kalama.task-7.5.5-source-graph-validation/v1",
        "run_id": "UZBL5",
        "validated_at": now(),
        "source_count": len(graph["sources"]),
        "retrieved_count": sum(entry["status"] == "RETRIEVED" for entry in graph["sources"]),
        "fetch_failed_count": sum(entry["status"].startswith("FETCH_FAILED") for entry in graph["sources"]),
        "unanchored_rejected_count": sum(entry["status"] == "UNANCHORED_SOURCE_REJECTED" for entry in graph["sources"]),
        "missing_parents": missing_parents,
        "content_hash_mismatches": hash_mismatches,
        "valid": not missing_parents and not hash_mismatches,
    }
    validation_bytes = (json.dumps(validation, indent=2, sort_keys=True) + "\n").encode()
    (DISCOVERY / "source_graph_validation.json").write_bytes(validation_bytes)


if __name__ == "__main__":
    main()
