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
REPOSITORY = "https://repository.apache.org/content/groups/staging"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def artifact_url(group: str, artifact: str, version: str, filename: str) -> str:
    return f"{REPOSITORY}/{group.replace('.', '/')}/{artifact}/{version}/{filename}"


def triplet(group: str, artifact: str, version: str, parent: str, *, classifier: str | None = None):
    stem = f"{artifact}-{version}" + (f"-{classifier}" if classifier else "")
    return [
        (artifact_url(group, artifact, version, f"{artifact}-{version}.pom"), parent, f"Dependency POM {group}:{artifact}:{version}"),
        (artifact_url(group, artifact, version, f"{stem}.jar"), parent, f"Dependency JAR {group}:{artifact}:{version}" + (f":{classifier}" if classifier else "")),
        (artifact_url(group, artifact, version, f"{stem}.jar.sha1"), parent, f"Repository SHA-1 for {group}:{artifact}:{version}" + (f":{classifier}" if classifier else "")),
    ]


items: list[tuple[str, str, str]] = []

# Parent POMs explicitly named by the already-retrieved plugin POMs.
for version, parent in (("2.3.32", "S118"), ("2.3.34", "S148")):
    url = artifact_url("org.apache.struts", "struts2-plugins", version, f"struts2-plugins-{version}.pom")
    items.append((url, parent, f"Plugin parent POM org.apache.struts:struts2-plugins:{version}"))

# Required non-test, non-optional dependencies extracted from S100/S101/S104/
# S105/S108/S109/S112/S115/S154 plus the matching related-module POMs.
coordinates = [
    ("org.freemarker", "freemarker", "2.3.22", "S100", None),
    ("ognl", "ognl", "3.0.19", "S100", None),
    ("ognl", "ognl", "3.0.21", "S104", None),
    ("commons-fileupload", "commons-fileupload", "1.3.2", "S100", None),
    ("commons-io", "commons-io", "2.2", "S100", None),
    ("org.apache.commons", "commons-lang3", "3.2", "S100", None),
    ("asm", "asm", "3.3", "S100", None),
    ("asm", "asm-commons", "3.3", "S100", None),
    ("org.freemarker", "freemarker", "2.3.23", "S108", None),
    ("ognl", "ognl", "3.1.12", "S108", None),
    ("commons-io", "commons-io", "2.4", "S108", None),
    ("org.apache.commons", "commons-lang3", "3.4", "S108", None),
    ("org.apache.logging.log4j", "log4j-api", "2.7", "S108", None),
    ("com.thoughtworks.xstream", "xstream", "1.4.10", "S104", None),
    ("net.sf.json-lib", "json-lib", "2.3", "S104", "jdk15"),
    ("org.codehaus.jackson", "jackson-core-asl", "1.9.2", "S154", None),
    ("org.codehaus.jackson", "jackson-mapper-asl", "1.9.2", "S154", None),
]
for group, artifact, version, parent, classifier in coordinates:
    items.extend(triplet(group, artifact, version, parent, classifier=classifier))


def suffix(url: str) -> str:
    name = url.rsplit("/", 1)[-1]
    for value in (".jar.sha1", ".pom", ".jar"):
        if name.endswith(value):
            return value
    return ".bin"


def main() -> None:
    graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    existing = {entry.get("url") for entry in graph["sources"]}
    root_map = {entry["source_id"]: entry["root_seed_reference"] for entry in graph["sources"]}
    parent_by_id = {entry["source_id"]: entry for entry in graph["sources"]}
    numeric = [int(entry["source_id"][1:]) for entry in graph["sources"] if entry["source_id"].startswith("S") and entry["source_id"][1:].isdigit()]
    next_id = max(max(numeric, default=199) + 1, 200)
    added = []
    for url, parent, purpose in items:
        if url in existing:
            continue
        source_id = f"S{next_id}"
        next_id += 1
        parent_entry = parent_by_id[parent]
        record = {
            "source_id": source_id,
            "url": url,
            "parent_source_id": parent,
            "root_seed_reference": parent_entry["root_seed_reference"],
            "discovery_method": "POM_COORDINATE_TO_AUTHORIZED_REPOSITORY",
            "retrieved_at": utc_now(),
            "content_hash": None,
            "authority_class": "PACKAGE_REPOSITORY",
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
            path = RETRIEVED / f"{source_id}{suffix(url)}"
            path.write_bytes(data)
            record["artifact_path"] = str(path.relative_to(RUN_ROOT)).replace("\\", "/")
            record["content_hash"] = f"sha256:{digest(data)}"
            record["status"] = "RETRIEVED"
        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        graph["sources"].append(record)
        parent_by_id[source_id] = record
        existing.add(url)
        added.append(record)

    graph["updated_at"] = utc_now()
    graph_bytes = (json.dumps(graph, indent=2, sort_keys=True) + "\n").encode()
    GRAPH_PATH.write_bytes(graph_bytes)

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["updated_at"] = utc_now()
    manifest["source_graph_sha256"] = digest(graph_bytes)
    for record in added:
        if record.get("artifact_path"):
            manifest["entries"].append(
                {
                    "source_id": record["source_id"],
                    "path": record["artifact_path"],
                    "sha256": record["content_hash"].removeprefix("sha256:"),
                    "size_bytes": record["size_bytes"],
                }
            )
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    MANIFEST_PATH.write_bytes(manifest_bytes)
    (DISCOVERY / "retrieved_sources_manifest.sha256").write_text(digest(manifest_bytes) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
