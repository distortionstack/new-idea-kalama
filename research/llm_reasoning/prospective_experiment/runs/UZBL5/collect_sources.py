from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


RUN_ROOT = Path(__file__).resolve().parent
OUT = RUN_ROOT / "source_discovery"
RETRIEVED = OUT / "retrieved_sources"
USER_AGENT = "Kalama-Task-7.5.5-evidence-anchored/1.0"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


roots = [
    {
        "source_id": "ROOT-S2-045",
        "url": None,
        "parent_source_id": None,
        "root_seed_reference": "frozen_evidence/TRIVY_BEFORE__scan_2026-09-16_UZBL5.json :: CVE-2017-5638 References[] = https://cwiki.apache.org/confluence/display/WW/S2-045",
        "discovery_method": "PATCH_REASONING_SEED_FIELD",
        "retrieved_at": None,
        "content_hash": None,
        "authority_class": "SCANNER_EVIDENCE",
        "purpose": "Source-graph root for CVE-2017-5638",
        "status": "SEED_ROOT",
    },
    {
        "source_id": "ROOT-S2-052",
        "url": None,
        "parent_source_id": None,
        "root_seed_reference": "frozen_evidence/TRIVY_BEFORE__scan_2026-09-16_UZBL5.json :: CVE-2017-9805 References[] = https://cwiki.apache.org/confluence/display/WW/S2-052",
        "discovery_method": "PATCH_REASONING_SEED_FIELD",
        "retrieved_at": None,
        "content_hash": None,
        "authority_class": "SCANNER_EVIDENCE",
        "purpose": "Source-graph root for CVE-2017-9805",
        "status": "SEED_ROOT",
    },
    {
        "source_id": "ROOT-STRUTS-GIT",
        "url": None,
        "parent_source_id": None,
        "root_seed_reference": "frozen_evidence/TRIVY_BEFORE__scan_2026-09-16_UZBL5.json :: References[] = https://github.com/apache/struts",
        "discovery_method": "PATCH_REASONING_SEED_FIELD",
        "retrieved_at": None,
        "content_hash": None,
        "authority_class": "SCANNER_EVIDENCE",
        "purpose": "Source-graph root for upstream source repository",
        "status": "SEED_ROOT",
    },
    {
        "source_id": "ROOT-TOMCAT-ARCHIVE",
        "url": None,
        "parent_source_id": None,
        "root_seed_reference": "runtime_evidence/docker_image_inspect.json :: Config.Env[TOMCAT_TGZ_FALLBACK_URL]",
        "discovery_method": "PATCH_REASONING_SEED_FIELD",
        "retrieved_at": None,
        "content_hash": None,
        "authority_class": "RUNTIME_EVIDENCE",
        "purpose": "Source-graph root for exact Tomcat runtime distribution",
        "status": "SEED_ROOT",
    },
]


specs = [
    ("S001", "https://cwiki.apache.org/confluence/display/WW/S2-045", "ROOT-S2-045", "SCANNER_REFERENCE", "UPSTREAM_VENDOR", "CVE-2017-5638 affected and fixed versions"),
    ("S002", "https://cwiki.apache.org/confluence/display/WW/S2-052", "ROOT-S2-052", "SCANNER_REFERENCE", "UPSTREAM_VENDOR", "CVE-2017-9805 affected and fixed versions and compatibility warning"),
    ("S003", "https://github.com/apache/struts", "ROOT-STRUTS-GIT", "SCANNER_REFERENCE", "CODE_REPOSITORY", "Upstream repository root"),
    ("S004", "https://cwiki.apache.org/confluence/spaces/WW/pages/68717261/Version%2BNotes%2B2.3.32", "S001", "PAGE_LINK", "PROJECT_DOCUMENTATION", "Struts 2.3.32 release metadata and Maven repository root"),
    ("S005", "https://cwiki.apache.org/confluence/spaces/WW/pages/68717259/Version%2BNotes%2B2.5.10.1", "S001", "PAGE_LINK", "PROJECT_DOCUMENTATION", "Struts 2.5.10.1 release metadata and Maven repository root"),
    ("S006", "https://cwiki.apache.org/confluence/spaces/WW/pages/73636531/Version%2BNotes%2B2.3.34", "S002", "PAGE_LINK", "PROJECT_DOCUMENTATION", "Struts 2.3.34 release metadata and Maven repository root"),
    ("S007", "https://cwiki.apache.org/confluence/spaces/WW/pages/73634549/Version%2BNotes%2B2.5.13", "S002", "PAGE_LINK", "PROJECT_DOCUMENTATION", "Struts 2.5.13 release metadata and Maven repository root"),
    ("S008", "https://github.com/apache/struts/tags", "S003", "PAGE_LINK", "CODE_REPOSITORY", "Tag naming and upstream releases"),
    ("S009", "https://github.com/apache/struts/tree/STRUTS_2_3_32", "S008", "DETERMINISTIC_NAVIGATION", "CODE_REPOSITORY", "Upstream 2.3.32 tag"),
    ("S010", "https://github.com/apache/struts/tree/STRUTS_2_3_34", "S008", "DETERMINISTIC_NAVIGATION", "CODE_REPOSITORY", "Upstream 2.3.34 tag"),
    ("S011", "https://github.com/apache/struts/tree/STRUTS_2_5_10_1", "S008", "DETERMINISTIC_NAVIGATION", "CODE_REPOSITORY", "Upstream 2.5.10.1 tag"),
    ("S012", "https://github.com/apache/struts/tree/STRUTS_2_5_13", "S008", "DETERMINISTIC_NAVIGATION", "CODE_REPOSITORY", "Upstream 2.5.13 tag"),
    ("S013", "https://repository.apache.org/content/groups/staging/", "S004", "PAGE_LINK", "PACKAGE_REPOSITORY", "Maven repository URL printed in upstream release notes"),
    ("S014", "https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.20/bin/apache-tomcat-8.5.20.tar.gz", "ROOT-TOMCAT-ARCHIVE", "RUNTIME_REFERENCE", "RUNTIME_VENDOR_DOCUMENTATION", "Exact runtime distribution and embedded deployment documentation"),
]


def maven_url(group: str, artifact: str, version: str, ext: str) -> str:
    return "https://repository.apache.org/content/groups/staging/{}/{}/{}/{}-{}.{}".format(
        group.replace(".", "/"), artifact, version, artifact, version, ext
    )


artifact_specs: list[tuple[str, str, str, str, str, str]] = []


def add_maven(source_id: str, group: str, artifact: str, version: str, ext: str, purpose: str) -> None:
    artifact_specs.append(
        (source_id, maven_url(group, artifact, version, ext), "S013", "DETERMINISTIC_MAVEN_PATH", "PACKAGE_REPOSITORY", purpose)
    )


# Direct components, parent metadata, and the Struts module sets observed in the
# affected deployments. Coordinates and versions come from S004-S007 and the
# corresponding POM dependencyManagement records, not from an open-web search.
sid = 100
for version in ("2.3.32", "2.3.34", "2.5.10.1"):
    for artifact in ("struts2-parent", "struts2-core"):
        add_maven(f"S{sid}", "org.apache.struts", artifact, version, "pom", f"POM for {artifact}:{version}")
        sid += 1
    add_maven(f"S{sid}", "org.apache.struts", "struts2-core", version, "jar", f"Direct component JAR struts2-core:{version}")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts", "struts2-core", version, "jar.sha1", f"Repository checksum for struts2-core:{version}")
    sid += 1

for version in ("2.3.32", "2.3.34"):
    add_maven(f"S{sid}", "org.apache.struts.xwork", "xwork-core", version, "pom", f"POM for xwork-core:{version}")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts.xwork", "xwork-core", version, "jar", f"Related module JAR xwork-core:{version}")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts.xwork", "xwork-core", version, "jar.sha1", f"Repository checksum for xwork-core:{version}")
    sid += 1

for artifact in (
    "struts2-config-browser-plugin",
    "struts2-convention-plugin",
    "struts2-dojo-plugin",
    "struts2-dwr-plugin",
    "struts2-jsf-plugin",
    "struts2-json-plugin",
    "struts2-sitemesh-plugin",
    "struts2-spring-plugin",
    "struts2-struts1-plugin",
    "struts2-tiles-plugin",
):
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.32", "pom", f"POM for observed related module {artifact}:2.3.32")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.32", "jar", f"Observed related module JAR {artifact}:2.3.32")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.32", "jar.sha1", f"Repository checksum for {artifact}:2.3.32")
    sid += 1

for artifact in ("struts2-config-browser-plugin", "struts2-convention-plugin", "struts2-rest-plugin"):
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.34", "pom", f"POM for observed related module {artifact}:2.3.34")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.34", "jar", f"Observed related module JAR {artifact}:2.3.34")
    sid += 1
    add_maven(f"S{sid}", "org.apache.struts", artifact, "2.3.34", "jar.sha1", f"Repository checksum for {artifact}:2.3.34")
    sid += 1

specs.extend(artifact_specs)


def suffix_for(url: str) -> str:
    name = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if not name:
        return ".html"
    if name.endswith(".jar.sha1"):
        return ".jar.sha1"
    for suffix in (".tar.gz", ".sha1", ".pom", ".jar", ".xml", ".html"):
        if name.endswith(suffix):
            return suffix
    return ".html"


def fetch(source_id: str, url: str) -> tuple[bytes, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as response:
        data = response.read()
        meta = {
            "http_status": response.status,
            "final_url": response.geturl(),
            "content_type": response.headers.get("Content-Type"),
            "size_bytes": len(data),
        }
    path = RETRIEVED / f"{source_id}{suffix_for(url)}"
    path.write_bytes(data)
    meta["artifact_path"] = str(path.relative_to(RUN_ROOT)).replace("\\", "/")
    return data, meta


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    RETRIEVED.mkdir(parents=True, exist_ok=True)
    records = list(roots)
    payloads: dict[str, bytes] = {}
    for source_id, url, parent, method, authority, purpose in specs:
        record = {
            "source_id": source_id,
            "url": url,
            "parent_source_id": parent,
            "root_seed_reference": next(
                r["root_seed_reference"]
                for r in roots
                if r["source_id"]
                == ({"S001": "ROOT-S2-045", "S002": "ROOT-S2-052", "S003": "ROOT-STRUTS-GIT", "S014": "ROOT-TOMCAT-ARCHIVE"}.get(source_id)
                    or ("ROOT-S2-052" if parent in {"S002", "S006", "S007"} else "ROOT-S2-045"))
            ),
            "discovery_method": method,
            "retrieved_at": now(),
            "content_hash": None,
            "authority_class": authority,
            "purpose": purpose,
            "status": "FETCH_FAILED",
        }
        try:
            data, meta = fetch(source_id, url)
            payloads[source_id] = data
            record.update(meta)
            record["content_hash"] = f"sha256:{sha256(data)}"
            record["status"] = "RETRIEVED"
        except Exception as exc:  # record bounded retrieval failures as evidence
            record["error"] = f"{type(exc).__name__}: {exc}"
        records.append(record)

    tomcat = payloads.get("S014")
    if tomcat:
        with tarfile.open(fileobj=io.BytesIO(tomcat), mode="r:gz") as archive:
            wanted = {
                "apache-tomcat-8.5.20/webapps/docs/deployer-howto.html": ("S015", "Tomcat deployment behavior"),
                "apache-tomcat-8.5.20/webapps/docs/config/host.html": ("S016", "Tomcat Host autoDeploy and deployOnStartup semantics"),
                "apache-tomcat-8.5.20/webapps/docs/config/context.html": ("S017", "Tomcat Context deployment semantics"),
                "apache-tomcat-8.5.20/RUNNING.txt": ("S018", "Tomcat runtime operation documentation"),
            }
            for member_name, (source_id, purpose) in wanted.items():
                member = archive.getmember(member_name)
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                data = stream.read()
                suffix = ".html" if member_name.endswith(".html") else ".txt"
                path = RETRIEVED / f"{source_id}{suffix}"
                path.write_bytes(data)
                records.append(
                    {
                        "source_id": source_id,
                        "url": f"archive-member:{member_name}",
                        "parent_source_id": "S014",
                        "root_seed_reference": roots[3]["root_seed_reference"],
                        "discovery_method": "ARCHIVE_MEMBER",
                        "retrieved_at": now(),
                        "content_hash": f"sha256:{sha256(data)}",
                        "authority_class": "RUNTIME_VENDOR_DOCUMENTATION",
                        "purpose": purpose,
                        "status": "RETRIEVED",
                        "size_bytes": len(data),
                        "artifact_path": str(path.relative_to(RUN_ROOT)).replace("\\", "/"),
                    }
                )

    graph = {
        "schema": "kalama.task-7.5.5-source-graph/v1",
        "run_id": "UZBL5",
        "created_at": now(),
        "policy": {
            "general_search_used": False,
            "source_discovery": "PATCH_REASONING_SEED roots, explicit page links, archive members, and deterministic paths within authorized sources",
            "unanchored_sources_used": False,
        },
        "sources": records,
    }
    graph_bytes = (json.dumps(graph, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "source_graph.json").write_bytes(graph_bytes)
    manifest = {
        "schema": "kalama.task-7.5.5-retrieved-source-manifest/v1",
        "run_id": "UZBL5",
        "created_at": now(),
        "source_graph_sha256": sha256(graph_bytes),
        "entries": [
            {
                "source_id": r["source_id"],
                "path": r.get("artifact_path"),
                "sha256": (r.get("content_hash") or "").removeprefix("sha256:") or None,
                "size_bytes": r.get("size_bytes"),
            }
            for r in records
            if r.get("artifact_path")
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (OUT / "retrieved_sources_manifest.json").write_bytes(manifest_bytes)
    (OUT / "retrieved_sources_manifest.sha256").write_text(sha256(manifest_bytes) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
