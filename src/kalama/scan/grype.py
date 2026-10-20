"""Conservative Grype JSON parser.

Grype has changed envelope fields across releases, so only documented match
fields are accepted and malformed values fail closed rather than fabricated.
"""
from __future__ import annotations
from typing import Any, Mapping
from .models import NormalizedFinding, ScannerResult

def parse_grype_report(value: Mapping[str, Any], *, artifact_path: str | None = None,
                       artifact_sha256: str | None = None) -> ScannerResult:
    if not isinstance(value, Mapping) or not isinstance(value.get("matches"), list):
        return ScannerResult("grype", "UNSUPPORTED_SCHEMA", error="Grype report has no matches array")
    descriptor = value.get("descriptor") if isinstance(value.get("descriptor"), Mapping) else {}
    version = descriptor.get("version") if isinstance(descriptor.get("version"), str) else None
    findings = []
    for index, match in enumerate(value["matches"]):
        if not isinstance(match, Mapping):
            return ScannerResult("grype", "INVALID_JSON", error=f"match {index} is not an object")
        vuln = match.get("vulnerability") if isinstance(match.get("vulnerability"), Mapping) else {}
        artifact = match.get("artifact") if isinstance(match.get("artifact"), Mapping) else {}
        cve = vuln.get("id")
        name = artifact.get("name")
        if not isinstance(cve, str) or not cve or not isinstance(name, str) or not name:
            return ScannerResult("grype", "INVALID_JSON", error=f"match {index} lacks vulnerability/package identity")
        purl = artifact.get("purl") if isinstance(artifact.get("purl"), str) else None
        fix = vuln.get("fix") if isinstance(vuln.get("fix"), Mapping) else {}
        versions = fix.get("versions") if isinstance(fix.get("versions"), list) else []
        findings.append(NormalizedFinding(cve, purl or name, name, purl,
            artifact.get("type") if isinstance(artifact.get("type"), str) else None,
            artifact.get("version") if isinstance(artifact.get("version"), str) else None,
            tuple(sorted(str(x) for x in versions if isinstance(x, str))), "grype", version,
            {"artifact_path": artifact_path, "artifact_sha256": artifact_sha256, "match_index": index}))
    return ScannerResult("grype", "SUCCEEDED", tuple(findings), version, artifact_path, artifact_sha256)
