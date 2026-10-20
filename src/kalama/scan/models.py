from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class NormalizedFinding:
    vulnerability_id: str
    component: str
    package_name: str | None
    package_purl: str | None
    ecosystem: str | None
    installed_version: str | None
    fixed_versions: tuple[str, ...]
    scanner: str
    scanner_version: str | None
    raw_ref: Mapping[str, Any]
    @property
    def candidate_key(self):
        return (self.vulnerability_id.upper(), self.package_purl or self.component, self.ecosystem or "")
    def to_dict(self):
        return {"vulnerability_id": self.vulnerability_id, "component": self.component,
                "package_name": self.package_name, "package_purl": self.package_purl,
                "ecosystem": self.ecosystem, "installed_version": self.installed_version,
                "fixed_versions": list(self.fixed_versions), "scanner": self.scanner,
                "scanner_version": self.scanner_version, "raw_ref": dict(self.raw_ref),
                "candidate_key": list(self.candidate_key)}

@dataclass(frozen=True)
class ScannerResult:
    scanner: str
    status: str
    findings: tuple[NormalizedFinding, ...] = ()
    version: str | None = None
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    error: str | None = None
