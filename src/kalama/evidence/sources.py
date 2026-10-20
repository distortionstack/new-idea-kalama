"""Read-only adapters for facts Kalama already produced; no transport lives here."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from ..knowledge import retrieve_compatible
from .models import (EvidenceItem, EvidencePurpose, EvidenceResult, EvidenceResultState,
                     FieldRequest, SourceKind)


class EvidenceSource(Protocol):
    kind: SourceKind
    def collect(self, request: FieldRequest) -> EvidenceResult: ...


def _wanted(request: FieldRequest, values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: values[key] for key in request.unresolved_fields if key in values}


@dataclass(frozen=True)
class RuntimeEvidenceSource:
    """Adapts persisted scanner occurrences and target facts; it never rescans."""
    occurrences: Sequence[Mapping[str, Any]]
    target_facts: Mapping[str, Any]
    artifact_ref: str | None = None
    kind: SourceKind = SourceKind.RUNTIME

    def collect(self, request: FieldRequest) -> EvidenceResult:
        matches = [x for x in self.occurrences if str(x.get("canonical_cve_id") or x.get("cve_id") or "").upper() == request.context.vulnerability_id
                   and str(x.get("package_purl") or x.get("package_name") or "") == request.context.component
                   and (not request.context.installed_versions or str(x.get("installed_version") or "") in request.context.installed_versions)]
        if not matches: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        ports = {key: self.target_facts.get(key) for key in ("exposed_ports", "listening_ports", "reachable_ports", "published_ports") if key in self.target_facts}
        values = {"runtime_identity": {key: self.target_facts.get(key) for key in ("requested_image_reference", "container_id", "ip_address", "network")},
                  "ports": ports, "rport": self.target_facts.get("target_port"),
                  "fixed_version": sorted({v for x in matches for v in (x.get("fixed_versions") or ()) if isinstance(v, str)}),
                  "scanner_occurrences": [{key: x.get(key) for key in ("canonical_cve_id", "package_name", "package_purl", "result_type", "installed_version", "fixed_versions")} for x in matches]}
        facts = _wanted(request, values)
        if not facts: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, "kalama-runtime", "runtime:observed", facts, provenance_ref=self.artifact_ref),))


@dataclass(frozen=True)
class KnowledgeEvidenceSource:
    store: Any
    kind: SourceKind = SourceKind.KNOWLEDGE

    def collect(self, request: FieldRequest) -> EvidenceResult:
        kinds = ("attack_config",) if request.purpose == EvidencePurpose.EXPLOIT_CONFIGURATION else (("remediation",) if request.purpose == EvidencePurpose.REMEDIATION else ())
        context = {"package_purl": request.context.component, "package_name": request.context.component,
                   "ecosystem": request.context.ecosystem,
                   "installed_version": request.context.installed_versions[0] if len(request.context.installed_versions) == 1 else None,
                   "image_family": request.context.image_identity}
        items = []
        for record_kind in kinds:
            for record in retrieve_compatible(self.store, cve_id=request.context.vulnerability_id,
                                               component=request.context.component, kind=record_kind, context=context):
                for field, value in _wanted(request, record.fields).items():
                    items.append(EvidenceItem(request.context, self.kind, "kalama-validated-knowledge",
                        f"knowledge:{record.record_id}", {field: value, "trust": record.trust.value,
                        "origin_run_id": record.run_id, "record_context": dict(record.context),
                        "validation_evidence": dict(record.evidence)}, provenance_ref=f"knowledge.record.{record.record_id}"))
        return EvidenceResult(EvidenceResultState.AVAILABLE if items else EvidenceResultState.NOT_APPLICABLE, self.kind, tuple(items))


@dataclass(frozen=True)
class MSFMetadataEvidenceSource:
    """Adapts a previously resolved ModuleCandidate mapping; never invokes MSF."""
    candidates: Mapping[str, Any]
    provenance_ref: str | None = None
    kind: SourceKind = SourceKind.MSF_METADATA

    def collect(self, request: FieldRequest) -> EvidenceResult:
        candidate = self.candidates.get(request.context.vulnerability_id)
        if candidate is None: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        values = {"module": candidate.module_path, "target": [x.to_dict() for x in candidate.target_details],
                  "module_options": [x.to_dict() for x in candidate.options],
                  "payload": [x.to_dict() for x in candidate.payloads],
                  "payload_options": [], "targeturi": next((x.default for x in candidate.options if x.name.upper() == "TARGETURI"), None),
                  "check_supported": candidate.check_supported, "rank": candidate.rank,
                  "default_target": candidate.default_target_index}
        facts = _wanted(request, values)
        if not facts: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, "metasploit", f"msf-module:{candidate.module_path}", facts, provenance_ref=self.provenance_ref),))


@dataclass(frozen=True)
class MSFReferenceEvidenceSource:
    candidates: Mapping[str, Any]
    provenance_ref: str | None = None
    kind: SourceKind = SourceKind.MSF_REFERENCE
    def collect(self, request: FieldRequest) -> EvidenceResult:
        candidate = self.candidates.get(request.context.vulnerability_id)
        if candidate is None or not candidate.references: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, "metasploit-reference", f"msf-module:{candidate.module_path}", {"references": list(candidate.references)}, provenance_ref=self.provenance_ref),))


@dataclass(frozen=True)
class CISAKEVEvidenceSource:
    catalog: Mapping[str, Any] | None
    provenance_ref: str | None = None
    kind: SourceKind = SourceKind.CISA_KEV
    def collect(self, request: FieldRequest) -> EvidenceResult:
        if request.purpose != EvidencePurpose.EXPLOITATION_STATUS and "known_exploited" not in request.unresolved_fields:
            return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        if self.catalog is None: return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind)
        ids = set(self.catalog.get("cve_ids") or ())
        facts = {"known_exploited": request.context.vulnerability_id in ids,
                 "catalog_version": self.catalog.get("catalog_version"), "date_released": self.catalog.get("date_released"),
                 "retrieved_at": self.catalog.get("retrieved_at"), "sha256": self.catalog.get("sha256"),
                 "etag": self.catalog.get("etag"), "last_modified": self.catalog.get("last_modified")}
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, "CISA", "cisa-kev-catalog", facts, snapshot_sha256=self.catalog.get("sha256"), provenance_ref=self.provenance_ref),))
