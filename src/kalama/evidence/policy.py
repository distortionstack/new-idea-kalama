"""Explicit field/purpose source precedence; deliberately no numeric trust score."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import EvidencePurpose, FieldRequest, SourceKind


@dataclass(frozen=True)
class EvidenceSourceConfig:
    runtime: bool = True
    knowledge: bool = True
    msf_metadata: bool = True
    msf_module_doc: bool = True
    msf_reference: bool = True
    vendor_upstream: bool = False
    nvd: bool = False
    cisa_kev: bool = True
    web_search: bool = False

    def enabled(self) -> frozenset[SourceKind]:
        values = {SourceKind.RUNTIME: self.runtime, SourceKind.KNOWLEDGE: self.knowledge,
                  SourceKind.MSF_METADATA: self.msf_metadata,
                  SourceKind.MSF_MODULE_DOC: self.msf_module_doc,
                  SourceKind.MSF_REFERENCE: self.msf_reference,
                  SourceKind.VENDOR_UPSTREAM: self.vendor_upstream,
                  SourceKind.NVD: self.nvd, SourceKind.CISA_KEV: self.cisa_kev}
        return frozenset(kind for kind, enabled in values.items() if enabled)


class SourcePolicy:
    """Returns enabled, field-specific source order for a request."""
    _runtime_fields = frozenset({"rhosts", "rport", "ports", "target_identity",
                                 "image_identity", "container_identity"})
    _msf_fields = frozenset({"module", "target", "module_options", "payload",
                             "payload_options"})

    def __init__(self, config: EvidenceSourceConfig = EvidenceSourceConfig()):
        self.config = config

    def ordered_sources(self, request: FieldRequest, field: str) -> tuple[SourceKind, ...]:
        if field in self._runtime_fields:
            order = (SourceKind.RUNTIME,)
        elif field == "known_exploited":
            order = (SourceKind.CISA_KEV,)
        elif request.purpose == EvidencePurpose.EXPLOITATION_STATUS:
            order = (SourceKind.CISA_KEV,)
        elif field in self._msf_fields:
            order = (SourceKind.MSF_METADATA, SourceKind.MSF_MODULE_DOC,
                     SourceKind.MSF_REFERENCE, SourceKind.VENDOR_UPSTREAM)
        elif field == "targeturi":
            order = (SourceKind.KNOWLEDGE, SourceKind.MSF_METADATA,
                     SourceKind.MSF_MODULE_DOC, SourceKind.MSF_REFERENCE,
                     SourceKind.VENDOR_UPSTREAM)
        elif field == "fixed_version":
            order = (SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM, SourceKind.NVD)
        elif field == "patch_strategy":
            order = (SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM, SourceKind.RUNTIME)
        # Task 6 Patch LLM fields: field-specific authority, no trust scores.
        # NVD/Vendor stay disabled by default via EvidenceSourceConfig.
        elif field == "fix_type":
            order = (SourceKind.RUNTIME, SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM)
        elif field == "target_version":
            order = (SourceKind.KNOWLEDGE, SourceKind.RUNTIME,
                      SourceKind.VENDOR_UPSTREAM, SourceKind.NVD)
        elif field in {"strategy", "artifact_source", "source_identifier"}:
            order = (SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM, SourceKind.RUNTIME)
        elif field == "build_system":
            order = (SourceKind.RUNTIME, SourceKind.KNOWLEDGE, SourceKind.VENDOR_UPSTREAM)
        elif field == "notes":
            order = (SourceKind.KNOWLEDGE, SourceKind.RUNTIME,
                      SourceKind.VENDOR_UPSTREAM, SourceKind.NVD)
        else:
            order = (SourceKind.KNOWLEDGE, SourceKind.RUNTIME, SourceKind.VENDOR_UPSTREAM,
                     SourceKind.NVD)
        enabled = self.config.enabled() & request.enabled_sources
        return tuple(source for source in order if source in enabled)

    def selections(self, request: FieldRequest) -> Mapping[str, tuple[SourceKind, ...]]:
        return {field: self.ordered_sources(request, field) for field in request.unresolved_fields}
