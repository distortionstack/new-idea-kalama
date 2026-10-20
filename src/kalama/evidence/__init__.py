"""Provider-neutral, immutable evidence contracts.

This package is deliberately not connected to resolution or remediation yet.
It establishes the candidate-bound data and cache primitives future adapters use.
"""

from .cache import EvidenceCache, EvidenceCacheRecord
from .models import (
    CandidateContext, EvidenceItem, EvidencePack, EvidencePurpose,
    EvidenceResult, EvidenceResultState, FieldRequest, SourceKind,
)
from .policy import EvidenceSourceConfig, SourcePolicy
from .collector import Collection, EvidenceCollector
from .sources import (CISAKEVEvidenceSource, KnowledgeEvidenceSource, MSFMetadataEvidenceSource,
                      MSFReferenceEvidenceSource, RuntimeEvidenceSource)
from .external import (BoundedHTTP, ExternalPolicy, HTTPResponse, MSFModuleDocumentationSource,
                       NVDEvidenceSource, VendorEvidenceSource)

__all__ = [
    "CandidateContext", "EvidenceCache", "EvidenceCacheRecord", "EvidenceItem",
    "EvidencePack", "EvidencePurpose", "EvidenceResult", "EvidenceResultState",
    "EvidenceSourceConfig", "FieldRequest", "SourceKind", "SourcePolicy",
    "Collection", "EvidenceCollector", "CISAKEVEvidenceSource", "KnowledgeEvidenceSource",
    "MSFMetadataEvidenceSource", "MSFReferenceEvidenceSource", "RuntimeEvidenceSource",
    "BoundedHTTP", "ExternalPolicy", "HTTPResponse", "MSFModuleDocumentationSource",
    "NVDEvidenceSource", "VendorEvidenceSource",
]
