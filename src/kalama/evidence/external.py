"""Bounded, policy-gated document evidence.  Transports are injected for testing."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress, json, re
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

from .cache import EvidenceCache, EvidenceCacheRecord
from .models import EvidenceItem, EvidenceResult, EvidenceResultState, FieldRequest, SourceKind, canonical_bytes

MAX_RAW_BYTES = 512 * 1024
MAX_NORMALIZED_BYTES = 4096
POLICY_VERSION = "external-evidence-v1"

@dataclass(frozen=True)
class HTTPResponse:
    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes

class ExternalPolicy:
    def __init__(self, approved_domains: Mapping[str, str] | None = None):
        self.approved_domains = dict(approved_domains or {"services.nvd.nist.gov": "NVD"})
    def authority(self, url: str) -> str | None:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname: return None
        host = parsed.hostname.casefold().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
            if address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified: return None
        except ValueError:
            if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"): return None
        return self.approved_domains.get(host)

def _now() -> str: return datetime.now(timezone.utc).isoformat()
def _text(data: bytes) -> tuple[str, bool]:
    text = data.decode("utf-8", "replace")
    text = re.sub(r"(?is)<(script|style|nav)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    encoded = text.encode("utf-8")
    return (encoded[:MAX_NORMALIZED_BYTES].decode("utf-8", "ignore"), len(encoded) > MAX_NORMALIZED_BYTES)

class BoundedHTTP:
    """GET-only redirect loop.  It has no cookies, credentials, or DNS override."""
    def __init__(self, transport: Callable[[str, Mapping[str, str], float], HTTPResponse], policy: ExternalPolicy, *, timeout: float = 10, max_redirects: int = 3):
        self.transport, self.policy, self.timeout, self.max_redirects = transport, policy, timeout, max_redirects
    def get(self, url: str, headers: Mapping[str, str] | None = None) -> HTTPResponse:
        current = url
        for _ in range(self.max_redirects + 1):
            if self.policy.authority(current) is None: raise ValueError("URL rejected by authority/address policy")
            response = self.transport(current, {"User-Agent":"Kalama-Evidence/1", "Accept":"application/json,text/html,text/plain", **dict(headers or {})}, self.timeout)
            if len(response.body) > MAX_RAW_BYTES: raise ValueError("response exceeds maximum bytes")
            if response.status not in {301,302,303,307,308}: return response
            location = response.headers.get("Location")
            if not location: raise ValueError("redirect without location")
            current = urljoin(current, location)
        raise ValueError("redirect limit exceeded")

class _ExternalSource:
    def __init__(self, kind: SourceKind, http: BoundedHTTP, cache: EvidenceCache, *, enabled: bool = False):
        self.kind, self.http, self.cache, self.enabled = kind, http, cache, enabled
    def _item(self, request: FieldRequest, authority: str, resource: str, response: HTTPResponse, facts: Mapping[str, Any], normalized: Mapping[str, Any] | str, *, status: str = "REFRESHED") -> EvidenceResult:
        raw = self.cache.store_raw(response.body); norm = self.cache.store_normalized(normalized)
        record = self.cache.record(EvidenceCacheRecord(self.kind, authority, resource, POLICY_VERSION, _now(),
            __import__("hashlib").sha256(response.body).hexdigest(), response.headers.get("Last-Modified"), response.headers.get("ETag"), response.headers.get("Last-Modified"), response.headers.get("Content-Type"), raw, norm, status, {"normalized_truncated": isinstance(normalized, Mapping) and bool(normalized.get("truncated"))}))
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, authority, resource, facts, normalized_content=norm, snapshot_sha256=record.content_sha256, retrieved_at=record.retrieved_at, source_modified_at=record.source_modified_at, provenance_ref=f"evidence-cache:{record.record_id}", cache_status=record.cache_status),))

    def _cached(self, request: FieldRequest, authority: str, resource: str, record: EvidenceCacheRecord, facts: Mapping[str, Any], *, state: EvidenceResultState, status: str) -> EvidenceResult:
        if not record.raw_snapshot_sha256 or not record.normalized_snapshot_sha256:
            return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind)
        # Revalidation creates a new index record, never mutates the historical one.
        revalidated_at = record.retrieved_at if status == "STALE" else _now()
        refreshed = self.cache.record(EvidenceCacheRecord(self.kind, authority, resource, POLICY_VERSION,
            revalidated_at, record.content_sha256, record.source_modified_at, record.etag,
            record.last_modified, record.mime_type, record.raw_snapshot_sha256,
            record.normalized_snapshot_sha256, status, record.freshness))
        item = EvidenceItem(request.context, self.kind, authority, resource, facts,
            normalized_content=record.normalized_snapshot_sha256, snapshot_sha256=record.content_sha256,
            retrieved_at=revalidated_at, source_modified_at=record.source_modified_at,
            provenance_ref=f"evidence-cache:{refreshed.record_id}", cache_status=status)
        return EvidenceResult(state, self.kind, (item,))

    def _request(self, resource: str, cached: EvidenceCacheRecord | None) -> HTTPResponse:
        headers = {}
        if cached and cached.etag: headers["If-None-Match"] = cached.etag
        if cached and cached.last_modified: headers["If-Modified-Since"] = cached.last_modified
        return self.http.get(resource, headers)

class NVDEvidenceSource(_ExternalSource):
    def __init__(self, http: BoundedHTTP, cache: EvidenceCache, *, enabled: bool = False): super().__init__(SourceKind.NVD, http, cache, enabled=enabled)
    def collect(self, request: FieldRequest) -> EvidenceResult:
        if not self.enabled: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind, detail="disabled")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + request.context.vulnerability_id
        cached = self.cache.latest(self.kind, url, POLICY_VERSION)
        try:
            response = self._request(url, cached)
            if response.status == 304:
                if cached is None: return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind, detail="304 without cache")
                raw = self.cache.read_raw(cached.raw_snapshot_sha256 or "")
                data = json.loads(raw); cve = data["vulnerabilities"][0]["cve"]
                refs = [x.get("url") for x in cve.get("references", []) if isinstance(x, Mapping) and isinstance(x.get("url"), str)]
                return self._cached(request, "NVD", url, cached, {"nvd_context": {"cve_id": cve.get("id"), "references": refs[:32]}, "references": refs[:32]}, state=EvidenceResultState.AVAILABLE, status="REVALIDATED_UNCHANGED")
            if "json" not in response.headers.get("Content-Type", "").casefold(): raise ValueError("NVD response MIME is not JSON")
            data = json.loads(response.body)
            vulnerabilities = data.get("vulnerabilities")
            if not isinstance(vulnerabilities, list) or len(vulnerabilities) != 1: raise ValueError("NVD response has no unique vulnerability")
            cve = vulnerabilities[0].get("cve", {})
            if str(cve.get("id", "")).upper() != request.context.vulnerability_id: raise ValueError("NVD candidate mismatch")
            refs = [x.get("url") for x in cve.get("references", []) if isinstance(x, Mapping) and isinstance(x.get("url"), str)]
            descriptions = [x.get("value") for x in cve.get("descriptions", []) if isinstance(x, Mapping) and x.get("lang") == "en"]
            normalized = {"cve_id": cve.get("id"), "published": cve.get("published"), "last_modified": cve.get("lastModified"), "description": (descriptions[0] if descriptions else "")[:2048], "references": refs[:32], "truncated": len(refs) > 32}
            facts = {"nvd_context": normalized, "references": refs[:32]}
            return self._item(request, "NVD", url, response, facts, normalized)
        except (TimeoutError, OSError):
            if cached is not None:
                try:
                    raw = self.cache.read_raw(cached.raw_snapshot_sha256 or ""); cve=json.loads(raw)["vulnerabilities"][0]["cve"]
                    return self._cached(request,"NVD",url,cached,{"nvd_context":{"cve_id":cve.get("id")},"references":[]},state=EvidenceResultState.STALE_CACHE_FALLBACK,status="STALE")
                except Exception: pass
            return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind)
        except Exception as exc: return EvidenceResult(EvidenceResultState.REJECTED_BY_POLICY, self.kind, detail=str(exc)[:300])

class VendorEvidenceSource(_ExternalSource):
    def __init__(self, http: BoundedHTTP, cache: EvidenceCache, policy: ExternalPolicy, references: Mapping[str, Sequence[str]], *, enabled: bool = False):
        super().__init__(SourceKind.VENDOR_UPSTREAM, http, cache, enabled=enabled); self.policy, self.references = policy, references
    def collect(self, request: FieldRequest) -> EvidenceResult:
        if not self.enabled: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind, detail="disabled")
        candidates = self.references.get(request.context.vulnerability_id, ())
        url = next((x for x in candidates if self.policy.authority(x)), None)
        if url is None: return EvidenceResult(EvidenceResultState.NO_AUTHORITATIVE_SOURCE, self.kind)
        cached = self.cache.latest(self.kind, url, POLICY_VERSION)
        try:
            response = self._request(url, cached)
            if response.status == 304:
                if cached is None: return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind, detail="304 without cache")
                return self._cached(request, self.policy.authority(url) or "VENDOR_UPSTREAM", url, cached, {"document_evidence":True,"candidate_cve":request.context.vulnerability_id}, state=EvidenceResultState.AVAILABLE, status="REVALIDATED_UNCHANGED")
            mime = response.headers.get("Content-Type", "").casefold()
            if not any(x in mime for x in ("text/", "html", "json", "xml")): raise ValueError("vendor MIME rejected")
            text, truncated = _text(response.body)
            if request.context.vulnerability_id not in text.upper(): return EvidenceResult(EvidenceResultState.REJECTED_BY_POLICY, self.kind, detail="candidate CVE absent from document")
            return self._item(request, self.policy.authority(response.url) or "VENDOR_UPSTREAM", response.url, response, {"document_evidence": True, "candidate_cve": request.context.vulnerability_id}, {"text": text, "truncated": truncated})
        except (TimeoutError, OSError):
            if cached is not None:
                return self._cached(request,self.policy.authority(url) or "VENDOR_UPSTREAM",url,cached,{"document_evidence":True,"candidate_cve":request.context.vulnerability_id},state=EvidenceResultState.STALE_CACHE_FALLBACK,status="STALE")
            return EvidenceResult(EvidenceResultState.UNAVAILABLE, self.kind)
        except Exception as exc: return EvidenceResult(EvidenceResultState.REJECTED_BY_POLICY, self.kind, detail=str(exc)[:300])

class MSFModuleDocumentationSource:
    kind = SourceKind.MSF_MODULE_DOC
    def __init__(self, documentation_roots: Sequence[Path | str], module_paths: Mapping[str, str]): self.roots=tuple(Path(x) for x in documentation_roots); self.module_paths=dict(module_paths)
    def collect(self, request: FieldRequest) -> EvidenceResult:
        module = self.module_paths.get(request.context.vulnerability_id)
        if not module: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        rel = module.replace("/", "_")
        choices = [root / f"{rel}.md" for root in self.roots] + [root / (module + ".md") for root in self.roots]
        path = next((x for x in choices if x.is_file()), None)
        if path is None: return EvidenceResult(EvidenceResultState.NOT_APPLICABLE, self.kind)
        text, truncated = _text(path.read_bytes())
        if module not in text and request.context.vulnerability_id not in text.upper(): return EvidenceResult(EvidenceResultState.REJECTED_BY_POLICY, self.kind, detail="module documentation identity mismatch")
        return EvidenceResult(EvidenceResultState.AVAILABLE, self.kind, (EvidenceItem(request.context, self.kind, "local-metasploit-doc", str(path.resolve()), {"module":module,"truncated":truncated}, normalized_content=text, provenance_ref=str(path.resolve())),))
