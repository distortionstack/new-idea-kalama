"""Injectable CVSS, FIRST EPSS, and CISA KEV enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import http.client
import json
import logging
import signal
import socket
import ssl
import threading
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from .models import (
    AggregatedCVE, CVSSCandidate, CVSSRecord, EnrichedCVE, EPSSRecord,
    EvidenceState, FailureCode, KEVCatalogSnapshot, KEVRecord, KEVState,
    StageIssue,
)


LOG = logging.getLogger(__name__)


class EPSSHTTPError(OSError):
    def __init__(self, status: int):
        super().__init__(f"FIRST EPSS returned HTTP {status}")
        self.status = status


def _bounded_call(operation: Callable[[], Mapping[str, Any]], timeout: float) -> Mapping[str, Any]:
    """Apply a true wall-clock budget on Unix main threads, with socket timeout fallback."""
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        return operation()
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum: int, _frame: Any) -> None:
        raise TimeoutError(f"FIRST EPSS request exceeded {timeout:.3f}s wall-clock budget")

    signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return operation()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])


def _ipv4_connect(host: str, port: int, timeout: float) -> socket.socket:
    """Connect using only addresses returned for AF_INET; no global monkeypatch."""
    addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    last_error: OSError | None = None
    for family, kind, protocol, _canonical, address in addresses:
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error or OSError(f"no IPv4 address is available for {host}")


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection whose address selection is narrowly scoped to IPv4."""

    def connect(self) -> None:
        self.sock = _ipv4_connect(self.host, self.port or 443, self.timeout)
        if self._tunnel_host:
            self._tunnel()
        # The default SSL context preserves CA/hostname verification, while
        # server_hostname preserves SNI even though the socket used an IPv4 address.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _fetch_json_ipv4(url: str, timeout: float) -> Mapping[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("FIRST EPSS transport requires an HTTPS URL")
    context = ssl.create_default_context()
    connection = _IPv4HTTPSConnection(parsed.hostname, parsed.port or 443,
                                      timeout=timeout, context=context)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise EPSSHTTPError(response.status)
        return json.loads(response.read())
    finally:
        connection.close()


class CVSSProvider(Protocol):
    def get_many(self, cve_ids: Sequence[str]) -> Mapping[str, CVSSRecord]: ...


class EPSSProvider(Protocol):
    def get_many(self, cve_ids: Sequence[str], data_date: date) -> Mapping[str, EPSSRecord]: ...


class KEVProvider(Protocol):
    def load_catalog(self) -> KEVCatalogSnapshot: ...


VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}


def _candidate_key(candidate: CVSSCandidate, authority_order: Sequence[str]) -> tuple[Any, ...]:
    authority = candidate.authority.casefold()
    if authority == "nvd":
        return (0, VERSION_RANK[candidate.version], 0, authority, candidate.vector or "")
    normalized = [item.casefold() for item in authority_order]
    authority_rank = normalized.index(authority) if authority in normalized else len(normalized)
    return (1, VERSION_RANK[candidate.version], authority_rank, authority, candidate.vector or "")


def embedded_candidates(aggregate: AggregatedCVE) -> tuple[CVSSCandidate, ...]:
    candidates: dict[tuple[Any, ...], CVSSCandidate] = {}
    for occurrence in aggregate.occurrences:
        for candidate in occurrence.scanner_cvss_candidates:
            key = (candidate.authority, candidate.version, candidate.score, candidate.vector,
                   candidate.transport_source, candidate.source_url)
            candidates[key] = candidate
    return tuple(candidates[key] for key in sorted(candidates, key=lambda x: tuple(str(v) for v in x)))


def authority_precedence(aggregate: AggregatedCVE,
                         configured: Sequence[str] = ()) -> tuple[str, ...]:
    preferred = []
    for occurrence in aggregate.occurrences:
        for value in (occurrence.scanner_severity_source,
                      (occurrence.data_source or {}).get("ID")):
            if isinstance(value, str) and value.casefold() != "nvd":
                preferred.append(value.casefold())
    preferred.extend(str(item).casefold() for item in configured)
    return tuple(dict.fromkeys(preferred))


def select_cvss(candidates: Sequence[CVSSCandidate],
                authority_order: Sequence[str] = ()) -> CVSSRecord:
    if not candidates:
        return CVSSRecord(EvidenceState.MISSING)
    selected = min(candidates, key=lambda x: _candidate_key(x, authority_order))
    return CVSSRecord(
        EvidenceState.AVAILABLE, selected.score, selected.version, selected.authority,
        selected.vector, selected.transport_source, selected.source_url,
    )


def enrich_cvss(aggregates: Sequence[AggregatedCVE], provider: CVSSProvider | None = None,
                vendor_authorities: Sequence[str] = ()) -> Mapping[str, CVSSRecord]:
    embedded = {item.cve_id: embedded_candidates(item) for item in aggregates}
    # NVD is source-first, so a provider gets one chance to supply missing NVD
    # evidence before Kalama selects an embedded vendor fallback.
    needs_provider = sorted(cve for cve, candidates in embedded.items()
                            if not any(x.authority.casefold() == "nvd" for x in candidates))
    external: Mapping[str, CVSSRecord] = provider.get_many(needs_provider) if provider and needs_provider else {}
    output = {}
    by_id = {item.cve_id: item for item in aggregates}
    for cve_id in sorted(by_id):
        external_record = external.get(cve_id)
        candidates = list(embedded[cve_id])
        if (external_record and external_record.state == EvidenceState.AVAILABLE
                and external_record.score is not None and external_record.version is not None
                and external_record.authority is not None):
            candidates.append(CVSSCandidate(
                external_record.authority, external_record.version, external_record.score,
                external_record.vector, external_record.transport_source or "external_provider",
                external_record.source_url,
            ))
        output[cve_id] = select_cvss(
            candidates, authority_precedence(by_id[cve_id], vendor_authorities))
        if output[cve_id].state != EvidenceState.AVAILABLE and external_record is not None:
            output[cve_id] = external_record
    return output


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _decimal(value: Any) -> Decimal:
    parsed = Decimal(str(value))
    if not parsed.is_finite() or parsed < 0 or parsed > 1:
        raise InvalidOperation
    return parsed


class FIRSTEPSSProvider:
    """Small-batch FIRST client. Unit tests inject ``fetch_json``."""

    endpoint = "https://api.first.org/data/v1/epss"

    def __init__(self, fetch_json: Callable[[str, float], Mapping[str, Any]] | None = None,
                 *, max_query_chars: int = 2000, max_batch_size: int = 50,
                 timeout: float = 8,
                 retries: int = 1, total_timeout: float = 30,
                 sleeper: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic,
                 today: Callable[[], date] = date.today):
        self.fetch_json = fetch_json or self._fetch_json
        self.max_query_chars = max_query_chars
        self.max_batch_size = max_batch_size
        self.timeout, self.retries, self.total_timeout = timeout, retries, total_timeout
        self.sleeper, self.monotonic, self.today = sleeper, monotonic, today

    @staticmethod
    def _fetch_json(url: str, timeout: float) -> Mapping[str, Any]:
        return _fetch_json_ipv4(url, timeout)

    def _batches(self, ids: Sequence[str]) -> list[list[str]]:
        batches: list[list[str]] = []
        current: list[str] = []
        for cve_id in sorted(set(ids)):
            proposed = current + [cve_id]
            encoded = urlencode({"cve": ",".join(proposed)})
            if current and (len(encoded) > self.max_query_chars
                            or len(proposed) > self.max_batch_size):
                batches.append(current)
                current = [cve_id]
            else:
                current = proposed
        if current:
            batches.append(current)
        return batches

    def get_many(self, cve_ids: Sequence[str], data_date: date) -> Mapping[str, EPSSRecord]:
        ids = sorted(set(cve_ids))
        retrieved_at = _now()
        output: dict[str, EPSSRecord] = {}
        batches = self._batches(ids)
        deadline = self.monotonic() + self.total_timeout
        current_run = data_date == self.today()
        date_resolution = ("LATEST_AVAILABLE_AS_OF" if current_run else "EXACT_DATE")
        for batch_index, batch in enumerate(batches, 1):
            LOG.info("EPSS enrichment: batch %d/%d", batch_index, len(batches))
            query = {"cve": ",".join(batch)}
            if not current_run:
                query["date"] = data_date.isoformat()
            url = f"{self.endpoint}?{urlencode(query)}"
            payload = None
            for attempt in range(self.retries + 1):
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    LOG.warning("EPSS enrichment unavailable: total deadline exceeded")
                    break
                request_timeout = min(self.timeout, remaining)
                started = self.monotonic()
                LOG.info("EPSS request attempt %d/%d", attempt + 1, self.retries + 1)
                try:
                    payload = _bounded_call(
                        lambda: self.fetch_json(url, request_timeout), request_timeout)
                    LOG.info("EPSS request succeeded in %.3fs", self.monotonic() - started)
                    break
                except Exception as exc:
                    LOG.warning("EPSS request attempt %d/%d failed after %.3fs: %s: %s",
                                attempt + 1, self.retries + 1,
                                self.monotonic() - started, type(exc).__name__, str(exc))
                    if isinstance(exc, EPSSHTTPError) and 400 <= exc.status < 500:
                        LOG.warning("EPSS request will not retry deterministic HTTP %d", exc.status)
                        break
                    if attempt < self.retries:
                        delay = min(0.1 * (2 ** attempt), max(0, deadline - self.monotonic()))
                        if delay:
                            LOG.info("EPSS request retrying in %.1fs", delay)
                            self.sleeper(delay)
            if payload is None:
                for cve_id in batch:
                    output[cve_id] = EPSSRecord(EvidenceState.LOOKUP_FAILED,
                                                retrieved_at=retrieved_at,
                                                as_of_date=data_date.isoformat(),
                                                date_resolution=date_resolution)
                continue
            returned: set[str] = set()
            rows = payload.get("data") if isinstance(payload, Mapping) else None
            if not isinstance(rows, list):
                rows = []
            for row in rows:
                if not isinstance(row, Mapping) or row.get("cve") not in batch:
                    continue
                cve_id = str(row["cve"])
                try:
                    score, percentile = _decimal(row.get("epss")), _decimal(row.get("percentile"))
                except (InvalidOperation, ValueError, TypeError):
                    output[cve_id] = EPSSRecord(EvidenceState.INVALID,
                                                retrieved_at=retrieved_at,
                                                as_of_date=data_date.isoformat(),
                                                date_resolution=date_resolution)
                else:
                    row_date = str(row.get("date") or data_date.isoformat())
                    try:
                        effective = date.fromisoformat(row_date)
                    except ValueError:
                        output[cve_id] = EPSSRecord(
                            EvidenceState.INVALID, retrieved_at=retrieved_at,
                            as_of_date=data_date.isoformat(), date_resolution=date_resolution)
                    else:
                        state = (EvidenceState.AVAILABLE if effective <= data_date
                                 else EvidenceState.INVALID)
                        output[cve_id] = EPSSRecord(
                            state, score if state == EvidenceState.AVAILABLE else None,
                            percentile if state == EvidenceState.AVAILABLE else None,
                            row_date, retrieved_at, as_of_date=data_date.isoformat(),
                            date_resolution=date_resolution)
                returned.add(cve_id)
            for cve_id in set(batch) - returned:
                output[cve_id] = EPSSRecord(EvidenceState.MISSING,
                                            retrieved_at=retrieved_at,
                                            as_of_date=data_date.isoformat(),
                                            date_resolution=date_resolution)
            if self.monotonic() >= deadline and batch_index < len(batches):
                LOG.warning("EPSS enrichment unavailable: total deadline exceeded")
        for cve_id in set(ids) - set(output):
            output[cve_id] = EPSSRecord(EvidenceState.LOOKUP_FAILED,
                                        retrieved_at=retrieved_at,
                                        as_of_date=data_date.isoformat(),
                                        date_resolution=date_resolution)
        return output


def parse_kev_catalog(payload: bytes, *, retrieved_at: str, source: str = "CISA",
                      etag: str | None = None, last_modified: str | None = None,
                      cache_status: str | None = None) -> KEVCatalogSnapshot:
    digest = hashlib.sha256(payload).hexdigest()
    try:
        data = json.loads(payload)
        vulnerabilities = data["vulnerabilities"]
        if not isinstance(vulnerabilities, list):
            raise ValueError("vulnerabilities must be an array")
        cves = []
        for item in vulnerabilities:
            if not isinstance(item, dict) or not isinstance(item.get("cveID"), str):
                raise ValueError("each KEV entry must contain cveID")
            cve = item["cveID"].strip().upper()
            if not cve.startswith("CVE-"):
                raise ValueError("invalid KEV cveID")
            cves.append(cve)
        declared = data.get("count")
        if declared is not None and (isinstance(declared, bool) or int(declared) != len(vulnerabilities)):
            raise ValueError("KEV count does not match vulnerabilities")
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return KEVCatalogSnapshot(EvidenceState.INVALID, retrieved_at=retrieved_at,
                                  source=source, sha256=digest)
    return KEVCatalogSnapshot(
        EvidenceState.AVAILABLE, frozenset(cves), str(data.get("catalogVersion")) if data.get("catalogVersion") is not None else None,
        str(data.get("dateReleased")) if data.get("dateReleased") is not None else None,
        retrieved_at, source, digest, len(vulnerabilities), etag, last_modified, cache_status,
    )


class CISAKEVProvider:
    endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, fetch: Callable[[str, float], tuple[bytes, Mapping[str, str]]] | None = None,
                 *, timeout: float = 20, retries: int = 2,
                 sleeper: Callable[[float], None] = time.sleep):
        self.fetch = fetch or self._fetch
        self.timeout, self.retries, self.sleeper = timeout, retries, sleeper

    @staticmethod
    def _fetch(url: str, timeout: float) -> tuple[bytes, Mapping[str, str]]:
        with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=timeout) as response:
            return response.read(), dict(response.headers.items())

    def load_catalog(self) -> KEVCatalogSnapshot:
        for attempt in range(self.retries + 1):
            try:
                payload, headers = self.fetch(self.endpoint, self.timeout)
                return parse_kev_catalog(payload, retrieved_at=_now(), etag=headers.get("ETag"),
                                         last_modified=headers.get("Last-Modified"),
                                         cache_status="MISS")
            except Exception:
                if attempt < self.retries:
                    self.sleeper(0.1 * (2 ** attempt))
        return KEVCatalogSnapshot(EvidenceState.LOOKUP_FAILED, retrieved_at=_now())


def kev_records(cve_ids: Sequence[str], catalog: KEVCatalogSnapshot) -> Mapping[str, KEVRecord]:
    if catalog.state != EvidenceState.AVAILABLE:
        return {cve: KEVRecord(KEVState.LOOKUP_FAILED, None) for cve in sorted(set(cve_ids))}
    return {cve: KEVRecord(KEVState.LISTED, True) if cve in catalog.cve_ids
            else KEVRecord(KEVState.NOT_LISTED, False) for cve in sorted(set(cve_ids))}


@dataclass(frozen=True)
class EnrichmentResult:
    enriched: tuple[EnrichedCVE, ...]
    issues: tuple[StageIssue, ...]
    kev_catalog: KEVCatalogSnapshot


def enrich_cves(aggregates: Sequence[AggregatedCVE], *, epss_data_date: date,
                epss_provider: EPSSProvider, kev_provider: KEVProvider,
                cvss_provider: CVSSProvider | None = None,
                vendor_authorities: Sequence[str] = ()) -> EnrichmentResult:
    ids = [item.cve_id for item in aggregates]
    cvss = enrich_cvss(aggregates, cvss_provider, vendor_authorities)
    try:
        epss = epss_provider.get_many(ids, epss_data_date)
    except Exception:
        epss = {cve: EPSSRecord(EvidenceState.LOOKUP_FAILED,
                                data_date=epss_data_date.isoformat()) for cve in ids}
    try:
        catalog = kev_provider.load_catalog()
    except Exception:
        catalog = KEVCatalogSnapshot(EvidenceState.LOOKUP_FAILED)
    kev = kev_records(ids, catalog)
    issues = []
    enriched = []
    for aggregate in aggregates:
        cve_id = aggregate.cve_id
        cvss_record = cvss.get(cve_id, CVSSRecord(EvidenceState.MISSING))
        epss_record = epss.get(cve_id, EPSSRecord(EvidenceState.MISSING,
                                                 data_date=epss_data_date.isoformat()))
        kev_record = kev[cve_id]
        if cvss_record.state != EvidenceState.AVAILABLE:
            issues.append(StageIssue(FailureCode.CVSS_UNAVAILABLE, "enrichment",
                                     f"CVSS is {cvss_record.state.value}", cve_id, provider="CVSS"))
        if epss_record.state != EvidenceState.AVAILABLE:
            code = FailureCode.EPSS_LOOKUP_FAILED if epss_record.state == EvidenceState.LOOKUP_FAILED else FailureCode.EPSS_MISSING
            issues.append(StageIssue(code, "enrichment", f"EPSS is {epss_record.state.value}",
                                     cve_id, epss_record.state == EvidenceState.LOOKUP_FAILED, "FIRST"))
        if kev_record.state == KEVState.LOOKUP_FAILED:
            code = FailureCode.KEV_CATALOG_INVALID if catalog.state == EvidenceState.INVALID else FailureCode.KEV_CATALOG_FAILED
            issues.append(StageIssue(code, "enrichment", f"KEV catalog is {catalog.state.value}",
                                     cve_id, catalog.state == EvidenceState.LOOKUP_FAILED, "CISA"))
        enriched.append(EnrichedCVE(aggregate, cvss_record, epss_record, kev_record))
    if issues:
        issues.append(StageIssue(FailureCode.ENRICHMENT_INCOMPLETE, "enrichment",
                                 "scoring-critical evidence is incomplete"))
    return EnrichmentResult(tuple(enriched), tuple(issues), catalog)
