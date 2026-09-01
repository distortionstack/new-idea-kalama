import copy
from datetime import date
from decimal import Decimal
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from src.app.kalama.prioritizer.enrichment import (
    EPSSHTTPError, FIRSTEPSSProvider, EnrichmentResult, enrich_cves, enrich_cvss,
    _bounded_call, _ipv4_connect, kev_records, parse_kev_catalog, select_cvss,
)
from src.app.kalama.prioritizer.models import (
    CVSSCandidate, CVSSRecord, EPSSRecord, EvidenceState, KEVCatalogSnapshot,
    KEVState, VulnerabilityOccurrence,
)
from src.app.kalama.prioritizer.pipeline import (
    prioritize_trivy, serialize_artifact, write_artifact_atomic,
)
from src.app.kalama.prioritizer.exposure import exposure_from_facts
from src.app.kalama.prioritizer.scoring import rank_cves, score_cve
from src.app.kalama.prioritizer.trivy_parser import (
    TrivyArtifactError, aggregate_unique_cves, parse_trivy_report,
)


def finding(cve="CVE-2021-44228", package="pkg", score="9.8", **extra):
    value = {
        "VulnerabilityID": cve, "PkgName": package, "InstalledVersion": "1.0",
        "FixedVersion": "1.1", "Severity": "CRITICAL", "SeveritySource": "redhat",
        "CVSS": {"nvd": {"V3Score": score, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
        "References": ["https://example.test"],
    }
    value.update(extra)
    return value


def report(results=None):
    return {"SchemaVersion": 2, "Trivy": {"Version": "0.72.0"},
            "ArtifactName": "image:test", "Results": results if results is not None else [
                {"Target": "image:test", "Class": "os-pkgs", "Type": "debian",
                 "Vulnerabilities": [finding()]}
            ]}


class FakeEPSS:
    def __init__(self, records=None, state=EvidenceState.AVAILABLE):
        self.records, self.state, self.calls = records or {}, state, []

    def get_many(self, ids, data_date):
        self.calls.append((list(ids), data_date))
        return {cve: self.records.get(cve, EPSSRecord(
            self.state, Decimal("0.5") if self.state == EvidenceState.AVAILABLE else None,
            Decimal("0.8") if self.state == EvidenceState.AVAILABLE else None,
            data_date.isoformat(), "2026-08-31T00:00:00Z")) for cve in ids}


class FakeKEV:
    def __init__(self, state=EvidenceState.AVAILABLE, listed=()):
        self.state, self.listed = state, listed

    def load_catalog(self):
        return KEVCatalogSnapshot(self.state, frozenset(self.listed), "2026.08.31",
                                  "2026-08-31", "2026-08-31T00:00:00Z", sha256="abc", count=len(self.listed))


class ParserTests(unittest.TestCase):
    def test_os_and_language_occurrences_across_results(self):
        data = report([
            {"Target": "OS", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [finding(package="apt")]},
            {"Target": "Java", "Class": "lang-pkgs", "Type": "jar", "Vulnerabilities": [finding(package="g:a")]},
        ])
        parsed = parse_trivy_report(data)
        self.assertEqual(len(parsed.occurrences), 2)
        self.assertEqual({x.result_type for x in parsed.occurrences}, {"debian", "jar"})
        aggregate = aggregate_unique_cves(parsed.occurrences)
        self.assertEqual(len(aggregate), 1)
        self.assertEqual(len(aggregate[0].occurrences), 2)

    def test_duplicate_occurrence_is_counted_not_repeated(self):
        item = finding()
        parsed = parse_trivy_report(report([{"Target": "T", "Class": "os-pkgs", "Type": "debian",
                                             "Vulnerabilities": [item, copy.deepcopy(item)]}]))
        aggregate = aggregate_unique_cves(parsed.occurrences)
        self.assertEqual(len(aggregate[0].occurrences), 1)
        self.assertEqual(aggregate[0].occurrences[0].duplicate_count, 2)

    def test_empty_vulnerability_variants(self):
        parsed = parse_trivy_report(report([
            {"Target": "a"}, {"Target": "b", "Vulnerabilities": None},
            {"Target": "c", "Vulnerabilities": []},
        ]))
        self.assertEqual(parsed.occurrences, ())

    def test_missing_results_is_invalid(self):
        with self.assertRaises(TrivyArtifactError):
            parse_trivy_report({"SchemaVersion": 2})

    def test_ghsa_excluded_explicit_alias_accepted_malformed_retained(self):
        parsed = parse_trivy_report(report([{"Target": "T", "Vulnerabilities": [
            finding("GHSA-abcd-efgh-ijkl"),
            finding("GHSA-with-alias", Aliases=["cve-2020-1234"]),
            finding("CVE-bad"),
        ]}]))
        self.assertEqual([x.canonical_cve_id for x in parsed.occurrences], ["CVE-2020-1234"])
        self.assertEqual({x.reason for x in parsed.excluded_findings},
                         {"NON_CVE_IDENTIFIER", "MALFORMED_CVE_IDENTIFIER"})

    def test_missing_fixed_version_and_package_identifiers(self):
        parsed = parse_trivy_report(report([{"Target": "T", "Vulnerabilities": [
            finding(FixedVersion=None, PkgIdentifier={"PURL": "pkg:x/y@1", "UID": "u"})
        ]}]))
        item = parsed.occurrences[0]
        self.assertEqual(item.fixed_versions, ())
        self.assertEqual((item.package_purl, item.package_uid), ("pkg:x/y@1", "u"))

    def test_aggregation_is_input_order_independent(self):
        occurrences = parse_trivy_report(report([{"Target": "T", "Vulnerabilities": [
            finding("CVE-2020-0002", "b"), finding("CVE-2020-0001", "a")
        ]}])).occurrences
        self.assertEqual(aggregate_unique_cves(occurrences), aggregate_unique_cves(reversed(occurrences)))


class CVSSTests(unittest.TestCase):
    def candidate(self, authority, version, score="5"):
        vector = f"CVSS:{version}/AV:N" if version != "2.0" else "AV:N/AC:L"
        return CVSSCandidate(authority, version, Decimal(score), vector)

    def test_frozen_source_and_version_precedence(self):
        values = [self.candidate("nvd", "3.0"), self.candidate("nvd", "3.1"),
                  self.candidate("nvd", "4.0"), self.candidate("redhat", "4.0", "10")]
        self.assertEqual(select_cvss(values).version, "4.0")
        self.assertEqual(select_cvss(values).authority, "nvd")
        self.assertEqual(select_cvss(values[0:2]).version, "3.1")

    def test_invalid_scores_and_inconsistent_vectors_are_rejected(self):
        parsed = parse_trivy_report(report([{"Target": "T", "Vulnerabilities": [
            finding(CVSS={"nvd": {"V3Score": 99, "V3Vector": "CVSS:3.1/X"},
                                   "x": {"V3Score": 5, "V3Vector": "CVSS:4.0/X"}})
        ]}]))
        self.assertEqual(parsed.occurrences[0].scanner_cvss_candidates, ())

    def test_embedded_nvd_avoids_provider_and_provider_fallback(self):
        aggregates = aggregate_unique_cves(parse_trivy_report(report()).occurrences)
        class Provider:
            def __init__(self): self.calls = []
            def get_many(self, ids):
                self.calls.append(list(ids))
                return {cve: CVSSRecord(EvidenceState.AVAILABLE, Decimal("7"), "4.0", "nvd", transport_source="nvd_api") for cve in ids}
        provider = Provider()
        selected = enrich_cvss(aggregates, provider)
        self.assertEqual(provider.calls, [])
        no_nvd = report([{"Target": "T", "Vulnerabilities": [finding(CVSS={
            "redhat": {"V3Score": 6, "V3Vector": "CVSS:3.1/X"}})]}])
        selected = enrich_cvss(aggregate_unique_cves(parse_trivy_report(no_nvd).occurrences), provider)
        self.assertEqual(provider.calls[-1], ["CVE-2021-44228"])
        self.assertEqual(selected["CVE-2021-44228"].transport_source, "nvd_api")

    def test_vendor_fallback_is_deterministic(self):
        values = [self.candidate("zulu", "3.1"), self.candidate("alpha", "3.1")]
        self.assertEqual(select_cvss(values).authority, "alpha")
        self.assertEqual(select_cvss(values, ("zulu",)).authority, "zulu")


class ProviderTests(unittest.TestCase):
    def test_epss_wall_clock_budget_interrupts_blocking_transport(self):
        import time
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            _bounded_call(lambda: (time.sleep(0.2) or {}), 0.03)
        self.assertLess(time.monotonic() - started, 0.15)

    def test_epss_deterministic_http_4xx_is_not_retried(self):
        calls = []
        def rejected(*_):
            calls.append(1)
            raise EPSSHTTPError(422)
        record = FIRSTEPSSProvider(rejected, retries=3).get_many(
            ["CVE-2017-5638"], date(2026, 9, 1))["CVE-2017-5638"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(record.state, EvidenceState.LOOKUP_FAILED)

    def test_epss_transport_resolves_only_ipv4_without_global_socket_changes(self):
        import socket
        original_has_ipv6 = socket.has_ipv6
        observed = []

        class FakeSocket:
            def settimeout(self, value): observed.append(("timeout", value))
            def connect(self, address): observed.append(("connect", address))
            def close(self): observed.append(("close", None))

        with patch("src.app.kalama.prioritizer.enrichment.socket.getaddrinfo",
                   return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]) as lookup, \
             patch("src.app.kalama.prioritizer.enrichment.socket.socket",
                   return_value=FakeSocket()):
            _ipv4_connect("api.first.org", 443, 5)
        self.assertEqual(lookup.call_args.args[2], socket.AF_INET)
        self.assertIn(("connect", ("192.0.2.1", 443)), observed)
        self.assertEqual(socket.has_ipv6, original_has_ipv6)

    def test_epss_success_for_live_smoke_cve(self):
        provider = FIRSTEPSSProvider(lambda *_: {"data": [{
            "cve": "CVE-2017-5638", "epss": "0.999990000",
            "percentile": "0.99999", "date": "2026-09-01"}]}, retries=0)
        record = provider.get_many(["CVE-2017-5638"], date(2026, 9, 1))["CVE-2017-5638"]
        self.assertEqual(record.state, EvidenceState.AVAILABLE)
        self.assertEqual(record.score, Decimal("0.999990000"))

    def test_epss_current_run_accepts_latest_previous_day_with_provenance(self):
        urls = []
        provider = FIRSTEPSSProvider(lambda url, _timeout: (urls.append(url) or {"data": [{
            "cve": "CVE-2017-5638", "epss": "0.9", "percentile": "0.8",
            "date": "2026-08-31"}]}), retries=0, today=lambda: date(2026, 9, 1))
        record = provider.get_many(["CVE-2017-5638"], date(2026, 9, 1))["CVE-2017-5638"]
        self.assertEqual(record.state, EvidenceState.AVAILABLE)
        self.assertNotIn("date=", urls[0])
        self.assertEqual(record.as_of_date, "2026-09-01")
        self.assertEqual(record.data_date, "2026-08-31")
        self.assertEqual(record.date_resolution, "LATEST_AVAILABLE_AS_OF")

    def test_epss_future_provider_snapshot_is_rejected(self):
        provider = FIRSTEPSSProvider(lambda *_: {"data": [{
            "cve": "CVE-2017-5638", "epss": "0.9", "percentile": "0.8",
            "date": "2026-09-01"}]}, retries=0, today=lambda: date(2026, 8, 31))
        record = provider.get_many(["CVE-2017-5638"], date(2026, 8, 31))["CVE-2017-5638"]
        self.assertEqual(record.state, EvidenceState.INVALID)
        self.assertIsNone(record.score)
        self.assertEqual(record.as_of_date, "2026-08-31")

    def test_epss_historical_lookup_remains_exact_date(self):
        urls = []
        provider = FIRSTEPSSProvider(lambda url, _timeout: (urls.append(url) or {"data": []}),
                                     retries=0, today=lambda: date(2026, 9, 1))
        provider.get_many(["CVE-2017-5638"], date(2026, 8, 30))
        self.assertIn("date=2026-08-30", urls[0])

    def test_epss_batches_latest_queries_below_provider_result_limit(self):
        calls = []
        def fetch(url, _timeout):
            from urllib.parse import parse_qs, urlsplit
            ids = parse_qs(urlsplit(url).query)["cve"][0].split(",")
            calls.append(ids)
            return {"data": [{"cve": cve, "epss": "0.1", "percentile": "0.2",
                              "date": "2026-08-31"} for cve in ids]}
        ids = [f"CVE-2026-{index:04d}" for index in range(1, 122)]
        records = FIRSTEPSSProvider(
            fetch, max_query_chars=10000, max_batch_size=50, retries=0,
            today=lambda: date(2026, 9, 1)).get_many(ids, date(2026, 9, 1))
        self.assertEqual([len(x) for x in calls], [50, 50, 21])
        self.assertTrue(all(x.state == EvidenceState.AVAILABLE for x in records.values()))

    def test_epss_timeout_retry_and_total_deadline_are_bounded_without_zero(self):
        calls = []
        ticks = iter((0, 0, 0, 4, 4, 4, 8, 8, 8, 8, 8, 8))
        def clock(): return next(ticks, 8)
        def timeout(_url, budget):
            calls.append(budget)
            raise TimeoutError("simulated")
        provider = FIRSTEPSSProvider(timeout, max_query_chars=25, timeout=5, retries=1,
                                     total_timeout=8, sleeper=lambda _: None, monotonic=clock)
        records = provider.get_many(["CVE-2020-0001", "CVE-2020-0002"], date(2026, 8, 30))
        self.assertLessEqual(len(calls), 2)
        self.assertTrue(all(x.state == EvidenceState.LOOKUP_FAILED for x in records.values()))
        self.assertTrue(all(x.score is None for x in records.values()))

    def test_epss_batch_order_zero_missing_and_date(self):
        calls = []
        def fetch(url, timeout):
            calls.append(url)
            return {"data": [
                {"cve": "CVE-2020-0002", "epss": "0", "percentile": "0.1", "date": "2026-08-30"},
                {"cve": "CVE-2020-0001", "epss": "0.5", "percentile": "0.8", "date": "2026-08-30"},
            ]}
        provider = FIRSTEPSSProvider(fetch, max_query_chars=2000, retries=0)
        records = provider.get_many(["CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0001"], date(2026, 8, 30))
        self.assertEqual(records["CVE-2020-0002"].score, Decimal("0"))
        self.assertEqual(records["CVE-2020-0003"].state, EvidenceState.MISSING)
        self.assertEqual(records["CVE-2020-0001"].data_date, "2026-08-30")

    def test_epss_lookup_failure_and_deterministic_batching(self):
        provider = FIRSTEPSSProvider(lambda *_: (_ for _ in ()).throw(OSError("down")),
                                     max_query_chars=25, retries=1, sleeper=lambda _: None)
        records = provider.get_many(["CVE-2020-0002", "CVE-2020-0001"], date(2026, 8, 30))
        self.assertTrue(all(x.state == EvidenceState.LOOKUP_FAILED for x in records.values()))

    def test_kev_listed_not_listed_invalid_and_failure(self):
        payload = json.dumps({"catalogVersion": "1", "dateReleased": "2026-08-31",
                              "count": 1, "vulnerabilities": [{"cveID": "CVE-2020-0001"}]}).encode()
        catalog = parse_kev_catalog(payload, retrieved_at="now")
        records = kev_records(["CVE-2020-0001", "CVE-2020-0002"], catalog)
        self.assertEqual(records["CVE-2020-0001"].state, KEVState.LISTED)
        self.assertEqual(records["CVE-2020-0002"].state, KEVState.NOT_LISTED)
        invalid = parse_kev_catalog(b'{"count":2,"vulnerabilities":[]}', retrieved_at="now")
        self.assertEqual(invalid.state, EvidenceState.INVALID)
        failed = kev_records(["CVE-2020-0002"], KEVCatalogSnapshot(EvidenceState.LOOKUP_FAILED))
        self.assertEqual(failed["CVE-2020-0002"].state, KEVState.LOOKUP_FAILED)
        self.assertIsNone(failed["CVE-2020-0002"].listed)


class ScoringPipelineTests(unittest.TestCase):
    def test_exact_score(self):
        result = score_cve(Decimal("10"), Decimal("0.94"), True)
        self.assertEqual(result.total_raw, Decimal("15.82"))
        self.assertEqual(result.to_dict()["components"]["epss"]["contribution"], "2.82")

    def _run(self, data=None, epss=None, kev=None, **kwargs):
        return prioritize_trivy(
            data or report(), run_id="aB3x9", created_at="2026-08-31T00:00:00Z",
            epss_data_date=date(2026, 8, 30), trivy_path="input.json", trivy_sha256="abc",
            epss_provider=epss or FakeEPSS(), kev_provider=kev or FakeKEV(), **kwargs)

    def test_missing_critical_evidence_blocks_artifact(self):
        missing_epss = self._run(epss=FakeEPSS(state=EvidenceState.MISSING))
        failed_kev = self._run(kev=FakeKEV(EvidenceState.LOOKUP_FAILED))
        no_cvss = self._run(report([{"Target": "T", "Vulnerabilities": [finding(CVSS={})]}]))
        for result in (missing_epss, failed_kev, no_cvss):
            self.assertFalse(result.success)
            self.assertIsNone(result.artifact)
            self.assertIn("ENRICHMENT_INCOMPLETE", [x.code.value for x in result.issues])

    def test_tie_breaks_and_randomized_order(self):
        # Same total: listed(3)+EPSS0 beats nonlisted+EPSS1; KEV wins first tie-break.
        ids = ["CVE-2020-0005", "CVE-2020-0004", "CVE-2020-0003", "CVE-2020-0002", "CVE-2020-0001"]
        findings = [finding(cve, package=cve, score="5") for cve in ids]
        data = report([{"Target": "T", "Vulnerabilities": findings}])
        records = {cve: EPSSRecord(EvidenceState.AVAILABLE, Decimal("0.5"), Decimal("0.5"), "2026-08-30", "now") for cve in ids}
        baseline = self._run(data, epss=FakeEPSS(records), kev=FakeKEV(listed=[ids[0]]))
        random.Random(9).shuffle(findings)
        shuffled = self._run(data, epss=FakeEPSS(records), kev=FakeKEV(listed=[ids[0]]))
        self.assertEqual([x.enriched.aggregate.cve_id for x in baseline.ranked_cves],
                         [x.enriched.aggregate.cve_id for x in shuffled.ranked_cves])
        self.assertEqual(baseline.ranked_cves[0].enriched.aggregate.cve_id, ids[0])
        self.assertEqual(baseline.ranked_cves[1].enriched.aggregate.cve_id, "CVE-2020-0001")

    def test_exact_tie_break_chain_kev_epss_and_cve_id(self):
        # KEV breaks an equal total: 5 + 0*3 + 3 equals 5 + 1*3 + 0.
        kev_tie = report([{"Target": "T", "Vulnerabilities": [
            finding("CVE-2020-0101", score="5"), finding("CVE-2020-0102", score="5")]}])
        records = {
            "CVE-2020-0101": EPSSRecord(EvidenceState.AVAILABLE, Decimal("0"), Decimal("0"), "2026-08-30", "now"),
            "CVE-2020-0102": EPSSRecord(EvidenceState.AVAILABLE, Decimal("1"), Decimal("1"), "2026-08-30", "now"),
        }
        result = self._run(kev_tie, epss=FakeEPSS(records), kev=FakeKEV(listed=["CVE-2020-0101"]))
        self.assertEqual(result.ranked_cves[0].enriched.aggregate.cve_id, "CVE-2020-0101")

        # With equal total and KEV, higher EPSS precedes higher CVSS.
        epss_tie = report([{"Target": "T", "Vulnerabilities": [
            finding("CVE-2020-0201", score="5.2"), finding("CVE-2020-0202", score="5.5")]}])
        records = {
            "CVE-2020-0201": EPSSRecord(EvidenceState.AVAILABLE, Decimal("0.6"), Decimal("0"), "2026-08-30", "now"),
            "CVE-2020-0202": EPSSRecord(EvidenceState.AVAILABLE, Decimal("0.5"), Decimal("0"), "2026-08-30", "now"),
        }
        result = self._run(epss_tie, epss=FakeEPSS(records))
        self.assertEqual(result.ranked_cves[0].enriched.aggregate.cve_id, "CVE-2020-0201")

        # Exact equality reaches canonical CVE-ID ascending.
        lexical = report([{"Target": "T", "Vulnerabilities": [
            finding("CVE-2020-0302", score="5"), finding("CVE-2020-0301", score="5")]}])
        result = self._run(lexical)
        self.assertEqual([x.enriched.aggregate.cve_id for x in result.ranked_cves],
                         ["CVE-2020-0301", "CVE-2020-0302"])

    def test_target_exposure_is_context_only_and_deterministic(self):
        first = exposure_from_facts({"collection_complete": True, "observations": [
            {"kind": "tcp_reachable", "port": 443}, {"kind": "container_running"}]})
        second = exposure_from_facts({"collection_complete": True, "observations": [
            {"kind": "container_running"}, {"kind": "tcp_reachable", "port": 443}]})
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict()["score"], None)
        self.assertEqual(first.to_dict()["classification"], "TARGET_CONTEXT_ONLY")

    def test_top_30_unique_and_duplicates_do_not_consume_slots(self):
        findings = [finding(f"CVE-2020-{i:04d}", package=f"p{i}") for i in range(1, 32)]
        findings.append(copy.deepcopy(findings[0]))
        result = self._run(report([{"Target": "T", "Vulnerabilities": findings}]))
        self.assertTrue(result.success)
        self.assertEqual(len(result.ranked_cves), 30)
        self.assertEqual(len({x.enriched.aggregate.cve_id for x in result.ranked_cves}), 30)

    def test_fewer_than_30_and_empty_report(self):
        one = self._run()
        empty = self._run(report([]))
        self.assertEqual(len(one.ranked_cves), 1)
        self.assertTrue(empty.success)
        self.assertEqual(empty.artifact["artifact"]["top_n_returned"], 0)
        self.assertEqual(empty.artifact["ranked_cves"], [])

    def test_parsing_does_not_mutate_input_and_realistic_fixture(self):
        data = report()
        snapshot = copy.deepcopy(data)
        parse_trivy_report(data)
        self.assertEqual(data, snapshot)
        fixture = Path(__file__).parent / "tests/fixtures/trivy_realistic.json"
        parsed = parse_trivy_report(json.loads(fixture.read_text()))
        self.assertEqual(len(aggregate_unique_cves(parsed.occurrences)), 2)

    def test_deterministic_serialization_and_provenance(self):
        result = self._run(target_facts_reference={"path": "facts.json", "sha256": "def"})
        first = serialize_artifact(result.artifact)
        second = serialize_artifact(result.artifact)
        self.assertEqual(first, second)
        self.assertIn(b'"exposure_in_score": false', first)
        self.assertIn(b'"sha256": "abc"', first)

    def test_atomic_write_failure_leaves_existing_canonical_file(self):
        result = self._run()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "top30.json"
            path.write_text("old")
            with patch("src.app.kalama.prioritizer.pipeline.os.replace", side_effect=OSError("boom")):
                with self.assertRaises(RuntimeError):
                    write_artifact_atomic(path, result.artifact)
            self.assertEqual(path.read_text(), "old")
            self.assertEqual(list(Path(tmp).glob(".top30.json.*")), [])


if __name__ == "__main__":
    unittest.main()
