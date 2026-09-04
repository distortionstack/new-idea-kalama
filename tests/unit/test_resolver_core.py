import json
import unittest

from kalama.resolver.core import DiscoveryBackend, discover_cve
from kalama.resolver.models import (
    DiscoveryStatus,
    PayloadDiscoveryStatus,
    ObservedPort,
    PublishedPort,
    TargetFacts,
)


def make_backend(*, cache, cached_candidates=None, live_names=None, live_data=None,
                 search_error=None, query_error=None):
    def load_cache():
        return cache

    def find_from_cache(_cache, _cve_id):
        return cached_candidates or {}

    def search_live(_cve_id, _container):
        if search_error:
            raise RuntimeError(search_error)
        return live_names or []

    def query_modules(_fullnames, _container):
        if query_error:
            raise RuntimeError(query_error)
        return live_data or {}

    return DiscoveryBackend(
        load_cache=load_cache,
        find_from_cache=find_from_cache,
        search_live=search_live,
        query_modules=query_modules,
        cache_description="test-cache.json",
    )


class ResolverCoreContractTests(unittest.TestCase):
    def test_compatible_payloads_are_normalized_deduplicated_without_eager_schema(self):
        live = {"exploit/example": {
            "options": [], "status": "FOUND", "payloads": [
                {"name": "payload/cmd/unix/generic", "options": []},
                {"name": "cmd/unix/generic", "options": []},
                {"name": "cmd/unix/reverse_bash", "options": [
                    {"name": "LHOST", "type": "address", "required": True, "default": None},
                    {"name": "LPORT", "type": "port", "required": True, "default": 4444},
                ]},
            ]}}
        result = discover_cve("CVE-2099-0100", "msf", make_backend(
            cache={"present": True}, cached_candidates={"exploit/example": {}}, live_data=live))
        candidate = result.candidates[0]
        self.assertEqual(candidate.payload_discovery_status, PayloadDiscoveryStatus.FOUND)
        self.assertEqual([item.name for item in candidate.payloads],
                         ["cmd/unix/generic", "cmd/unix/reverse_bash"])
        self.assertTrue(all(not item.options for item in candidate.payloads))

    def test_large_payload_allowlist_does_not_introspect_options(self):
        calls = []
        names = [{"name": f"cmd/test/payload_{index}"} for index in range(2201)]
        backend = make_backend(
            cache={"present": True}, cached_candidates={"exploit/example": {}},
            live_data={"exploit/example": {"options": [], "status": "FOUND",
                                             "payloads": names}})
        backend = DiscoveryBackend(**{**backend.__dict__,
            "introspect_payload": lambda *_: calls.append(1)})
        candidate = discover_cve("CVE-2099-0199", "msf", backend).candidates[0]
        self.assertEqual(len(candidate.payloads), 2201)
        self.assertEqual(calls, [])

    def test_sole_real_target_becomes_deterministic_default(self):
        live = {"exploit/example": {"options": [],
            "target_details": [{"index": 7, "name": "Universal"}],
            "default_target_index": None}}
        candidate = discover_cve("CVE-2099-0103", "msf", make_backend(
            cache={"present": True}, cached_candidates={"exploit/example": {"targets": ["Universal"]}},
            live_data=live)).candidates[0]
        self.assertEqual(candidate.default_target_index, 7)

    def test_multiple_targets_without_valid_default_remain_unresolved(self):
        live = {"exploit/example": {"options": [],
            "target_details": [{"index": 0, "name": "A"}, {"index": 1, "name": "B"}],
            "default_target_index": 9}}
        candidate = discover_cve("CVE-2099-0104", "msf", make_backend(
            cache={"present": True}, cached_candidates={"exploit/example": {"targets": ["A", "B"]}},
            live_data=live)).candidates[0]
        self.assertIsNone(candidate.default_target_index)

    def test_payload_discovery_unavailable_is_explicit(self):
        result = discover_cve("CVE-2099-0101", "msf", make_backend(
            cache={"present": True}, cached_candidates={"exploit/example": {}},
            live_data={"exploit/example": {"options": []}}))
        self.assertEqual(result.candidates[0].payloads, ())
        self.assertEqual(result.candidates[0].payload_discovery_status,
                         PayloadDiscoveryStatus.UNAVAILABLE)

    def test_real_target_mapping_and_default_are_preserved(self):
        live = {"exploit/example": {"options": [],
            "target_details": [{"index": 0, "name": "Automatic"},
                               {"index": 1, "name": "Linux"}],
            "default_target_index": 0}}
        result = discover_cve("CVE-2099-0102", "msf", make_backend(
            cache={"present": True},
            cached_candidates={"exploit/example": {"targets": ["Automatic", "Linux"]}},
            live_data=live))
        candidate = result.candidates[0]
        self.assertEqual([(x.index, x.name) for x in candidate.target_details],
                         [(0, "Automatic"), (1, "Linux")])
        self.assertEqual(candidate.default_target_index, 0)
    def test_multiple_candidates_are_preserved_without_selection(self):
        cached = {
            "exploit/a": {"rank": "excellent", "references": ["CVE-2099-0001"]},
            "exploit/b": {"rank": "good", "references": ["CVE-2099-0001"]},
        }
        live = {
            "exploit/a": {"options": []},
            "exploit/b": {"options": []},
        }
        result = discover_cve(
            "CVE-2099-0001", "msf", make_backend(
                cache={"present": True}, cached_candidates=cached, live_data=live,
            ),
        )

        self.assertEqual(result.status, DiscoveryStatus.FOUND)
        self.assertEqual([item.module_path for item in result.candidates], ["exploit/a", "exploit/b"])
        self.assertNotIn("selected_module", result.to_dict())

    def test_genuine_no_module_is_distinct(self):
        result = discover_cve(
            "CVE-2099-0002", "msf", make_backend(cache={"present": True}),
        )

        self.assertEqual(result.status, DiscoveryStatus.NO_MSF_MODULE)
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.errors, ())

    def test_query_failure_is_environment_error(self):
        result = discover_cve(
            "CVE-2099-0003", "msf", make_backend(
                cache={"present": True},
                cached_candidates={"exploit/a": {"rank": "normal"}},
                query_error="msfconsole unavailable",
            ),
        )

        self.assertEqual(result.status, DiscoveryStatus.ENVIRONMENT_ERROR)
        self.assertNotEqual(result.status, DiscoveryStatus.NO_MSF_MODULE)
        self.assertIn("msfconsole unavailable", result.errors[0])

    def test_serialization_preserves_module_metadata(self):
        cached = {"exploit/example": {
            "rank": "great",
            "disclosure_date": "2099-01-02",
            "platform": ["Linux"],
            "targets": ["Automatic", "Unix Command"],
            "check_supported": True,
            "references": ["CVE-2099-0004", "URL-https://example.invalid"],
        }}
        live = {"exploit/example": {"options": [
            {"name": "RHOSTS", "type": "address_range", "required": True, "default": None},
            {"name": "RPORT", "type": "port", "required": True, "default": 8080},
        ]}}
        result = discover_cve(
            "CVE-2099-0004", "msf", make_backend(
                cache={"present": True}, cached_candidates=cached, live_data=live,
            ),
        )
        serialized = result.to_dict()
        candidate = serialized["candidates"][0]

        self.assertEqual(candidate["module_path"], "exploit/example")
        self.assertEqual(candidate["rank"], "great")
        self.assertEqual(candidate["platform"], ["Linux"])
        self.assertEqual(candidate["targets"], ["Automatic", "Unix Command"])
        self.assertTrue(candidate["check_supported"])
        self.assertEqual(candidate["references"], ["CVE-2099-0004", "URL-https://example.invalid"])
        self.assertEqual(candidate["options"][0], {
            "name": "RHOSTS", "type": "address_range", "required": True, "default": None,
        })
        self.assertEqual(candidate["options"][1]["default"], 8080)
        self.assertEqual(candidate["discovery_source"], "metadata_cache")
        self.assertEqual(candidate["metadata_source"], ["test-cache.json", "live_msfconsole"])
        json.dumps(serialized, sort_keys=True)

    def test_target_facts_preserve_multiple_structured_ports(self):
        facts = TargetFacts(
            run_id="aB3x9",
            ip_address="172.18.0.3",
            observed_ports=(
                ObservedPort(8080, service="http"),
                ObservedPort(9200, service="elasticsearch"),
            ),
            published_ports=(
                PublishedPort(container_port=8080, host_port=18080),
                PublishedPort(container_port=9200, host_port=19200),
            ),
            msf_container="msf-resolver-host",
        )
        serialized = facts.to_dict()

        self.assertEqual([item["port"] for item in serialized["observed_ports"]], [8080, 9200])
        self.assertEqual(
            [item["host_port"] for item in serialized["published_ports"]],
            [18080, 19200],
        )
        self.assertNotIn("target_port", serialized)


if __name__ == "__main__":
    unittest.main()
