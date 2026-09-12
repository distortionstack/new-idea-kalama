import json
import tempfile
import unittest
from pathlib import Path

from kalama.resolver.backend import (
    find_candidates_from_cache,
    load_json_cache,
)
from kalama.resolver.core import DiscoveryBackend, discover_cve
from kalama.resolver.models import DiscoveryStatus


def metadata(fullname="exploit/test/non_ascii"):
    return {
        "exploit_test/non_ascii": {
            "fullname": fullname,
            "rank": 600,
            "disclosure_date": "2099-01-02 00:00:00 +0000",
            "platform": "Unix",
            "targets": {"Automatic": 0},
            "check": True,
            "references": ["CVE-2099-1234", "D’aymore’s Dual GPU Miner"],
        }
    }


def write_json_bytes(path, document):
    path.write_bytes(
        (json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    )


class ResolverBackendCacheTests(unittest.TestCase):
    def test_non_ascii_utf8_cache_loads_under_cp874_incompatible_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            write_json_bytes(path, metadata())
            raw = path.read_bytes()
            self.assertRaises(UnicodeDecodeError, raw.decode, "cp874")

            cache = load_json_cache(path)

        self.assertIn("exploit_test/non_ascii", cache)
        self.assertEqual(
            cache["exploit_test/non_ascii"]["references"][1],
            "D’aymore’s Dual GPU Miner",
        )

    def test_valid_utf8_cache_supports_normal_candidate_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            write_json_bytes(path, metadata())

            backend = DiscoveryBackend(
                load_cache=lambda: load_json_cache(path),
                find_from_cache=find_candidates_from_cache,
                search_live=lambda *_: self.fail("cache hit should not search live"),
                query_modules=lambda *_: {
                    "exploit/test/non_ascii": {
                        "options": [],
                        "target_details": [{"index": 0, "name": "Automatic"}],
                        "default_target_index": 0,
                    }
                },
                cache_description=str(path),
            )
            result = discover_cve("CVE-2099-1234", "msf-resolver-host", backend)

        self.assertEqual(result.status, DiscoveryStatus.FOUND)
        self.assertEqual(result.candidates[0].module_path, "exploit/test/non_ascii")
        self.assertEqual(result.candidates[0].rank, "excellent")

    def test_invalid_utf8_cache_is_explicit_environment_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            path.write_bytes(b'{"bad": "\x99"}')

            with self.assertRaisesRegex(RuntimeError, "metadata cache decode failed"):
                load_json_cache(path)

            backend = DiscoveryBackend(
                load_cache=lambda: load_json_cache(path),
                find_from_cache=find_candidates_from_cache,
                search_live=lambda *_: (),
                query_modules=lambda *_: {},
                cache_description=str(path),
            )
            result = discover_cve("CVE-2099-1234", "msf-resolver-host", backend)

        self.assertEqual(result.status, DiscoveryStatus.ENVIRONMENT_ERROR)
        self.assertIn("metadata cache decode failed", result.errors[0])
        self.assertNotEqual(result.status, DiscoveryStatus.NO_MSF_MODULE)

    def test_malformed_json_cache_is_explicit_environment_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "metadata cache JSON parse failed"):
                load_json_cache(path)

            backend = DiscoveryBackend(
                load_cache=lambda: load_json_cache(path),
                find_from_cache=find_candidates_from_cache,
                search_live=lambda *_: (),
                query_modules=lambda *_: {},
                cache_description=str(path),
            )
            result = discover_cve("CVE-2099-1234", "msf-resolver-host", backend)

        self.assertEqual(result.status, DiscoveryStatus.ENVIRONMENT_ERROR)
        self.assertIn("metadata cache JSON parse failed", result.errors[0])
        self.assertNotEqual(result.status, DiscoveryStatus.NO_MSF_MODULE)

    def test_missing_cache_behavior_is_unchanged_and_searches_live(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            self.assertIsNone(load_json_cache(path))

            backend = DiscoveryBackend(
                load_cache=lambda: load_json_cache(path),
                find_from_cache=find_candidates_from_cache,
                search_live=lambda *_: calls.append("search") or (),
                query_modules=lambda *_: {},
                cache_description=str(path),
            )
            result = discover_cve("CVE-2099-1234", "msf-resolver-host", backend)

        self.assertEqual(calls, ["search"])
        self.assertEqual(result.status, DiscoveryStatus.NO_MSF_MODULE)

    def test_ascii_utf8_cache_keeps_current_platform_behavior(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modules_metadata.json"
            write_json_bytes(path, metadata("exploit/test/ascii"))

            cache = load_json_cache(path)
            candidates = find_candidates_from_cache(cache, "CVE-2099-1234")

        self.assertEqual(list(candidates), ["exploit/test/ascii"])


if __name__ == "__main__":
    unittest.main()
