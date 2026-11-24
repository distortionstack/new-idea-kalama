import json
import importlib.util
from pathlib import Path
import sys
import unittest


FIXTURE = Path(__file__).with_name("task5-fixtures") / "provider-results.json"
BENCHMARK_PATH = Path(__file__).with_name("task5_benchmark.py")
SPEC = importlib.util.spec_from_file_location("task5_benchmark", BENCHMARK_PATH)
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class Task5FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = json.loads(FIXTURE.read_text())

    def test_all_fixture_results_are_structured(self):
        for case in self.results:
            provider = case.get("registries") or case.get("id2url")
            self.assertIn(provider["status"], {"FOUND", "NOT_FOUND", "UNSUPPORTED", "PROVIDER_ERROR"})
            self.assertIsInstance(provider.get("errors", []), list)

    def test_nonexistent_versions_are_not_found_not_verified_urls(self):
        negatives = [item for item in self.results if item["case"] == "nonexistent-version"]
        self.assertEqual(2, len(negatives))
        for item in negatives:
            provider = item.get("registries") or item.get("id2url")
            self.assertEqual("NOT_FOUND", provider["status"])
            self.assertNotIn("artifact_url", provider)
            self.assertEqual([], provider.get("artifacts", []))

    def test_source_archives_are_not_claimed_as_buildable_trees(self):
        for item in self.results:
            provider = item.get("id2url")
            if provider and provider.get("artifact_kind") == "SOURCE_ARCHIVE":
                self.assertFalse(provider["buildable_source_tree"])

    def test_fixtures_contain_no_credentials_or_authorization_headers(self):
        serialized = FIXTURE.read_text().lower()
        for sentinel in ("authorization", "bearer ", "password=", "token=", "credential="):
            self.assertNotIn(sentinel, serialized)

    def test_malformed_and_unsupported_cases_are_preserved(self):
        statuses = {item["case"]: (item.get("registries") or item.get("id2url"))["status"] for item in self.results if item["case"] in {"unsupported", "malformed"}}
        self.assertEqual("UNSUPPORTED", statuses["unsupported"])
        self.assertEqual("PROVIDER_ERROR", statuses["malformed"])

    def test_runner_bounds_time_and_output_and_rejects_malformed_json(self):
        timed_out = BENCHMARK._run([sys.executable, "-c", "import time; time.sleep(1)"], timeout=0.01)
        malformed = BENCHMARK._run([sys.executable, "-c", "print('not-json')"])
        too_large = BENCHMARK._run([sys.executable, "-c", "print('x' * 100)"], max_output_bytes=10)
        self.assertEqual("TIMEOUT", timed_out["errors"][0]["kind"])
        self.assertEqual("MALFORMED_RESPONSE", malformed["errors"][0]["kind"])
        self.assertEqual("TOO_LARGE", too_large["errors"][0]["kind"])


if __name__ == "__main__":
    unittest.main()
