import tempfile
import unittest
from pathlib import Path

import yaml

import resolver


class ResolverSerializationTests(unittest.TestCase):
    def test_draft_requires_explicit_selection_for_multiple_candidates(self):
        result = {
            "found": True,
            "candidates": [
                {"module": "exploit/multi/http/one", "options": []},
                {"module": "exploit/multi/http/two", "options": []},
            ],
        }

        with self.assertRaisesRegex(RuntimeError, "explicit module selection is required"):
            resolver.build_draft_from_result("CVE-2099-0000", result, resolver.DEFAULT_FACTS)

        draft = resolver.build_draft_from_result(
            "CVE-2099-0000", result, resolver.DEFAULT_FACTS,
            module_path="exploit/multi/http/two",
        )
        self.assertEqual(draft["module_fullname"], "exploit/multi/http/two")

    def test_draft_preserves_candidate_check_support(self):
        result = {
            "found": True,
            "candidates": [{
                "module": "exploit/multi/http/example",
                "check_supported": True,
                "options": [],
            }],
        }
        draft = resolver.build_draft_from_result(
            "CVE-2099-0001", result, resolver.DEFAULT_FACTS
        )
        self.assertIs(draft["check_supported"], True)

    def test_resolved_yaml_preserves_batch_check_support(self):
        fields = {
            "module": {"value": "multi/http/example"},
            "RHOSTS": {"value": "{target_ip}"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = resolver.write_resolved_yaml(
                tmp, "CVE-2099-0002", "multi/http/example", True, fields
            )
            data = yaml.safe_load(Path(path).read_text())
        self.assertIs(data["check_supported"], True)


if __name__ == "__main__":
    unittest.main()
