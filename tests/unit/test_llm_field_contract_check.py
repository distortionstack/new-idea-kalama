"""Task 7.5 offline tests: typed target parser, prompts, conformance.

No Ollama, network, Docker, or live model.
"""

import json
import unittest

from kalama.evaluation.llm_field_contract_check import (
    ABSTAIN_FORMAT,
    TARGET_TYPED_FORMAT,
    build_abstention_prompt,
    build_typed_target_prompt,
    parse_typed_target,
    production_conformance,
)


class TypedTargetParserTests(unittest.TestCase):
    def test_object_value_accepted(self):
        parsed, ok, _ = parse_typed_target(
            '{"value": {"index": 0, "name": "Universal"}, "evidence_refs": ["m"]}')
        self.assertTrue(ok)
        self.assertEqual(parsed["value"], {"index": 0, "name": "Universal"})

    def test_index_only_accepted(self):
        parsed, ok, _ = parse_typed_target(
            '{"value": {"index": 0}, "evidence_refs": ["m"]}')
        self.assertTrue(ok)
        self.assertEqual(parsed["value"], {"index": 0})

    def test_bare_string_rejected(self):
        # The exact Task 7.4 failure mode must not parse as typed target.
        _, ok, issues = parse_typed_target(
            '{"value": "component: pkg:maven/x", "evidence_refs": ["m"]}')
        self.assertFalse(ok)
        self.assertTrue(any("object" in i for i in issues))

    def test_missing_index_rejected(self):
        _, ok, _ = parse_typed_target(
            '{"value": {"name": "Universal"}, "evidence_refs": ["m"]}')
        self.assertFalse(ok)

    def test_bool_index_rejected(self):
        _, ok, _ = parse_typed_target(
            '{"value": {"index": true}, "evidence_refs": ["m"]}')
        self.assertFalse(ok)

    def test_extra_key_rejected(self):
        _, ok, _ = parse_typed_target(
            '{"value": {"index": 0, "foo": 1}, "evidence_refs": ["m"]}')
        self.assertFalse(ok)

    def test_null_with_refs_rejected(self):
        _, ok, _ = parse_typed_target(
            '{"value": null, "evidence_refs": ["m"]}')
        self.assertFalse(ok)

    def test_null_abstention_accepted(self):
        parsed, ok, _ = parse_typed_target('{"value": null, "evidence_refs": []}')
        self.assertTrue(ok)
        self.assertIsNone(parsed["value"])


class PromptTests(unittest.TestCase):
    def test_typed_prompt_no_expected_leak(self):
        prompt, spec = build_typed_target_prompt()
        self.assertNotIn("expected_value", prompt)
        self.assertNotIn("candidate_digest", prompt)
        self.assertNotIn("field_evidence_sha256", prompt)
        self.assertNotIn("index=0", prompt.replace(" ", ""))
        # Shape requirement present, answer absent.
        self.assertIn('"index"', prompt)
        self.assertEqual(list(spec.allowed_evidence_ids),
                         ["msf:exploit/multi/http/struts2_rest_xstream"])
        self.assertEqual(spec.expected_value, {"index": 0, "name": "Universal"})

    def test_abstention_prompt_has_zero_evidence(self):
        prompt, _ = build_abstention_prompt()
        self.assertIn("zero items", prompt)
        self.assertIn('"value": null', prompt)

    def test_formats_are_constrained(self):
        self.assertIn("anyOf", json.dumps(TARGET_TYPED_FORMAT))
        self.assertEqual(ABSTAIN_FORMAT["properties"]["value"], {"type": "null"})


class ConformanceTests(unittest.TestCase):
    def test_correct_target_passes_unmodified_validator(self):
        result = production_conformance({"index": 0, "name": "Universal"},
                                        ["msf:exploit/multi/http/struts2_rest_xstream"])
        self.assertEqual(result["validation_state"], "ACCEPTED_AS_SUGGESTION")
        self.assertIn("target", result["accepted"])

    def test_string_target_rejected_by_unmodified_validator(self):
        result = production_conformance(
            "component: pkg:maven/org.apache.struts/struts2-core@2.5.12",
            ["msf:exploit/multi/http/struts2_rest_xstream"])
        self.assertEqual(result["validation_state"], "REJECTED")

    def test_fabricated_ref_rejected(self):
        result = production_conformance({"index": 0, "name": "Universal"},
                                        ["evidence:does-not-exist"])
        self.assertEqual(result["validation_state"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
