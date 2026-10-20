"""Task 7.4 offline tests: parser, evidence refs, binding harness, prompts.

No Ollama, network, Docker, or live model.  Fake content only.
"""

import unittest

from kalama.evaluation.llm_field_decomp import (
    ALLOWED_DIAG_KEYS,
    attach_response,
    binding_store,
    build_field_prompt,
    build_field_specs,
    check_cross_field,
    diagnostic_request_id,
    has_forbidden_expansion,
    parse_field_response,
    refs_supported,
    values_equal,
)


class ParserTests(unittest.TestCase):
    def test_exact_keys_accepted(self):
        parsed, ok, _ = parse_field_response('{"value": "2.5.13", "evidence_refs": ["a"]}')
        self.assertTrue(ok)
        self.assertEqual(set(parsed.keys()), set(ALLOWED_DIAG_KEYS))

    def test_extra_key_rejected(self):
        _, ok, issues = parse_field_response(
            '{"value": "x", "evidence_refs": [], "reasoning_summary": "y"}')
        self.assertFalse(ok)
        self.assertTrue(any("keys_must_be" in i for i in issues))

    def test_missing_key_rejected(self):
        _, ok, _ = parse_field_response('{"value": "x"}')
        self.assertFalse(ok)

    def test_non_json_rejected(self):
        _, ok, _ = parse_field_response('not json')
        self.assertFalse(ok)

    def test_null_abstention_shape(self):
        parsed, ok, _ = parse_field_response('{"value": null, "evidence_refs": []}')
        self.assertTrue(ok)
        self.assertIsNone(parsed["value"])

    def test_object_value_allowed_for_target(self):
        parsed, ok, _ = parse_field_response(
            '{"value": {"index": 0, "name": "Universal"}, "evidence_refs": ["m"]}')
        self.assertTrue(ok)
        self.assertTrue(values_equal(parsed["value"], {"index": 0, "name": "Universal"}))


class EvidenceRefTests(unittest.TestCase):
    def test_subset_ok(self):
        self.assertTrue(refs_supported(["a"], ["a", "b"]))
        self.assertFalse(refs_supported(["zz"], ["a", "b"]))

    def test_no_expected_leak_in_prompt(self):
        # Prompts must not contain evaluator expectation markers.
        for spec in build_field_specs():
            prompt = build_field_prompt(spec)
            self.assertNotIn("expected_value", prompt)
            self.assertNotIn("candidate_digest", prompt)
            self.assertNotIn("field_evidence_sha256", prompt)
            # Forbidden protocol outputs are never requested.
            self.assertNotIn("candidate_digest", prompt)
            self.assertNotIn("action_id", prompt)

    def test_field_specs_cover_only_requested(self):
        specs = build_field_specs()
        by_case: dict[str, list[str]] = {}
        for s in specs:
            by_case.setdefault(s.case_id, []).append(s.field)
        self.assertEqual(sorted(by_case["B"]), ["payload", "target", "targeturi"])
        self.assertEqual(by_case["F"], ["target_version"])
        # Evidence IDs preserved from fixtures.
        ids_b = {tuple(s.allowed_evidence_ids) for s in specs if s.case_id == "B"}
        self.assertIn(("msf:exploit/multi/http/struts2_rest_xstream",), ids_b)
        self.assertIn(("msf:option:TARGETURI",), ids_b)
        self.assertIn(("knowledge.record.11",),
                      {tuple(s.allowed_evidence_ids) for s in specs if s.case_id == "F"})
        # rport must never be a diagnostic field (protected in B).
        self.assertNotIn("rport", [s.field for s in specs])

    def test_forbidden_expansion_detector(self):
        self.assertTrue(has_forbidden_expansion('{"candidate_digest": "abc"}'))
        self.assertFalse(has_forbidden_expansion('{"value": "x", "evidence_refs": []}'))


class BindingHarnessTests(unittest.TestCase):
    def test_valid_attach(self):
        specs = build_field_specs()
        store = binding_store(specs)
        rid = diagnostic_request_id(specs[0].candidate_digest, specs[0].field,
                                    specs[0].field_evidence_sha256)
        parsed = {"value": "v", "evidence_refs": list(specs[0].allowed_evidence_ids)}
        env, msg = attach_response(store, rid, parsed)
        self.assertIsNotNone(env)
        self.assertEqual(env["candidate_digest"], specs[0].candidate_digest)
        self.assertEqual(env["field_name"], specs[0].field)
        self.assertEqual(msg, "accept")

    def test_wrong_request_rejected(self):
        specs = build_field_specs()
        store = binding_store(specs)
        env, _ = attach_response(store, "R-does-not-exist",
                                 {"value": "v", "evidence_refs": []})
        self.assertIsNone(env)

    def test_unknown_ref_rejected(self):
        specs = build_field_specs()
        store = binding_store(specs)
        rid = diagnostic_request_id(specs[0].candidate_digest, specs[0].field,
                                    specs[0].field_evidence_sha256)
        env, msg = attach_response(store, rid,
                                   {"value": "v", "evidence_refs": ["nope"]})
        self.assertIsNone(env)
        self.assertIn("not in request set", msg)

    def test_cross_field_rejected(self):
        specs = build_field_specs()
        store = binding_store(specs)
        rid = diagnostic_request_id(specs[0].candidate_digest, specs[0].field,
                                    specs[0].field_evidence_sha256)
        ok, _ = check_cross_field(store, rid,
                                  {"value": "v", "evidence_refs": []},
                                  claimed_field="__other__")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
