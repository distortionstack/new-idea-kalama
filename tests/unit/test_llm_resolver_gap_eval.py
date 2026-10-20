"""Research-only Task 7.5.1 discovery safeguards; no live model."""
import unittest
from kalama.evaluation.llm_resolver_gap_eval import (
    direct_answer_present, expectation_leak_free, interpretation_success,
    necessity, no_suggestion_abstention, prompt_for, refs_exist, refs_sufficient,
    unsupported_inference,
)


class ResolverGapResearchTests(unittest.TestCase):
    def setUp(self):
        self.items = [{"id": "a", "facts": {"left": "x"}, "text": "one"},
                      {"id": "b", "facts": {"right": "y"}, "text": "two"}]

    def test_copy_detection(self):
        self.assertTrue(direct_answer_present("x", self.items))
        self.assertFalse(direct_answer_present("xy", self.items))

    def test_prompt_has_no_expectation_leak(self):
        prompt = prompt_for("payload", self.items)
        self.assertTrue(expectation_leak_free(prompt, "xy"))
        self.assertFalse(expectation_leak_free(prompt, "x"))

    def test_necessity_representation(self):
        self.assertEqual([x["removed"] for x in necessity(self.items, ["a", "b"])], ["a", "b"])

    def test_refs_and_success(self):
        self.assertTrue(refs_exist(["a"], self.items))
        self.assertFalse(refs_exist(["no"], self.items))
        self.assertTrue(refs_sufficient(["a", "b"], ["a", "b"]))
        self.assertTrue(interpretation_success(structured=True, value_correct=True, refs_ok=True,
                                                refs_are_sufficient=True, forbidden_expansion=False))

    def test_ablation_and_no_suggestion(self):
        self.assertTrue(unsupported_inference(value="gold", expected="gold", ablated=True))
        self.assertTrue(no_suggestion_abstention(None, []))
        self.assertFalse(no_suggestion_abstention(None, ["a"]))


if __name__ == "__main__":
    unittest.main()
