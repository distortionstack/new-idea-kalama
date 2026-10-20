import unittest
from kalama.evaluation.llm_reasoning_benchmark import (
    Benchmark, Classification, Evidence, ablate, direct_answer_sources,
    has_two_necessary, is_deterministic_rule, ready, serialize_prompt,
)


class ReasoningBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.evidence = (Evidence("e1", "runtime", "fixture:a", {"observation": "alpha"}),
                         Evidence("e2", "module_doc", "fixture:b", {"semantic": "beta"}))
        self.benchmark = Benchmark("b", "attack", "targeturi", Classification.SEMANTIC_INTERPRETATION,
            {"status": "UNRESOLVED"}, {"status": "MISS"}, {"value": "gamma", "provenance": "hidden"},
            self.evidence, {"e1": "necessary", "e2": "necessary"}, {"type": "string"})

    def test_schema_enum_and_gap_representation(self):
        self.assertEqual(self.benchmark.resolver_gap_proof["status"], "UNRESOLVED")
        self.assertEqual(self.benchmark.knowledge_miss_proof["status"], "MISS")
        self.assertTrue(ready(self.benchmark))

    def test_truth_never_enters_prompt(self):
        prompt = serialize_prompt(self.benchmark)
        self.assertNotIn("gamma", prompt)
        self.assertNotIn("hidden", prompt)

    def test_necessity_direct_answer_and_deterministic_classification(self):
        self.assertTrue(has_two_necessary(self.benchmark.evidence_necessity))
        self.assertEqual(direct_answer_sources("alpha", self.evidence), ("e1",))
        self.assertTrue(is_deterministic_rule({"set_intersection": True}))

    def test_ablation_is_precise_and_nonzero(self):
        remaining = ablate(self.benchmark, "e1")
        self.assertEqual([x.id for x in remaining], ["e2"])
        with self.assertRaises(ValueError):
            ablate(Benchmark("one", "attack", "targeturi", Classification.COPY, {}, {}, {"value": "x"},
                            (self.evidence[0],), {}, {}), "e1")

    def test_structured_copy_detection_and_provenance(self):
        e = (Evidence("target", "msf", "real:metadata", {"target": {"index": 0, "name": "Universal"}}),)
        self.assertEqual(direct_answer_sources({"index": 0, "name": "Universal"}, e), ("target",))
        self.assertEqual(e[0].provenance, "real:metadata")
