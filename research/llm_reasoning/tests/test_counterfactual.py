import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class CounterfactualTests(unittest.TestCase):
 def test_controlled_change_and_distinct_truth(self):
  o=json.loads((ROOT/"fixtures/patch_strategy/original/fixture.json").read_text()); c=json.loads((ROOT/"fixtures/patch_strategy/counterfactual/fixture.json").read_text())
  self.assertTrue(c["controlled_synthetic"]); self.assertEqual(o["candidate_context"]["cve"],c["candidate_context"]["cve"])
  ot=json.loads((ROOT/"ground_truth/original/truth.json").read_text())["value"]; ct=json.loads((ROOT/"ground_truth/counterfactual/truth.json").read_text())["value"]
  self.assertNotEqual(ot,ct)
 def test_no_model_invocation(self):
  self.assertNotIn("ollama", "\n".join(p.read_text().lower() for p in (ROOT/"scripts").glob("*.py")))
