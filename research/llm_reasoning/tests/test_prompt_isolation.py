import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"scripts"))
from serialize_prompt import serialize
class PromptIsolationTests(unittest.TestCase):
 def test_truth_isolation_and_schema(self):
  prompt,_=serialize(ROOT/"fixtures/patch_strategy/original/model_evidence.json")
  truth=json.loads((ROOT/"ground_truth/original/truth.json").read_text())
  self.assertNotIn(truth["value"],prompt); self.assertNotIn("ground_truth",prompt)
  self.assertNotIn("expected",prompt); self.assertNotIn("gold",prompt)
 def test_hash_stable(self):
  p=ROOT/"fixtures/patch_strategy/original/model_evidence.json"
  self.assertEqual(serialize(p)[1],serialize(p)[1])
