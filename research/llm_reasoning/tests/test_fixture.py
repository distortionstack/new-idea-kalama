import json, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"scripts"))
from validate_fixture import check
class FixtureTests(unittest.TestCase):
 def test_schema_enum_and_gate(self):
  self.assertEqual(check("original")["qualification"],"REJECTED_AS_DETERMINISTIC")
  self.assertIn("REBUILD",check("original")["production_field_contract"]["allowed"])
 def test_conditions_keep_evidence(self):
  p=ROOT/"fixtures/patch_strategy/original"
  for name in ("condition_ablation_a.json","condition_ablation_b.json"):
   self.assertEqual(len(json.loads((p/name).read_text())["evidence_ids"]),1)
 def test_provenance_and_necessity_audit(self):
  e=json.loads((ROOT/"fixtures/patch_strategy/original/model_evidence.json").read_text())["evidence"]
  self.assertTrue(all(x["provenance"] for x in e))
  self.assertEqual(len(e),2)
