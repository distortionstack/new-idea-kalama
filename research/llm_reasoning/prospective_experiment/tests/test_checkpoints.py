import importlib.util, json, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; S=ROOT/'scripts'
def load(name):
 s=importlib.util.spec_from_file_location(name,S/(name+'.py')); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
F=load('freeze_checkpoint'); V=load('validate_checkpoint')
class Checkpoints(unittest.TestCase):
 def test_freeze_and_verify(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); source=p/'raw.log'; source.write_text('raw runtime output')
   target=p/'checkpoint'; F.freeze(target,'NEWID','ATTEMPT_1_OBSERVATION','1','container123',[source])
   self.assertTrue(V.validate(target)['valid'])
 def test_denylist(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); bad=p/'patch_form_lkW2d_r2.yaml'; bad.write_text('x')
   with self.assertRaises(ValueError): F.freeze(p/'checkpoint','NEW','PRE_PATCH','1','container',[bad])
 def test_immutability_hash(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); source=p/'raw.log'; source.write_text('a'); target=p/'checkpoint'; F.freeze(target,'NEW','PRE_PATCH','1','container',[source])
   frozen=next((target/'frozen_evidence').iterdir()); frozen.write_text('changed')
   with self.assertRaises(AssertionError): V.validate(target)
if __name__=='__main__': unittest.main()
