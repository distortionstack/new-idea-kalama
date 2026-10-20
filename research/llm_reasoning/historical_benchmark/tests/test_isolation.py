import json, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

class IsolationTests(unittest.TestCase):
    def test_rejected_case_has_no_model_visible_evidence_pack(self):
        m = json.loads((ROOT / "cases/lkW2d_r2_runtime_revision/manifest.json").read_text())
        self.assertEqual(m["status"], "REJECTED")
        self.assertFalse((ROOT / "cases/lkW2d_r2_runtime_revision/evidence").exists())
    def test_validator_does_not_reference_ground_truth(self):
        self.assertNotIn("ground_truth", (SCRIPTS / "validate_cases.py").read_text())
    def test_runner_does_not_reference_ground_truth(self):
        self.assertNotIn("ground_truth", (SCRIPTS / "run_benchmark.py").read_text())
    def test_static_validation_and_runner_guard(self):
        check = subprocess.run([sys.executable, str(SCRIPTS / "validate_cases.py")], capture_output=True, text=True, check=True)
        run = subprocess.run([sys.executable, str(SCRIPTS / "run_benchmark.py")], capture_output=True, text=True, check=True)
        self.assertIn('"admitted": 0', check.stdout)
        self.assertIn("NO_MODEL_CALL", run.stdout)

if __name__ == "__main__": unittest.main()
