"""Evaluator-only boundary; may read ground_truth after a future admitted run."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
def ground_truth_root(): return ROOT / "ground_truth"
