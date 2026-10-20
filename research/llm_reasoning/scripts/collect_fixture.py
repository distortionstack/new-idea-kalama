"""Read-only source-observation manifest; no target, patch, or model action."""
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCES=(ROOT.parents[1]/"remediation_review_rvcdv"/"Dockerfile",ROOT.parents[1]/"remediation_review_rvcdv"/"README.md")
if __name__ == "__main__":
 print(json.dumps({str(p.relative_to(ROOT.parents[1])):hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES},sort_keys=True))
