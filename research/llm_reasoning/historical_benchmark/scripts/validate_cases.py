"""Static admission/isolation validation; intentionally reads no ground truth."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("patch_form_lkW2d_r2", "patch_result_2026-09-08_lkW2d_attempt_2", "session-log-2026-09-09")

def main():
    manifests = list((ROOT / "cases").glob("*/manifest.json"))
    assert manifests, "no manifests"
    for path in manifests:
        item = json.loads(path.read_text(encoding="utf-8"))
        assert item["status"] == "REJECTED"
        assert item["observation_time"] == "NOT_RECORDED"
        assert not (ROOT / "cases" / path.parent.name / "evidence").exists()
        assert all(any(token in x for x in item["forbidden_post_revision_evidence"]) for token in FORBIDDEN)
    print(json.dumps({"valid": True, "admitted": 0, "model_calls_permitted": 0}))

if __name__ == "__main__": main()
