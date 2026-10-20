"""Runner guard. It deliberately cannot read evaluator material or call a model without admission."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def admitted_manifests():
    return [p for p in (ROOT / "cases").glob("*/manifest.json")
            if json.loads(p.read_text(encoding="utf-8"))["status"] == "ADMITTED"]

def main():
    admitted = admitted_manifests()
    if not admitted:
        print(json.dumps({"status": "NO_MODEL_CALL", "reason": "no admitted temporally valid cases"}))
        return
    raise RuntimeError("Runner implementation intentionally unavailable until an admitted case and frozen evidence pack exist")

if __name__ == "__main__": main()
