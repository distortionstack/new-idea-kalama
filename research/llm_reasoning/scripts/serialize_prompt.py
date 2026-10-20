"""Serialize model evidence only; deliberately no ground-truth path exists."""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def serialize(path: Path, ids=None):
    data=json.loads(path.read_text(encoding="utf-8")); evidence=data["evidence"]
    if ids is not None: evidence=[x for x in evidence if x["id"] in ids]
    out=json.dumps({"field":data["field"],"evidence":evidence,
                    "output_contract":{"value":"PatchStrategy enum or null","evidence_refs":"string array"}},sort_keys=True,separators=(",",":"))
    return out, hashlib.sha256(out.encode()).hexdigest()

if __name__ == "__main__":
    import sys
    text,digest=serialize(Path(sys.argv[1]))
    print(json.dumps({"prompt":text,"sha256":digest}))
