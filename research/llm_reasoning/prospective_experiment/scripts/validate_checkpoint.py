"""Verify frozen bytes, bindings, and denylist exclusion."""
import hashlib,json,sys
from pathlib import Path
DENYLIST = ("patch_form_lkW2d_r2", "patch_result_2026-09-08_lkW2d_attempt_2", "session-log-2026-09-09")
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def validate(root):
    m=json.loads((Path(root)/"manifest.json").read_text()); assert m["run_id"] and m["revision"] and m["container_id"]
    for e in m["evidence"]:
        assert not any(x in e["source_path"].replace('\\','/') for x in DENYLIST)
        assert digest(e["frozen_path"])==e["sha256"]
    return {"valid":True,"evidence_count":len(m["evidence"])}
if __name__=="__main__": print(json.dumps(validate(sys.argv[1])))
