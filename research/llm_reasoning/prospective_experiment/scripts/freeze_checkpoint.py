"""Copy and hash a prospective checkpoint; never read historical answers."""
import argparse, hashlib, json, shutil
from datetime import datetime, timezone
from pathlib import Path

DENYLIST = ("patch_form_lkW2d_r2", "patch_result_2026-09-08_lkW2d_attempt_2", "session-log-2026-09-09")
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def freeze(destination, run_id, label, revision, container_id, sources):
    destination = Path(destination); evidence = destination / "frozen_evidence"
    destination.mkdir(parents=True, exist_ok=False); evidence.mkdir()
    records=[]
    for raw in sources:
        source=Path(raw)
        if any(x in str(source).replace('\\','/') for x in DENYLIST): raise ValueError("historical-answer denylist: " + str(source))
        target=evidence/source.name
        shutil.copy2(source, target)
        records.append({"id":"E%03d"%(len(records)+1),"source_path":str(source),"frozen_path":str(target),"sha256":sha(target)})
    manifest={"label":label,"captured_at":datetime.now(timezone.utc).isoformat(),"run_id":run_id,"revision":revision,"container_id":container_id,"evidence":records}
    (destination/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    return manifest
def main():
    p=argparse.ArgumentParser(); p.add_argument("destination"); p.add_argument("--run-id",required=True); p.add_argument("--label",required=True); p.add_argument("--revision",required=True); p.add_argument("--container-id",required=True); p.add_argument("sources",nargs='+'); a=p.parse_args()
    print(json.dumps(freeze(a.destination,a.run_id,a.label,a.revision,a.container_id,a.sources),indent=2))
if __name__=="__main__": main()
