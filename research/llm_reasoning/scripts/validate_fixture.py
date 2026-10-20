"""Deterministic qualification gate; it does not invoke a model."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(rel): return json.loads((ROOT/rel).read_text(encoding="utf-8"))
def check(kind):
 f=read(f"fixtures/patch_strategy/{kind}/fixture.json"); m=read(f"fixtures/patch_strategy/{kind}/model_evidence.json")
 assert f["field"]=="strategy" and len(m["evidence"])>=2
 assert f["classification"]=="DETERMINISTIC_RULE"
 assert all("expected" not in x and "gold" not in x for x in m["evidence"])
 return f
if __name__=="__main__": print(json.dumps({k:check(k)["qualification"] for k in ("original","counterfactual")}))
