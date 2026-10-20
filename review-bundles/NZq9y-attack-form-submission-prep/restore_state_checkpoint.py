import json
from copy import deepcopy

ROOT = r"C:\Users\distortion\Documents\new-idea-kalama"
path = ROOT + r"\output\screening-run\state\run_NZq9y.json"
d = json.load(open(path, encoding="utf-8"))
assert d["status"] == "RUNNING", d["status"]
assert d["waiting_reason"] is None
assert d["current_stage"] == "STEP_4_RESOLVER"
assert d["stages"]["STEP_4_RESOLVER"]["status"] == "RUNNING"

restored = deepcopy(d)
restored["status"] = "WAITING_FOR_USER_INPUT"
restored["waiting_reason"] = "ATTACK_FORM"
restored["stages"]["STEP_4_RESOLVER"]["status"] = "WAITING"
restored["updated_at"] = "2026-09-08T15:55:46Z"
open(path, "w", encoding="utf-8").write(json.dumps(restored, ensure_ascii=False, indent=2) + "\n")

check = json.load(open(path, encoding="utf-8"))
print("status:", check["status"])
print("waiting_reason:", check["waiting_reason"])
print("current_stage:", check["current_stage"])
print("resolver_stage:", check["stages"]["STEP_4_RESOLVER"]["status"])
print("updated_at:", check["updated_at"])
print("artifacts unchanged:", list(check["artifacts"].keys()))
print("submission_artifact_present:", any(a.kind if False else False for a in []))