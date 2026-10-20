import json
from pathlib import Path
import yaml
from kalama.resolution.config_codec import exploit_config_from_dict
from kalama.resolution.submission import apply_human_confirmation
from kalama.execution.executor import build_execution_plan

root = Path.cwd()
state_path = root / "output" / "live-cve-2015-1427-utf8-validation-2" / "state" / "run_93AF1.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
form_path = Path(state["artifacts"]["ATTACK_FORM"]["path"])
resolver_path = Path(state["artifacts"]["RESOLVER_BEFORE"]["path"])
form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
resolver = json.loads(resolver_path.read_text(encoding="utf-8"))
cve_id = "CVE-2015-1427"
entry = next(item for item in resolver["cves"] if item["cve_id"] == cve_id)
submission = json.loads(json.dumps(form))
cve = submission["cves"][cve_id]

def confirm_value(field, value=None):
    if value is None:
        value = field.get("suggested")
    field["confirmed"] = value
    return value

confirm_value(cve["target"]["index"], 0)
confirm_value(cve["target"]["name"], "ElasticSearch 1.4.2")
confirm_value(cve["targeturi"], "/")
for name in [
    "KrbCacheMode",
    "HTTP::Auth",
    "KrbClockSkew",
    "HTTP::KrbOfferedEncryptionTypes",
    "SSLVersion",
    "DOMAIN",
]:
    confirm_value(cve["module_options"][name])
confirm_value(cve["environment"]["rport"], 9200)
# LHOST is not required or used in check-only mode. Leave it as a suggestion.
protocol = cve["execution_protocol"]
protocol["mode"] = "check-only"
protocol["run_check"] = True
protocol["run_exploit"] = False
protocol["session_confirmation_expected"] = False
protocol["confirmed"] = True
protocol["confirmation_status"] = "SUGGESTED"
# Ground-truth lab note: create one document and refresh before MSF check().
cve["preconditions"] = {
    "description": (
        "Ensure Elasticsearch has at least one document before Metasploit check(); "
        "the CVE-2015-1427 lab note records an empty-index false-negative risk."
    ),
    "commands": [
        "curl -fsS -XPOST -H 'Content-Type: application/json' 'http://172.18.0.6:9200/kalama/doc/1' -d '{\"field\":\"value\"}'",
        "curl -fsS -XPOST 'http://172.18.0.6:9200/kalama/_refresh'",
    ],
    "execution_target": "kalama-workbench",
    "required": True,
    "confirmation_status": "HUMAN_CONFIRMED",
}
# Keep check-only. Do not select payload or payload options.
out_path = root / "review-bundles" / "93AF1-attack-form-submission-prep" / "attack_form_93AF1_r1_submission_check_only_precondition.yaml"
out_path.write_text(yaml.safe_dump(submission, sort_keys=False, allow_unicode=True), encoding="utf-8")

base_config = exploit_config_from_dict(entry["exploit_config"])
applied = apply_human_confirmation(base_config, submission["cves"][cve_id])
plan = build_execution_plan(applied.config, entry["rank"]) if applied.validation.ready else None
changed = []
orig = form["cves"][cve_id]
new = submission["cves"][cve_id]
for dotted in [
    "target.index.confirmed", "target.name.confirmed", "targeturi.confirmed",
    "module_options.KrbCacheMode.confirmed", "module_options.HTTP::Auth.confirmed",
    "module_options.KrbClockSkew.confirmed",
    "module_options.HTTP::KrbOfferedEncryptionTypes.confirmed",
    "module_options.SSLVersion.confirmed", "module_options.DOMAIN.confirmed",
    "environment.rport.confirmed", "execution_protocol.confirmed",
    "execution_protocol.mode", "execution_protocol.run_check", "execution_protocol.run_exploit",
    "preconditions.description", "preconditions.commands", "preconditions.execution_target",
    "preconditions.required", "preconditions.confirmation_status",
]:
    def get(obj, path):
        cur = obj
        for part in path.split('.'):
            cur = cur[part]
        return cur
    oldv = get(orig, dotted)
    newv = get(new, dotted)
    if oldv != newv:
        changed.append({"field": dotted, "from": oldv, "to": newv})
summary = {
    "state_path": str(state_path),
    "form_path": str(form_path),
    "resolver_path": str(resolver_path),
    "submission_path": str(out_path),
    "target": state["target"]["facts"],
    "validation_ready": applied.validation.ready,
    "validation_readiness": applied.validation.readiness.value,
    "validation_issues": [issue.to_dict() for issue in applied.validation.issues],
    "plan": None if plan is None else plan.__dict__,
    "changed_fields": changed,
    "submitted_precondition_required_persisted_by_current_code": applied.config.invariant.preconditions.required,
}
summary_path = root / "review-bundles" / "93AF1-attack-form-submission-prep" / "summary.json"
summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True, default=str))
