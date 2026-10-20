import json
from pathlib import Path
import yaml
root = Path(r"C:\\Users\\distortion\\Documents\\new-idea-kalama\\review-bundles\\YKdop-step4-review-20260908")
state = json.loads((root / "run_YKdop.json").read_bytes())
resolver_ref = state["artifacts"].get("RESOLVER_BEFORE")
form_ref = state["artifacts"].get("ATTACK_FORM")
resolver = json.loads(Path(resolver_ref["path"]).read_bytes()) if resolver_ref else None
form = yaml.safe_load(Path(form_ref["path"]).read_bytes()) if form_ref else None
cve = None
if resolver:
    cve = next((item for item in resolver.get("cves", []) if item.get("cve_id") == "CVE-2015-1427"), None)
form_cve = None
if form:
    form_cve = (form.get("cves") or {}).get("CVE-2015-1427")
config = (cve or {}).get("exploit_config") or {}
inv = config.get("invariant") or {}
env = config.get("environment") or {}
validation = (cve or {}).get("validation") or {}
summary = {
    "state": {
        "status": state.get("status"),
        "current_stage": state.get("current_stage"),
        "waiting_reason": state.get("waiting_reason"),
        "step4_resolver_status": state.get("stages", {}).get("STEP_4_RESOLVER", {}).get("status"),
        "updated_at": state.get("updated_at"),
    },
    "artifacts": {k: state.get("artifacts", {}).get(k) for k in ("RESOLVER_BEFORE", "ATTACK_FORM", "TOP30_BEFORE", "TRIVY_BEFORE")},
    "resolver_summary": resolver.get("summary") if resolver else None,
    "cve_2015_1427": {
        "status": (cve or {}).get("status"),
        "rank": (cve or {}).get("rank"),
        "module": (((inv.get("module_selection") or {}).get("module") or {}).get("suggested_value") or ((inv.get("module_selection") or {}).get("module") or {}).get("value")),
        "module_confirmation": ((inv.get("module_selection") or {}).get("module") or {}).get("confirmation_status"),
        "target_ip": env.get("ip_address"),
        "rhosts": (env.get("rhosts") or {}).get("value"),
        "rport_suggested": (env.get("rport") or {}).get("suggested_value"),
        "rport_confirmed": (env.get("rport") or {}).get("value"),
        "lhost_suggested": (env.get("lhost") or {}).get("suggested_value"),
        "target_index_suggested": (((inv.get("target_selection") or {}).get("target_index") or {}).get("suggested_value")),
        "target_name_suggested": (((inv.get("target_selection") or {}).get("target_name") or {}).get("suggested_value")),
        "targeturi_suggested": (inv.get("targeturi") or {}).get("suggested_value"),
        "payload_required": (((inv.get("payload") or {}).get("payload") or {}).get("required")),
        "payload_suggested": (((inv.get("payload") or {}).get("payload") or {}).get("suggested_value")),
        "compatible_payloads": (inv.get("payload") or {}).get("compatible_payloads"),
        "payload_options": (inv.get("payload") or {}).get("options"),
        "execution_protocol": inv.get("execution_protocol"),
        "validation": validation,
        "form_input_reasons": (form_cve or {}).get("input_reasons"),
    },
    "environment_error_sample": [
        {"rank": item.get("rank"), "cve_id": item.get("cve_id"), "errors": item.get("errors")}
        for item in (resolver.get("cves", []) if resolver else []) if item.get("status") == "ENVIRONMENT_ERROR"
    ][:10],
}
(root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
