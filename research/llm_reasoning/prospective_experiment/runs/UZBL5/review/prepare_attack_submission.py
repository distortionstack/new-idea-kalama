from __future__ import annotations

from pathlib import Path

import yaml


RUN_ID = "UZBL5"
ROOT = Path("output/2d8ru-struts2-evidence-anchored-755")
SOURCE = ROOT / "resolver/forms/attack_form_UZBL5_r1.yaml"
DESTINATION = Path(
    "research/llm_reasoning/prospective_experiment/runs/UZBL5/review/"
    "attack_form_UZBL5_r1_reviewed.yaml"
)

SELECTED = {
    "CVE-2017-5638": "/S2-045/",
    "CVE-2017-9805": "/S2-052/orders/3",
}


def confirm(field: dict) -> None:
    value = field.get("suggested")
    if value is None:
        value = field.get("default")
    if value is not None:
        field["confirmed"] = value


form = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
if form.get("run_id") != RUN_ID or form.get("revision") != 1:
    raise SystemExit("unexpected Attack Form identity")

for cve_id, cve in form["cves"].items():
    if cve_id not in SELECTED:
        cve["decision"]["confirmed"] = "skip"
        cve["decision"]["reason"] = (
            "Fresh UZBL5 scanner/runtime evidence did not establish a "
            "CVE-specific reachable endpoint and applicable module binding; "
            "abstain rather than infer."
        )
        continue

    confirm(cve["module"])
    confirm(cve["target"]["index"])
    confirm(cve["target"]["name"])
    cve["targeturi"]["confirmed"] = SELECTED[cve_id]
    cve["environment"]["rport"]["confirmed"] = 8080
    cve["environment"]["lhost"]["confirmed"] = "172.18.0.2"
    cve["payload"]["confirmed"] = "cmd/unix/reverse_bash"
    cve["execution_protocol"]["mode"] = "check-then-exploit"
    cve["execution_protocol"]["confirmed"] = True

    for option in cve.get("module_options", {}).values():
        if option.get("required"):
            confirm(option)

DESTINATION.parent.mkdir(parents=True, exist_ok=True)
DESTINATION.write_text(
    yaml.safe_dump(form, sort_keys=False, allow_unicode=True),
    encoding="utf-8",
)
print(DESTINATION)
