from __future__ import annotations

from pathlib import Path

import yaml


RUN_ID = "UZBL5"
ROOT = Path("output/2d8ru-struts2-evidence-anchored-755")
SOURCE = ROOT / "resolver/forms/attack_form_UZBL5_r2.yaml"
DESTINATION = Path(
    "research/llm_reasoning/prospective_experiment/runs/UZBL5/review/"
    "attack_form_UZBL5_r2_reviewed.yaml"
)
LPORTS = {
    "CVE-2017-5638": 4444,
    "CVE-2017-9805": 4445,
}


def confirm(field: dict) -> None:
    value = field.get("suggested")
    if value is None:
        value = field.get("default")
    if value is not None:
        field["confirmed"] = value


form = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
if form.get("run_id") != RUN_ID or form.get("revision") != 2:
    raise SystemExit("unexpected Attack Form identity")

if set(form["cves"]) != set(LPORTS):
    raise SystemExit("r2 does not contain exactly the two unresolved CVEs")

for cve_id, cve in form["cves"].items():
    for name, option in cve.get("payload_options", {}).items():
        if not option.get("required"):
            continue
        if name == "LPORT":
            option["confirmed"] = LPORTS[cve_id]
        else:
            confirm(option)

DESTINATION.write_text(
    yaml.safe_dump(form, sort_keys=False, allow_unicode=True),
    encoding="utf-8",
)
print(DESTINATION)
