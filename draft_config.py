#!/usr/bin/env python3
"""
Kalama Option Resolver test: draft config vs ground truth (no execution).

Given the module resolver.py already found for a CVE, plus a small set of
target facts (the kind a `scan` stage would already produce), mechanically
fill in the module's own declared required options. Then diff the result
against a human-verified attack/ config.

Comparison only. Does not execute, check, or configure any exploit. Does
not touch any Docker container beyond what resolver.py already does for
module-metadata lookup. Does not modify anything under attack/, cve_meta/,
patch/, or src/kalama/ -- the ground-truth file is read-only input.

Usage:
    python draft_config.py run --cve CVE-2015-1427 \
        --ground-truth /path/to/attack/exploit_st_A/CVE-2015-1427.yaml
"""

import argparse
import sys

import yaml  # read-only parse of the ground-truth attack/ config

from kalama.resolver import backend as resolver  # resolver.py, same directory -- build_draft() and its
                  # fact/option constants now live there so the batch/review
                  # CLI in resolver.py can reuse them without a circular import

DEFAULT_FACTS = resolver.DEFAULT_FACTS
FACT_FOR_OPTION = resolver.FACT_FOR_OPTION
NOT_IN_MODULE_SCHEMA = resolver.NOT_IN_MODULE_SCHEMA
build_draft = resolver.build_draft

DIFF_FIELDS = ["module", "RHOSTS", "RPORT", "PAYLOAD", "LHOST"]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def load_ground_truth(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def diff_value(a, b):
    return a == b


def render_diff_table(draft, ground_truth):
    gt_exploit = ground_truth.get("exploit", {}) or {}
    gt_params = gt_exploit.get("params", {}) or {}

    gt_values = {
        "module": gt_exploit.get("module"),
        "RHOSTS": gt_params.get("RHOSTS"),
        "RPORT": gt_params.get("RPORT"),
        "PAYLOAD": gt_params.get("PAYLOAD"),
        "LHOST": gt_params.get("LHOST"),
    }
    draft_values = {
        "module": draft["module"],
        "RHOSTS": draft["params"].get("RHOSTS"),
        "RPORT": draft["params"].get("RPORT"),
        "PAYLOAD": draft["params"].get("PAYLOAD"),
        "LHOST": draft["params"].get("LHOST"),
    }

    lines = []
    lines.append("| field | ground truth | resolver draft | match? |")
    lines.append("|---|---|---|---|")
    for field in DIFF_FIELDS:
        gt_v = gt_values[field]
        draft_v = draft_values[field]
        if draft_v is None and gt_v is not None:
            verdict = "NO MATCH (unresolved)"
        elif diff_value(gt_v, draft_v):
            verdict = "MATCH"
        else:
            verdict = "NO MATCH"
        lines.append(f"| {field} | `{gt_v}` | `{draft_v}` | {verdict} |")
    return "\n".join(lines)


def render_supplementary_table(draft):
    """Every OTHER required option the module declares, beyond the 4 named
    fields the spec's diff table asks about. Not part of the requested
    comparison -- included because it's the direct answer to the exercise's
    actual question ("how many option fields CAN be filled from facts +
    module defaults alone") and costs nothing extra to show."""
    extra = [n for n in draft["required_option_names"] if n not in FACT_FOR_OPTION]
    if not extra:
        return None
    lines = []
    lines.append("| option | required | resolved value | how |")
    lines.append("|---|---|---|---|")
    for name in extra:
        value = draft["params"].get(name)
        note = draft["notes"].get(name, "")
        status = "unresolved (null)" if value is None else f"`{value}`"
        lines.append(f"| {name} | yes | {status} | {note} |")
    return "\n".join(lines)


def render_setup_steps_gap(ground_truth):
    setup_steps = ground_truth.get("setup_steps")
    if not setup_steps:
        return "(ground truth has no setup_steps block)"
    dumped = yaml.safe_dump({"setup_steps": setup_steps}, sort_keys=False, allow_unicode=True)
    return dumped


def main():
    parser = argparse.ArgumentParser(prog="draft_config.py")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="Build a draft config and diff it against ground truth")
    run_p.add_argument("--cve", required=True, help="CVE-ID, e.g. CVE-2015-1427")
    run_p.add_argument("--ground-truth", required=True, help="Path to the verified attack/ YAML")
    run_p.add_argument("--target-ip", default=DEFAULT_FACTS["target_ip"])
    run_p.add_argument("--target-port", type=int, default=DEFAULT_FACTS["target_port"])
    run_p.add_argument("--msf-ip", default=DEFAULT_FACTS["msf_ip"])
    run_p.add_argument(
        "--msf-container", default=resolver.DEFAULT_MSF_CONTAINER,
        help=f"Docker container running msfconsole (default: {resolver.DEFAULT_MSF_CONTAINER})",
    )
    args = parser.parse_args()

    cve_id = resolver.normalize_cve(args.cve)
    if cve_id is None:
        eprint(f"[draft_config] invalid CVE-ID format: {args.cve!r}")
        sys.exit(2)

    facts = {
        "target_ip": args.target_ip,
        "target_port": args.target_port,
        "msf_ip": args.msf_ip,
    }

    try:
        draft = build_draft(cve_id, args.msf_container, facts)
        ground_truth = load_ground_truth(args.ground_truth)
    except (RuntimeError, OSError, yaml.YAMLError) as e:
        eprint(f"[draft_config] error: {e}")
        sys.exit(1)

    print(f"# Option Resolver draft vs ground truth -- {cve_id}\n")

    print("## Draft config (mechanically resolved from module metadata + scan facts)\n")
    print("```yaml")
    print(f"module: {resolver.yaml_scalar(draft['module'])}")
    print("params:")
    for name, value in draft["params"].items():
        print(f"  {name}: {resolver.yaml_scalar(value)}  # {draft['notes'][name]}")
    print("```\n")

    print(f"## Diff vs ground truth ({args.ground_truth})\n")
    print(render_diff_table(draft, ground_truth))
    print()

    supplementary = render_supplementary_table(draft)
    if supplementary:
        print("## Additional required options the module declares (beyond the 4 named fields)\n")
        print(supplementary)
        print()

    print("## Gap: setup_steps (expected, not a failure)\n")
    print(
        "The resolver draft has nothing corresponding to this block. It is "
        "not a module option at all -- it's CVE-specific HTTP precondition "
        "knowledge (the empty-index check() bug) that lives entirely in the "
        "human-verified lab note and the attack/ YAML. Captured here for the "
        "record, not attempted:\n"
    )
    print("```yaml")
    print(render_setup_steps_gap(ground_truth), end="")
    print("```")


if __name__ == "__main__":
    main()
