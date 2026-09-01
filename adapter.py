#!/usr/bin/env python3
"""Translate reviewed resolver output into a Kalama attack-config draft.

The generated file is deliberately marked as needing review whenever the
resolver does not contain enough information to complete a field.  This tool
does not edit the pipeline, cve_meta, or hand-verified attack strategies.
"""

from __future__ import annotations

import argparse
import copy
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


VALID_DEPLOYMENT_MODES = {"single_image", "vulhub_compose"}
VULHUB_REQUIRED_FIELDS = {"vulhub_case_path", "victim_service"}
AUTO_FIELDS = ("tool", "module", "params", "oracle.verdict_source")
MANUAL_FIELDS = ("deployment", "setup_steps", "wait_seconds", "oracle.verdict_source")


class AdapterError(RuntimeError):
    pass


@dataclass
class Conversion:
    cve_id: str
    output: dict[str, Any]
    auto_filled: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def load_mapping(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AdapterError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise AdapterError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AdapterError(f"{path} must contain a YAML mapping")
    return data


def find_pipeline_root(explicit: Path | None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend((Path.cwd(), Path.cwd().parent / "kalama-mvp"))
    for root in candidates:
        if (root / "src/app/kalama/scan/scan.py").is_file() and (root / "attack").is_dir():
            return root.resolve()
    if explicit:
        raise AdapterError(f"pipeline root does not have the expected Kalama layout: {explicit}")
    return None


def deployment_from_verified_attack(pipeline_root: Path | None, cve_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Reuse deployment only when cve_meta points to a verified strategy.

    This is existing, CVE-specific project data, not a heuristic.  If it is
    absent or invalid, the adapter leaves deployment for manual completion.
    """
    if pipeline_root is None:
        return None, None
    meta_path = pipeline_root / "cve_meta" / f"{cve_id}.yaml"
    if not meta_path.is_file():
        return None, None
    meta = load_mapping(meta_path)
    for affected in meta.get("affected", []) or []:
        for version_range in affected.get("version_ranges", []) or []:
            strategy = version_range.get("attack_strategy")
            if not version_range.get("verified") or not strategy:
                continue
            source = pipeline_root / "attack" / str(strategy) / f"{cve_id}.yaml"
            if not source.is_file():
                continue
            deployment = load_mapping(source).get("deployment")
            errors = deployment_errors(deployment)
            if not errors:
                return copy.deepcopy(deployment), str(source)
    return None, None


def deployment_errors(deployment: Any) -> list[str]:
    if not isinstance(deployment, dict):
        return ["deployment must be a mapping"]
    mode = deployment.get("mode")
    if mode not in VALID_DEPLOYMENT_MODES:
        return [f"deployment.mode must be one of {sorted(VALID_DEPLOYMENT_MODES)}"]
    if mode == "vulhub_compose":
        missing = sorted(k for k in VULHUB_REQUIRED_FIELDS if not deployment.get(k))
        if missing:
            return [f"vulhub_compose deployment is missing: {', '.join(missing)}"]
    return []


def convert(resolved: dict[str, Any], pipeline_root: Path | None) -> Conversion:
    cve_id = resolved.get("cve_id")
    module = resolved.get("module")
    params = resolved.get("params")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise AdapterError("resolved input is missing a valid cve_id")
    if not isinstance(module, str) or not module:
        raise AdapterError(f"{cve_id}: resolved input is missing module")
    if not isinstance(params, dict):
        raise AdapterError(f"{cve_id}: resolved input params must be a mapping")

    result = Conversion(cve_id=cve_id, output={})
    deployment, source = deployment_from_verified_attack(pipeline_root, cve_id)
    if deployment is None:
        deployment = {"mode": None}
        result.manual.append("deployment")
        result.notes.append("deployment.mode is intentionally null; resolve_case_config() will stop until a human completes it")
    else:
        result.auto_filled.append("deployment")
        result.notes.append(f"deployment copied from verified project data: {source}")

    check_supported = resolved.get("check_supported")
    oracle: dict[str, Any]
    if check_supported is True:
        oracle = {"verdict_source": "msf_check"}
        result.auto_filled.append("oracle.verdict_source")
    else:
        oracle = {"verdict_source": None}
        result.manual.append("oracle.verdict_source")
        if check_supported is False:
            result.notes.append("resolver reports check_supported=false; a different oracle strategy is required")
        else:
            result.notes.append("current resolver review output omits check_supported; oracle cannot be inferred from this file")

    result.auto_filled.extend(("tool", "module", "params"))
    result.manual.extend(("setup_steps", "wait_seconds"))
    result.output = {
        "cve_id": cve_id,
        "strategy": "exploit_resolver",
        "deployment": deployment,
        "setup_steps": [],
        "exploit": {
            "tool": "msf",
            "module": module,
            "params": copy.deepcopy(params),
            "wait_seconds": None,
        },
        "oracle": oracle,
        "adapter_status": {
            "status": "needs_review" if result.manual else "complete",
            "requires_manual_completion": result.manual,
            "notes": result.notes,
        },
    }
    return result


def validate_shape(conversion: Conversion) -> list[str]:
    """Validate keys used by resolve_case_config and its MSF consumer."""
    data = conversion.output
    errors = []
    for key in ("deployment", "setup_steps", "exploit", "oracle"):
        if key not in data:
            errors.append(f"missing top-level key: {key}")
    exploit = data.get("exploit")
    if not isinstance(exploit, dict):
        errors.append("exploit must be a mapping")
    else:
        for key in ("tool", "module", "params", "wait_seconds"):
            if key not in exploit:
                errors.append(f"missing exploit.{key}")
    # Match scan.py's actual hard validation. A manual deployment placeholder
    # is allowed to be written, but is reported as pipeline-blocking.
    errors.extend(deployment_errors(data.get("deployment")))
    return errors


def write_conversion(conversion: Conversion, out_path: Path) -> list[str]:
    errors = validate_shape(conversion)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        yaml.safe_dump(conversion.output, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return errors


def print_summary(conversion: Conversion, out_path: Path, errors: list[str]) -> None:
    print(f"{conversion.cve_id}: written to {out_path}")
    if conversion.manual:
        print(f"  ⚠ requires manual completion: {', '.join(conversion.manual)}")
    print(f"  ✓ auto-filled: {', '.join(conversion.auto_filled)}")
    if errors:
        print("  ✗ not safe for resolve_case_config() yet:")
        for error in errors:
            print(f"    - {error}")
    else:
        print("  ✓ validates against resolve_case_config()'s required deployment shape")
    for note in conversion.notes:
        print(f"  note: {note}")
    if conversion.manual:
        print("  status: needs human completion; not pipeline-ready")


def command_convert(args: argparse.Namespace) -> int:
    resolved_path = Path(args.resolved)
    out_path = Path(args.out)
    pipeline_root = find_pipeline_root(Path(args.pipeline_root) if args.pipeline_root else None)
    conversion = convert(load_mapping(resolved_path), pipeline_root)
    errors = write_conversion(conversion, out_path)
    print_summary(conversion, out_path, errors)
    return 0


def command_batch(args: argparse.Namespace) -> int:
    resolved_dir = Path(args.resolved_dir)
    out_dir = Path(args.out_dir)
    pipeline_root = find_pipeline_root(Path(args.pipeline_root) if args.pipeline_root else None)
    paths = sorted(resolved_dir.glob("*.yaml"))
    if not paths:
        raise AdapterError(f"no YAML files found in {resolved_dir}")
    for path in paths:
        conversion = convert(load_mapping(path), pipeline_root)
        out_path = out_dir / f"{conversion.cve_id}.yaml"
        errors = write_conversion(conversion, out_path)
        print_summary(conversion, out_path, errors)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipeline-root", help="Kalama MVP root; auto-detected as ../kalama-mvp when available")
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("convert", help="convert one reviewed resolver YAML")
    one.add_argument("--resolved", required=True)
    one.add_argument("--out", required=True)
    one.set_defaults(func=command_convert)
    batch = sub.add_parser("convert-batch", help="convert all reviewed resolver YAML files in a directory")
    batch.add_argument("--resolved-dir", required=True)
    batch.add_argument("--out-dir", required=True)
    batch.set_defaults(func=command_batch)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except AdapterError as exc:
        print(f"adapter: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
