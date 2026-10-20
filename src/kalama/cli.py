"""VIPER command-line adapter with backwards-compatible Kalama entry points."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Callable, TextIO

from .runtime import build_runtime
from .doctor import render_doctor, run_doctor
from .state import ArtifactKind, RunState, RunStatus, StateStoreError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="viper", description="VIPER — Vulnerability Inspection, Patching, and Exploit Retesting for Container Images")
    parser.add_argument("--output-root", default="output", help="canonical output root (default: output; per-case: output/<case>)")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="create a run and execute target scan + prioritization")
    run.add_argument("--image", required=True, help="victim image reference")
    run.add_argument("--dynamic-scan", choices=["off", "nuclei"], default="off",
                     help="opt-in shadow dynamic probing with approved Nuclei templates (default: off)")
    run.add_argument("--nuclei-profile", choices=["safe-cve-http"], default="safe-cve-http",
                     help="approved Nuclei template profile (default: safe-cve-http)")
    run.add_argument("--dynamic-scan-required", action="store_true",
                     help="fail the run when requested dynamic probing is inconclusive")
    for name, help_text in (
        ("continue", "execute exactly one pipeline stage"),
        ("status", "show canonical run state"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("run_id")
        if name == "continue":
            command.add_argument("--resolver-cve", default=None,
                                 help="controlled Resolver scope: one CVE already present in verified Top-30")
    attack = sub.add_parser("submit-attack-form", help="submit an Attack Form snapshot")
    attack.add_argument("run_id")
    attack.add_argument("file", type=Path)
    patch = sub.add_parser("submit-patch-form", help="submit a Patch Form snapshot")
    patch.add_argument("run_id")
    patch.add_argument("file", type=Path)
    retry = sub.add_parser("retry", help="retry a supported failed pipeline attempt")
    retry.add_argument("run_id")
    retry_mode = retry.add_mutually_exclusive_group(required=False)
    retry_mode.add_argument("--edit-plan", action="store_true",
                            help="create the next editable Patch Form revision")
    retry_mode.add_argument("--same-plan", action="store_true",
                            help="retry the current confirmed Patch Plan unchanged")
    retry.add_argument("--force-smoke-failed", action="store_true",
                       help="bounded override: retry a mechanically successful patch "
                            "that failed live smoke (PAUSED/STEP_6_AFTER_SCAN only, "
                            "requires --edit-plan)")
    doctor = sub.add_parser("doctor", help="validate the production environment without modifying it")
    doctor.add_argument("--json", action="store_true", help="emit a machine-readable report")
    return parser


def _line(stream: TextIO, label: str, value: object | None) -> None:
    if value is not None:
        print(f"{label}: {value}", file=stream)


def _target(stream: TextIO, heading: str, target) -> None:
    if target is None:
        return
    print(f"\n{heading}:", file=stream)
    identity, facts = target.image_identity, target.facts or {}
    for label, value in (("  container", facts.get("container_name")),
                         ("  image ID", identity.get("image_id")),
                         ("  IP", facts.get("ip_address"))):
        _line(stream, label, value)


def _artifact_summary(stream: TextIO, state: RunState, kind: ArtifactKind, heading: str) -> None:
    reference = state.artifact(kind)
    if reference is None:
        return
    print(f"\n{heading}:", file=stream)
    for key, value in reference.summary:
        print(f"  {key}: {value}", file=stream)


def _next_action(stream: TextIO, state: RunState) -> None:
    print("\nNext:", file=stream)
    if state.status == RunStatus.COMPLETED:
        print("  Run is complete.", file=stream)
    elif state.status == RunStatus.FAILED_FATAL:
        if state.current_stage and state.current_stage.value in {"STEP_5_PATCH_EXECUTION", "STEP_6_AFTER_SCAN"}:
            print(f"  python3 -m kalama retry {state.run_id} --edit-plan", file=stream)
            print(f"  python3 -m kalama retry {state.run_id} --same-plan", file=stream)
        else:
            print("  Run failed; execution is disabled.", file=stream)
    elif state.status == RunStatus.WAITING_FOR_USER_INPUT:
        if state.waiting_reason == "ATTACK_FORM":
            ref = state.artifact(ArtifactKind.ATTACK_FORM)
            if ref:
                print(f"  Copy the canonical form to a new file before editing: {ref.path}", file=stream)
            print(f"  python3 -m kalama submit-attack-form {state.run_id} EDITED_COPY.yaml", file=stream)
        elif state.waiting_reason == "PATCH_FORM":
            ref = state.artifact(ArtifactKind.PATCH_FORM)
            if ref: print(f"  Copy/edit the canonical form: {ref.path}", file=stream)
            print(f"  python3 -m kalama submit-patch-form {state.run_id} FILE", file=stream)
        else:
            print(f"  User input required: {state.waiting_reason or 'unspecified'}", file=stream)
    else:
        print(f"  python3 -m kalama continue {state.run_id}", file=stream)


def render_state(state: RunState, state_path: Path, stream: TextIO) -> None:
    _line(stream, "Run ID", state.run_id)
    _line(stream, "Status", state.status.value)
    _line(stream, "Current stage", state.current_stage.value if state.current_stage else None)
    _line(stream, "Waiting reason", state.waiting_reason)
    _line(stream, "Created", state.created_at)
    if state.status == RunStatus.COMPLETED:
        _line(stream, "Completed", state.updated_at)
    _line(stream, "Requested image", state.victim_image)
    _line(stream, "State", state_path)
    _target(stream, "Before target", state.target)
    if state.patched_image: _line(stream, "\nPatched image", state.patched_image.get("reference"))
    _target(stream, "After target", state.after_target)
    print("\nStages:", file=stream)
    for stage in state.stages:
        print(f"  {stage.stage.value}: {stage.status.value}", file=stream)
    for kind, heading in (
        (ArtifactKind.TOP30_BEFORE, "Prioritization"),
        (ArtifactKind.ATTACK_BEFORE, "Before exploit"),
        (ArtifactKind.PATCH_RESULT, "Patch"),
        (ArtifactKind.REMEDIATION_SCAN_RESULT, "After scan"),
        (ArtifactKind.ATTACK_AFTER, "After exploit"),
        (ArtifactKind.REMEDIATION_RESULT, "Remediation"),
        (ArtifactKind.EVALUATION_METRICS, "Evaluation"),
    ):
        _artifact_summary(stream, state, kind, heading)
    if state.status == RunStatus.COMPLETED:
        for kind in (ArtifactKind.EVALUATION_DATASET, ArtifactKind.EVALUATION_METRICS,
                     ArtifactKind.RUN_SUMMARY):
            ref = state.artifact(kind)
            if ref: _line(stream, kind.value, ref.path)
    if state.errors:
        print("\nErrors:", file=stream)
        for error in state.errors:
            print(f"  {error.code}: {error.message}", file=stream)
    _next_action(stream, state)


def main(argv: list[str] | None = None, *, runtime_factory: Callable = build_runtime,
         stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        report = run_doctor(Path(args.output_root))
        print(json.dumps(report.to_dict(), sort_keys=True) if args.json else render_doctor(report),
              file=stdout)
        return 0 if report.ready else 1
    runtime = runtime_factory(Path(args.output_root))
    try:
        if args.command == "run":
            if not args.image.strip():
                raise ValueError("IMAGE_REQUIRED: image must not be empty")
            state = runtime.start(args.image.strip(), dynamic_scan=args.dynamic_scan,
                                  nuclei_profile=args.nuclei_profile,
                                  dynamic_scan_required=args.dynamic_scan_required)
        else:
            path = runtime.store.path_for(args.run_id)
            if not path.is_file():
                print(f"RUN_NOT_FOUND: {args.run_id}", file=stderr)
                return 1
            if args.command == "status":
                state = runtime.store.load(args.run_id)
            elif args.command == "continue":
                before = runtime.store.load(args.run_id)
                if before.status in (RunStatus.WAITING_FOR_USER_INPUT, RunStatus.COMPLETED,
                                     RunStatus.FAILED_FATAL):
                    state = before
                else:
                        if args.resolver_cve:
                            state = runtime.continue_once(args.run_id, resolver_cve=args.resolver_cve)
                        else:
                            state = runtime.continue_once(args.run_id)
            elif args.command == "submit-attack-form":
                state = runtime.submit_attack_form(args.run_id, args.file)
            elif args.command == "submit-patch-form":
                state = runtime.submit_patch_form(args.run_id, args.file)
            else:
                state = runtime.retry_patch_execution(
                    args.run_id, edit_plan=args.edit_plan,
                    force_smoke_failed=args.force_smoke_failed)
        render_state(state, runtime.store.path_for(state.run_id), stdout)
        return 1 if state.status == RunStatus.FAILED_FATAL else 0
    except (StateStoreError, ValueError, RuntimeError) as exc:
        code = getattr(exc, "code", exc.__class__.__name__.upper())
        print(f"{code}: {exc}", file=stderr)
        return 1
