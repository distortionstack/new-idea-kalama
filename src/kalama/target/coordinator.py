"""Thin Step 2 coordinator. It does not persist central run state."""

from __future__ import annotations

from pathlib import Path

from .models import Step2Request, Step2Result, Step2Status
from .trivy_scanner import scan_image
from .victim_manager import (
    CommandRunner, Step2OperationError, collect_target_facts, prepare_container,
    resolve_image, wait_until_ready,
)


def execute_step2(request: Step2Request, runner: CommandRunner,
                  *, trivy_timeout: float | None = None) -> Step2Result:
    image = None
    target_facts = None
    try:
        image = resolve_image(request, runner)
        if request.victim_runtime_required:
            prepare_container(request, image, runner)
            ready = wait_until_ready(f"victim-{request.run_id}", runner,
                                     request.startup_timeout, request.startup_grace_period)
            target_facts = collect_target_facts(request, image, ready, runner)
        artifact = scan_image(image, Path(request.output_path), runner, timeout=trivy_timeout)
        return Step2Result(Step2Status.SUCCEEDED, image, target_facts, artifact)
    except Step2OperationError as exc:
        return Step2Result(Step2Status.FAILED, image, target_facts, failure=exc.issue)

