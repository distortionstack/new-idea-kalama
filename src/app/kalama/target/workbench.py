"""Production routing for scanner tools hosted by the modern workbench."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .models import CommandResult
from .victim_manager import CommandRunner
from ..infrastructure import WORKBENCH_NAME


class WorkbenchToolRunner:
    """Route Trivy to the managed workbench without a host fallback.

    Non-Trivy commands are delegated unchanged because Step 2 also uses the
    same runner for host Docker operations. The adapter remains argv-only.
    """

    def __init__(self, runner: CommandRunner, *, container: str = WORKBENCH_NAME):
        self.runner = runner
        self.container = container

    def run(self, argv: Sequence[str], *, timeout: float | None = None) -> CommandResult:
        args = tuple(str(item) for item in argv)
        if args and args[0] == "trivy":
            output_path = None
            if "--output" in args:
                index = args.index("--output")
                if index + 1 < len(args):
                    output_path = Path(args[index + 1])
                    args = args[:index] + args[index + 2:]
            result = self.runner.run(("docker", "exec", self.container) + args,
                                     timeout=timeout)
            if result.exit_code == 0 and output_path is not None:
                try:
                    output_path.write_text(result.stdout, encoding="utf-8")
                except OSError as exc:
                    return CommandResult(result.argv, 1, result.stdout,
                                         f"workbench scan output transfer failed: {exc}")
            return result
        return self.runner.run(args, timeout=timeout)
