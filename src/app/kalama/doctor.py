"""Read-only environment diagnostics for the production pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

import yaml

from .target.models import CommandResult
from .target.victim_manager import CommandRunner, SubprocessCommandRunner
from .infrastructure import WORKBENCH_NAME


class CheckStatus(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    section: str
    label: str
    status: CheckStatus
    required: bool
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"id": self.check_id, "section": self.section, "label": self.label,
                "status": self.status.value, "required": self.required,
                "message": self.message}


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[CheckResult, ...]

    @property
    def ready(self) -> bool:
        return not any(item.required and item.status == CheckStatus.FAIL for item in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {"ready": self.ready, "checks": [item.to_dict() for item in self.checks]}


def _command(runner: CommandRunner, argv: Sequence[str], *, check_id: str,
             section: str, label: str, missing_code: str, failure_code: str) -> CheckResult:
    result = runner.run(argv, timeout=10)
    if result.exit_code == 0:
        value = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "available"
        return CheckResult(check_id, section, label, CheckStatus.OK, True, value)
    code = missing_code if result.exit_code == 127 else failure_code
    return CheckResult(check_id, section, label, CheckStatus.FAIL, True,
                       f"{code}: {result.stderr.strip() or result.stdout.strip() or 'command failed'}")


def _expected(runner: CommandRunner, argv: Sequence[str], expected: str, *, check_id: str,
              section: str, label: str, failure_code: str) -> CheckResult:
    result = runner.run(argv, timeout=10)
    actual = result.stdout.strip()
    ok = result.exit_code == 0 and actual == expected
    return CheckResult(check_id, section, label, CheckStatus.OK if ok else CheckStatus.FAIL,
                       True, actual if ok else f"{failure_code}: {result.stderr.strip() or actual or 'check failed'}")


def _storage_check(output_root: Path) -> CheckResult:
    if not output_root.is_dir():
        return CheckResult("OUTPUT_ROOT", "Storage", "output root", CheckStatus.FAIL, True,
                           "OUTPUT_ROOT_MISSING: run ./setup-workbench.sh")
    probe = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_root, prefix=".kalama-doctor-", delete=False) as handle:
            probe = Path(handle.name)
            handle.write(b"doctor")
            handle.flush()
            os.fsync(handle.fileno())
        probe.unlink()
        return CheckResult("OUTPUT_ROOT", "Storage", "output root writable",
                           CheckStatus.OK, True, str(output_root))
    except OSError as exc:
        if probe is not None:
            try: probe.unlink()
            except OSError: pass
        return CheckResult("OUTPUT_ROOT", "Storage", "output root writable",
                           CheckStatus.FAIL, True, f"OUTPUT_ROOT_UNWRITABLE: {exc}")


def run_doctor(output_root: Path, *, runner: CommandRunner | None = None) -> DoctorReport:
    runner = runner or SubprocessCommandRunner()
    checks = [
        CheckResult("PYTHON_VERSION", "Python", "Python version",
                    CheckStatus.OK if sys.version_info >= (3, 10) else CheckStatus.FAIL,
                    True, sys.version.split()[0]),
        CheckResult("PYYAML", "Python", "PyYAML", CheckStatus.OK, True, yaml.__version__),
    ]
    docker_cli = _command(runner, ("docker", "--version"), check_id="DOCKER_CLI",
                          section="Docker", label="docker CLI", missing_code="DOCKER_CLI_MISSING",
                          failure_code="DOCKER_CLI_UNUSABLE")
    checks.append(docker_cli)
    if docker_cli.status == CheckStatus.OK:
        daemon = _command(runner, ("docker", "info", "--format", "{{.ServerVersion}}"),
                          check_id="DOCKER_DAEMON", section="Docker", label="daemon",
                          missing_code="DOCKER_CLI_MISSING",
                          failure_code="DOCKER_DAEMON_UNREACHABLE")
    else:
        daemon = CheckResult("DOCKER_DAEMON", "Docker", "daemon", CheckStatus.FAIL, True,
                             "DOCKER_DAEMON_UNCHECKED: Docker CLI unavailable")
    checks.append(daemon)
    if daemon.status == CheckStatus.OK:
        checks.append(_command(runner, ("docker", "network", "inspect", "kalama-net"),
                               check_id="KALAMA_NETWORK", section="Docker", label="kalama-net",
                               missing_code="KALAMA_NETWORK_MISSING",
                               failure_code="KALAMA_NETWORK_MISSING"))
        container = _command(runner, ("docker", "container", "inspect", "msf-resolver-host"),
                             check_id="MSF_CONTAINER", section="Metasploit",
                             label="msf-resolver-host", missing_code="MSF_RESOLVER_HOST_MISSING",
                             failure_code="MSF_RESOLVER_HOST_MISSING")
        checks.append(container)
        if container.status == CheckStatus.OK:
            running_result = runner.run(("docker", "inspect", "-f", "{{.State.Running}}",
                                         "msf-resolver-host"), timeout=10)
            running = running_result.exit_code == 0 and running_result.stdout.strip() == "true"
            checks.append(CheckResult(
                "MSF_RUNNING", "Metasploit", "container running",
                CheckStatus.OK if running else CheckStatus.FAIL, True,
                "true" if running else "MSF_RESOLVER_HOST_STOPPED"))
            checks.append(_expected(
                runner, ("docker", "inspect", "-f",
                         "{{if index .NetworkSettings.Networks \"kalama-net\"}}true{{else}}false{{end}}",
                         "msf-resolver-host"), "true", check_id="MSF_NETWORK",
                section="Metasploit", label="kalama-net attached",
                failure_code="MSF_RESOLVER_NETWORK_MISSING"))
        else:
            checks.append(CheckResult("MSF_RUNNING", "Metasploit", "container running",
                                      CheckStatus.FAIL, True, "MSF_RESOLVER_HOST_UNCHECKED"))
            checks.append(CheckResult("MSF_NETWORK", "Metasploit", "kalama-net attached",
                                      CheckStatus.FAIL, True, "MSF_RESOLVER_HOST_UNCHECKED"))

        workbench = _command(runner, ("docker", "container", "inspect", WORKBENCH_NAME),
                             check_id="WORKBENCH", section="Workbench",
                             label=WORKBENCH_NAME, missing_code="WORKBENCH_MISSING",
                             failure_code="WORKBENCH_MISSING")
        checks.append(workbench)
        if workbench.status == CheckStatus.OK:
            checks.extend((
                _expected(runner, ("docker", "inspect", "-f", "{{.State.Running}}",
                                   WORKBENCH_NAME), "true", check_id="WORKBENCH_RUNNING",
                          section="Workbench", label="container running",
                          failure_code="WORKBENCH_STOPPED"),
                _expected(runner, ("docker", "inspect", "-f",
                                   "{{if and (eq (index .Config.Labels \"kalama.managed\") \"true\") (eq (index .Config.Labels \"kalama.role\") \"workbench\")}}true{{else}}false{{end}}",
                                   WORKBENCH_NAME), "true", check_id="WORKBENCH_OWNERSHIP",
                          section="Workbench", label="managed ownership",
                          failure_code="WORKBENCH_CONTAINER_CONFLICT"),
                _expected(runner, ("docker", "inspect", "-f",
                                   "{{range .Mounts}}{{if and (eq .Source \"/var/run/docker.sock\") (eq .Destination \"/var/run/docker.sock\")}}true{{end}}{{end}}",
                                   WORKBENCH_NAME), "true", check_id="WORKBENCH_SOCKET",
                          section="Workbench", label="docker socket",
                          failure_code="WORKBENCH_SOCKET_MISSING"),
                _expected(runner, ("docker", "inspect", "-f",
                                   "{{if index .NetworkSettings.Networks \"kalama-net\"}}true{{else}}false{{end}}",
                                   WORKBENCH_NAME), "true", check_id="WORKBENCH_NETWORK",
                          section="Workbench", label="kalama-net attached",
                          failure_code="WORKBENCH_NETWORK_MISSING"),
            ))
            checks.append(_command(
                runner, ("docker", "exec", WORKBENCH_NAME, "docker", "info", "--format",
                         "{{.ServerVersion}}"), check_id="WORKBENCH_DOCKER", section="Workbench",
                label="Docker socket usable", missing_code="WORKBENCH_DOCKER_UNREACHABLE",
                failure_code="WORKBENCH_DOCKER_UNREACHABLE"))
            checks.append(_command(
                runner, ("docker", "exec", WORKBENCH_NAME, "trivy", "--version"),
                check_id="WORKBENCH_TRIVY", section="Scanner", label="Trivy (workbench)",
                missing_code="WORKBENCH_TRIVY_MISSING",
                failure_code="WORKBENCH_TRIVY_MISSING"))
        else:
            for check_id, label, code in (
                ("WORKBENCH_RUNNING", "container running", "WORKBENCH_UNCHECKED"),
                ("WORKBENCH_OWNERSHIP", "managed ownership", "WORKBENCH_UNCHECKED"),
                ("WORKBENCH_SOCKET", "docker socket", "WORKBENCH_UNCHECKED"),
                ("WORKBENCH_NETWORK", "kalama-net attached", "WORKBENCH_UNCHECKED"),
                ("WORKBENCH_DOCKER", "Docker socket usable", "WORKBENCH_UNCHECKED"),
            ):
                checks.append(CheckResult(check_id, "Workbench", label, CheckStatus.FAIL, True, code))
            checks.append(CheckResult("WORKBENCH_TRIVY", "Scanner", "Trivy (workbench)",
                                      CheckStatus.FAIL, True, "WORKBENCH_TRIVY_UNCHECKED"))
    else:
        checks.extend((
            CheckResult("KALAMA_NETWORK", "Docker", "kalama-net", CheckStatus.FAIL, True,
                        "KALAMA_NETWORK_UNCHECKED"),
            CheckResult("MSF_CONTAINER", "Metasploit", "msf-resolver-host", CheckStatus.FAIL, True,
                        "MSF_RESOLVER_HOST_UNCHECKED"),
            CheckResult("MSF_RUNNING", "Metasploit", "container running", CheckStatus.FAIL, True,
                        "MSF_RESOLVER_HOST_UNCHECKED"),
            CheckResult("MSF_NETWORK", "Metasploit", "kalama-net attached", CheckStatus.FAIL, True,
                        "MSF_RESOLVER_HOST_UNCHECKED"),
            CheckResult("WORKBENCH", "Workbench", WORKBENCH_NAME, CheckStatus.FAIL, True,
                        "WORKBENCH_UNCHECKED"),
            CheckResult("WORKBENCH_TRIVY", "Scanner", "Trivy (workbench)", CheckStatus.FAIL, True,
                        "WORKBENCH_TRIVY_UNCHECKED"),
        ))
    checks.extend((
        CheckResult("EPSS_PROVIDER", "Providers", "FIRST EPSS adapter", CheckStatus.OK, True,
                    "configured; network is exercised by the pipeline"),
        CheckResult("KEV_PROVIDER", "Providers", "CISA KEV adapter", CheckStatus.OK, True,
                    "configured; network is exercised by the pipeline"),
        _storage_check(output_root.resolve()),
    ))
    return DoctorReport(tuple(checks))


def render_doctor(report: DoctorReport) -> str:
    lines = ["Kalama Environment Doctor"]
    sections: list[str] = []
    for item in report.checks:
        if item.section not in sections: sections.append(item.section)
    for section in sections:
        lines.extend(("", section))
        for item in (x for x in report.checks if x.section == section):
            lines.append(f"  {item.label:<28} {item.status.value:<7} {item.message}")
    lines.extend(("", "Overall", f"  {'READY' if report.ready else 'NOT_READY'}"))
    problems = [x for x in report.checks if x.required and x.status == CheckStatus.FAIL]
    if problems:
        lines.extend(("", "Problems:"))
        lines.extend(f"  {item.message.split(':', 1)[0]}" for item in problems)
        lines.extend(("", "Run:", "  ./setup-workbench.sh"))
    return "\n".join(lines)
