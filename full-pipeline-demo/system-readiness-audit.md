# System readiness audit

Date: 2026-10-13. Working directory:
`C:\Users\distortion\Documents\new-idea-kalama`.

## Classification

**NOT_READY** for a new end-to-end run.

## Passed

- Git revision: `5699dc10bc772e1dc72478e55f3c9b3ac8ef7905`.
- Python 3.12.14 and PyYAML 6.0.3 in `.venv`.
- CLI imports and `kalama --help` work in the virtual environment.
- `pip check`: no broken requirements.
- Output root is writable.
- Doctor reports EPSS and CISA KEV providers configured; LLM assistance disabled.
- Docker CLI is installed (`29.7.2`). Docker Compose is documented and the
  CLI is present in the environment configuration.

## Failed or blocked

`.venv\Scripts\python.exe -m kalama doctor` reports
`DOCKER_DAEMON_UNREACHABLE`. Consequently `kalama-net`, `msf-resolver-host`,
the workbench, and workbench Trivy are unchecked rather than READY.

## Test evidence

A focused unit-test command was run for doctor, attribution, and scoped
evaluation tests. Result: **23 passed, 19 failed, 10 errors**. Several failures
are caused by Windows sandbox temporary-directory permission errors during
cleanup; attribution assertions also failed. This is not a clean passing
verification of the current checkout.

No exploit, patch, Docker mutation, or new case was started.
