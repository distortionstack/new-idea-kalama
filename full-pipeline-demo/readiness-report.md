# Readiness report

Assessment: **NOT_READY for a new live run.** Historical evidence review is
possible, but no historical run meets the fully verified success criteria.

Evidence: `.venv\Scripts\python.exe -m kalama doctor` on 2026-10-13 reported
Python 3.12.14 and PyYAML 6.0.3 as OK, but Docker daemon
`DOCKER_DAEMON_UNREACHABLE`. Consequently `kalama-net`, `msf-resolver-host`,
the workbench, and workbench Trivy were unchecked. Output storage and provider
configuration were OK; LLM assistance was disabled.

The supported CLI is `run`, `continue`, `status`, Attack Form and Patch Form
submission, `retry`, and `doctor` (`src/kalama/cli.py`). The documented core
flow is scan → prioritize → resolver/Attack Form → BEFORE exploit → patch plan
and execution → AFTER scan → re-exploit → evaluation (README.md).

Blockers for a new execution:

1. Docker Desktop's Linux engine is not reachable.
2. Required network, scanner workbench, and Metasploit resolver services
   therefore cannot be verified.
3. Existing checkout changes are present; this task did not modify or clean
   them.

No setup, Docker mutation, cleanup, or new case execution was performed.
