# Implementation changes

Changed files:

- `src/kalama/remediation/execution_orchestrator.py`: classify successful
  command output as `NO_OP` when it contains the explicit scope-exclusion or
  unchanged markers; retain command result separately.
- `src/kalama/verification/orchestrator.py`: preserve per-CVE action effects,
  expose `no_op_cves`, and prevent all-NO_OP actions from being represented as
  patch success in AFTER evidence.

No historical output, state file, Docker resource, evaluator threshold, or
exploit result was changed. The change is intentionally narrow and backward
compatible for ordinary successful actions.
