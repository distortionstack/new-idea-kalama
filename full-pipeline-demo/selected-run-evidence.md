# Selected-run evidence

No run qualifies, so this is a rejection audit rather than a successful
walkthrough.

## `lkW2d` — closest candidate

Source state: `output/2d8ru-struts2-fullpipeline/state/run_lkW2d.json`.
It contains artifacts for target identity, BEFORE Trivy scan, Top-30,
resolver/Attack Form, BEFORE exploit, remediation discovery, Patch Form and
submission, Patch Plan, patch execution, AFTER scan, AFTER exploit, and
evaluation.

The two exercised CVEs were `CVE-2017-5638` and `CVE-2017-9805`. BEFORE exploit
status was successful for both. Patch attempt 2 reports 8/8 actions succeeded.
However, AFTER verification reports `found: 2`, while AFTER exploit reports two
failed attempts and remediation status is `INCONCLUSIVE` for both. No
authoritative positive remediation validation exists.

## `AoFTs` — complete but contradictory

The run has all stage artifacts, but `CVE-2015-1427` has AFTER scan
`NOT_FOUND`, AFTER exploit `EXPLOIT_SUCCEEDED`, and remediation `FAILED`.
Therefore it cannot qualify under the task's explicit requirements.
