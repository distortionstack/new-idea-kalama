# Metrics audit: `lkW2d`

## Reconciliation

| Reported number | Raw evidence | Meaning | Verdict |
|---|---|---|---|
| Top-N = 30 | `TOP30_BEFORE.artifact.top_n_requested=30`, `top_n_returned=30` | 30 ranked CVE records were returned | VERIFIED |
| Eligible cases = 3 | Before result: `attempted=3` | Three human-selected candidates were executed, not three eligible cases in the full Top-30 | CONTRADICTED if phrased as “three eligible”; VERIFIED as attempts |
| Successful exploits = 2 | Before summary: `EXPLOIT_SUCCEEDED=2` | Attributable sessions for CVE-2017-5638 and CVE-2017-9805 | VERIFIED |
| Successful patches = 8 | Patch result attempt 2: `actions=8`, `succeeded=8` | Eight plan actions mechanically succeeded; six are `SCOPE_EXCLUDED_NOOP`/presence guards | VERIFIED mechanically; misleading semantically |
| Re-exploit attempts = 2 | After summary: `attempted=2`, `selected=2` | Both previously successful CVEs were retested | VERIFIED |
| Final = INCONCLUSIVE | Remediation result: `targets=2`, `verified=0`, `inconclusive=2` | Both targets had scanner/exploit evidence conflict | VERIFIED |

## What happened to the other 27?

The before result was: 2 successes, 1 inconclusive, 14 `NO_MSF_MODULE`, and 13 `USER_SKIPPED`; these sum to 30. The evaluation exclusions report 14 no-module, 13 skipped, and 1 unattributed-impact record, leaving only 2 binary-metric-eligible cases. Therefore the other 27 were not exploit-tested: 14 lacked a Metasploit module and 13 were skipped by the human submission. The third attempted case was inconclusive and excluded from binary metrics.

Coverage is `2/30 = 6.67%` (`evaluation/metrics_2026-09-08_lkW2d.json`). Precision@30 is recorded as 1.0 only within the limited empirically eligible sample; recall and F1 are unavailable. Do not present Precision@30 as “30 vulnerabilities validated.”

## Patch semantics

Eight successes means eight shell/action records returned success and local validation passed. It does not mean eight CVEs disappeared, eight packages were updated, or eight vulnerabilities were remediated. The plan changed selected libraries in S2-045 and S2-052; actions for other occurrences were explicit no-op scope guards (`full-pipeline-demo/lkW2d-root-cause-analysis.md:55-66`).

## Why final status was inconclusive

For both CVEs the trace is:

`BEFORE EXPLOIT_SUCCEEDED` → `PATCH SUCCEEDED` → `AFTER scan FOUND` → `AFTER exploit EXPLOIT_FAILED / NOT_VULNERABLE` → `INCONCLUSIVE`.

The classifier treats a negative exploit result as insufficient when the scanner still finds the intended CVE; `src/kalama/reexploit/classifier.py:22-49`. This is a deliberate fail-closed rule, not a contradiction to be silently resolved.

## Important internal inconsistency

The state contains `STEP_5_PATCH=NOT_STARTED` while `STEP_5_PATCH_PLAN` and `STEP_5_PATCH_EXECUTION` are `SUCCEEDED`. The source defines both the legacy umbrella and sub-stages (`src/kalama/state/models.py:25-34`); reporting should describe the sub-stages and retain the umbrella warning, not call patching unstarted.

