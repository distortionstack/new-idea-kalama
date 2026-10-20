# Final report

## Result

The current system can demonstrate a complete historical execution, but the
selected run does **not** validate remediation successfully. Run `lkW2d` is
marked `COMPLETED`; all stages from `STEP_2_TARGET_SCAN` through
`STEP_8_EVALUATION` have succeeded status except the legacy `STEP_5_PATCH`
umbrella stage, which remains `NOT_STARTED` while its plan and execution
sub-stages succeeded.

## Timeline and coverage

| Stage | Evidence | Result |
|---|---|---|
| Target scan | `trivy/before/scan_2026-09-08_AoFTs.json` | succeeded |
| Top-N | `scoring/before/top30_2026-09-08_AoFTs.json` | 30 returned; CVE rank 1 |
| Resolver / Attack Form | `resolver/resolver_2026-09-08_AoFTs.json`, form and submission | human review recorded |
| BEFORE exploit | `msf/before/attack_res_2026-09-08_lkW2d.json` | 2 exploits succeeded; 14 no module; 13 skipped |
| Patch planning | discovery, Patch Form, plan, submission | 1 action |
| Patch execution | `patch/results/patch_result_2026-09-08_lkW2d_attempt_2.json` | 8/8 succeeded after retry |
| AFTER scan | `trivy/after/verification_2026-09-08_lkW2d.json` | both CVEs still found |
| Re-exploit | `msf/after/attack_res_2026-09-08_lkW2d.json` | 2 attempts failed |
| Evaluation | `evaluation/run_summary_2026-09-08_lkW2d.json`, metrics | completed; inconclusive |

## Before/after and validation

The source image is digest `7aa386b4...e47db`; the patched image is
`kalama/struts2:patched-lkw2d` with digest `e15d5edf...40bec`.
The AFTER scan reports both CVEs still `FOUND`; AFTER exploitation failed for
both, while remediation is `INCONCLUSIVE` with zero verified targets. The run
therefore demonstrates a completed pipeline with an unsuccessful patch outcome.

## Limitations

There are no real screenshots in this evidence bundle. The original run was
historical and the current Docker daemon is unavailable, so no UI or terminal
replay was possible. DB provenance is unavailable, 29 Top-N entries had no
Metasploit module, and the run warnings explicitly record that BEFORE exploit
and patch boundaries were not fully integrated. These limitations are retained
rather than normalized away.
