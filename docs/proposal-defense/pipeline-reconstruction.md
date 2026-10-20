# Pipeline reconstruction: `lkW2d`

This is a reconstruction from artifacts, not a replay. No exploit, patch, Docker run, or live API call was performed.

| Stage | Trigger/input | Output/tool | Human gate / failure | Evidence and status |
|---|---|---|---|---|
| Intake | Existing local image reference | Canonical image digest and target metadata | Image identity or Docker preflight can fail | run state `images`; `TRIVY_BEFORE`; CODE-SUPPORTED by `src/kalama/runtime.py` and target orchestrator |
| Scan | Source digest | Normalized Trivy report, version `0.74.0` | Parser/scan failure; scanner is inventory evidence, not reachability proof | `trivy/before/scan_...lkW2d.json` |
| Enrichment | Normalized CVEs | NVD-first CVSS, FIRST EPSS, CISA KEV snapshot | Missing/failed enrichment excludes scoring or records issue | Top30 `enrichment_snapshot`; `src/kalama/prioritizer/enrichment.py:404-439` |
| Prioritize | Enriched CVEs | 30 ranked records | Missing required score data cannot be ranked; ties use KEV, EPSS, CVSS, then stable order | `scoring/...top30...json`; `src/kalama/prioritizer/scoring.py:16-51` |
| Resolver | Top-30 records and module metadata | Suggestions/form for 16 module-available CVEs | Human confirmation or skip required; no module is not an exploit failure | resolver artifact, attack form, submission |
| Before exploit | Human-submitted configuration | 3 attempts: 2 successes, 1 inconclusive | Wrong options, no session, check-only, environment error, or missing module | `msf/before/attack_res_...lkW2d.json`; `src/kalama/execution/oracle.py:80-99` |
| Patch discovery/plan | Two successful exploit targets and patch evidence | 8 actions, revision 1 then revision 2 after smoke failure | Human confirms scope, versions, sources, commands and validation | patch discovery/forms/plans |
| Patch execution | Submitted revision-2 plan | Patched image and 8 action records | Command/checksum/list validation can fail; action success is not semantic fix | patch result attempt 2; `src/kalama/remediation/execution_orchestrator.py:118-170` |
| After scan | Patched image digest | Both intended CVEs `FOUND` | Scanner can be `UNKNOWN`; `NOT_FOUND` is required for scanner verification | `trivy/after/verification_...lkW2d.json`: found 2 |
| Re-exploit | Same two configs rebound to after target | 2 complete negative attempts; no sessions | Environment unresolved or inconclusive oracle remains possible | after attack result/config; `reexploit/classifier.py:22-49` |
| Evaluation | Top-N dataset and before/after evidence | 0 verified, 2 inconclusive; no remediation success rate | Conflicting scanner and exploit evidence fails closed | remediation result and run summary |

## Automatic versus human decisions

Automatic behavior includes scan normalization, enrichment, ranking, artifact lineage, config validation, image identity checks, execution-status aggregation, and conservative final classification. Human-controlled behavior is the attack-form selection/confirmation and patch-form scope, versions, command and validation submission. The historical artifacts do not prove that an LLM generated any submitted field.

## What was not proven

The artifacts do not prove that all 30 vulnerabilities were dynamically testable, that all vulnerable WAR occurrences were patched, that the current source code was the run's exact commit, or that a proposal screenshot depicts this run.

