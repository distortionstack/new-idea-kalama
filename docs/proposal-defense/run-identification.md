# VIPER prototype run identification

## Verdict

The strongest and only fully evidenced candidate matching a complete pipeline is `lkW2d`. It is not evidence of successful remediation. The repository's own search of 21 state files rejects every other candidate as incomplete or contradictory (`full-pipeline-demo/end-to-end-run-search.md:3-27`). No proposal screenshot was found, so the claim that this is the screenshot run is **UNVERIFIED**.

## Identity

| Field | Evidence | Classification |
|---|---|---|
| Run ID | `output/2d8ru-struts2-fullpipeline/state/run_lkW2d.json`, `run_id=lkW2d` | VERIFIED |
| Created | `2026-09-08T23:48:31Z` | VERIFIED |
| Final state | `STEP_8_EVALUATION`, `COMPLETED` | VERIFIED |
| Source image | `2d8ru/struts2@sha256:7aa386b4...e47db`, linux/amd64 | VERIFIED |
| Patched image | `kalama/struts2:patched-lkw2d@sha256:e15d5edf...40bec` | VERIFIED |
| Recorded after container | `victim-after-lkW2d`, ID `374091...546fa6`, IP `172.18.0.5` | VERIFIED |
| Before container | `victim-lkW2d`, IP `172.18.0.18` | VERIFIED in root-cause audit |
| Trivy | `0.74.0`, before/after artifact metadata | VERIFIED |
| Git commit | `5699dc10bc772e1dc72478e55f3c9b3ac8ef7905` is current checkout HEAD | CODE-SUPPORTED only; not proven run commit |
| Docker image build/tool versions | Image digests are recorded; Docker daemon and full image-build provenance are not | PARTIAL |
| Screenshots | None in the evidence bundle | UNVERIFIED |

The run was updated on `2026-09-15`, after execution, and evaluation artifacts carry that timestamp. Treat the original execution timeline and later evaluation-material regeneration separately (`state/run_lkW2d.json`; `evaluation/run_summary_2026-09-08_lkW2d.json`).

## Artifact inventory

Primary evidence is linked by the run state's artifact index and SHA-256 hashes:

- scan and ranking: `output/2d8ru-struts2-fullpipeline/trivy/before/scan_2026-09-08_lkW2d.json`, `scoring/before/top30_2026-09-08_lkW2d.json`;
- resolver and human gate: `resolver/resolver_2026-09-08_lkW2d.json`, `resolver/forms/attack_form_lkW2d_r1.yaml`, `resolver/forms/submissions/attack_form_submission_lkW2d_r1.yaml`;
- exploit: `msf/before/attack_res_2026-09-08_lkW2d.json`, `msf/after/attack_res_2026-09-08_lkW2d.json`;
- patch: `patch/discovery/discovery_2026-09-09_lkW2d.json`, patch form/plan/result revisions 1 and 2;
- verification: `trivy/after/verification_2026-09-08_lkW2d.json`, `verification/remediation_result_2026-09-08_lkW2d.json`;
- evaluation: `evaluation/run_summary_2026-09-08_lkW2d.json`, `evaluation/metrics_2026-09-08_lkW2d.json`.

## Historical versus later features

The record proves the historical run used Trivy, priority-v1, resolver forms, Metasploit, patch execution, after-scan, re-exploit and evaluation. Current dynamic-probe and later LLM research files are not evidence that those features executed in `lkW2d`. The run warning `DB_PROVENANCE_UNAVAILABLE` also prevents a database-backed provenance claim.

