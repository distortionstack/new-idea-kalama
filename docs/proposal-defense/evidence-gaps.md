# Evidence gaps and claims that must not be made

## High-priority gaps

1. No original terminal screenshot is retained; screenshot-to-run identity is UNVERIFIED.
2. No exact run-start Git commit is recorded. Current HEAD is only checkout state.
3. Docker daemon/build logs and complete image-layer provenance are unavailable.
4. Database provenance is explicitly warned as unavailable.
5. Only 2 of 30 Top-N records were binary-metric eligible; 28 were not empirically tested.
6. Patch scope covered two applications while the scanner observed many occurrences.
7. The 8/8 counter is mechanical action success, not CVE-removal success.
8. No per-field provenance proves whether an LLM supplied any historical value.
9. Full original runtime logs and intermediate human reasoning are not retained.
10. The metrics/evaluation artifacts were updated on 2026-09-15, so they are not all contemporaneous with the 2026-09-08/09 execution.

## Contradictions to preserve

- `STEP_5_PATCH` is `NOT_STARTED`, while patch-plan and patch-execution sub-stages succeeded.
- After exploit is negative, but after scan still reports both CVEs; the correct result is `INCONCLUSIVE`, not `VERIFIED`.
- “3 eligible” is wrong if it means eligible across Top-30; it is correct only as “3 attempted.”
- “8 successful patches” is wrong if it means 8 CVEs or packages remediated.

## Safe claims

- VIPER completed a recorded end-to-end attempt for `lkW2d`.
- It ranked 30 records, human-selected three exploit attempts, and obtained two attributable before-exploit successes.
- It executed eight patch actions in revision 2 and retested two targets.
- The patched digest was scanned and both intended CVEs remained `FOUND`.
- Re-exploit produced two complete negative observations, but the final remediation result was 0 verified and 2 inconclusive.

## Unsafe claims

Do not claim that VIPER remediated eight vulnerabilities; validated all 30; achieved a 2/3 or 2/30 general exploit success rate; proved the image safe; proved exploitability was removed; demonstrated LLM use; or reproduced the proposal screenshot exactly.

