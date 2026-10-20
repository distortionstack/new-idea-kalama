# Root-cause analysis: `lkW2d`

Investigation only. No implementation, historical artifact, Docker resource,
exploit, or patch was changed.

## 1. Executive findings

| Issue | Root cause | Confidence |
|---|---|---|
| AFTER scan still finds both CVEs | The patch plan deliberately left most vulnerable WAR occurrences unchanged. Only selected S2-045/S2-052 libraries were replaced; Trivy still sees old Struts libraries in the image, including S2-033/S2-037 and many other applications. | `CONFIRMED_ROOT_CAUSE` |
| AFTER exploits failed | They ran against the recorded patched container and produced complete negative observations (`SAFE`, no new session, no error). This supports blocked exploitability, but the scanner contradiction prevents a positive remediation claim. | `CONFIRMED_ROOT_CAUSE` for observed result; `UNRESOLVED` for whether all vulnerable paths were fixed |
| 8/8 patch success | Success means each shell command exited 0 and its local validation command passed. Several actions are explicit `SCOPE_EXCLUDED_NOOP`; this is execution success, not vulnerability-remediation success. | `CONFIRMED_ROOT_CAUSE` |
| `STEP_5_PATCH` remains `NOT_STARTED` | The state model has a legacy umbrella enum plus separate `STEP_5_PATCH_PLAN` and `STEP_5_PATCH_EXECUTION` stages. Current orchestrators write only the sub-stages. | `CONFIRMED_ROOT_CAUSE` |

## 2. Evidence inventory and timeline

Primary directory: `output/2d8ru-struts2-fullpipeline/`.

| Time (UTC) | Stage | Evidence | Identity/result |
|---|---|---|---|
| 2026-09-08 22:54–23:58 | BEFORE target, scan, resolver, exploit | `state/run_lkW2d.json`, `trivy/before/scan_2026-09-08_lkW2d.json`, `resolver/resolver_2026-09-08_lkW2d.json`, `msf/before/attack_res_2026-09-08_lkW2d.json` | source digest `7aa386b4...e47db`; container `victim-lkW2d`, IP `172.18.0.18`; both selected exploits succeeded |
| 2026-09-09 02:59–03:05 | Patch retry attempt 2 | `patch/forms/patch_form_lkW2d_r2.yaml`, `patch/plan/patch_plan_lkW2d_r2.json`, `patch/results/patch_result_2026-09-08_lkW2d_attempt_2.json` | patch workspace from source image; 8 actions, all exit 0 |
| 2026-09-09 03:07–03:09 | AFTER target and exploit | `resolver/config/exploit_config_after_2026-09-08_lkW2d.json`, `msf/after/attack_res_2026-09-08_lkW2d.json` | patched digest `e15d5edf...40bec`; container `victim-after-lkW2d`, IP `172.18.0.5`; both complete negatives |
| 2026-09-09 03:09 onward / final artifact | AFTER scan and evaluation | `trivy/after/scan_2026-09-08_lkW2d.json`, `trivy/after/verification_2026-09-08_lkW2d.json`, `verification/remediation_result_2026-09-08_lkW2d.json`, `evaluation/run_summary_2026-09-08_lkW2d.json` | 2 found; 0 verified; both final statuses `INCONCLUSIVE` |

The artifact index in `state/run_lkW2d.json` links these artifacts by run ID,
schema, path, timestamp, and SHA-256. The BEFORE/AFTER exploit configs also
record equivalent invariant hashes for each CVE.

## 3. AFTER scan investigation

BEFORE Trivy scans the source digest `2d8ru/struts2@sha256:7aa386b4...e47db`.
The relevant findings are Maven JARs:

- `CVE-2017-5638`: `org.apache.struts:struts2-core`, fixed versions
  `2.3.32` or `2.5.10.1`, with occurrences under S2-009, S2-015, S2-016,
  S2-019, S2-032, S2-033, S2-037, S2-045, S2-046, S2-052, and S2-053.
- `CVE-2017-9805`: `org.apache.struts:struts2-rest-plugin`, fixed versions
  `2.3.34` or `2.5.13`, with occurrences including S2-033, S2-037, S2-045,
  and S2-052.

The AFTER scan is explicitly against
`kalama/struts2@sha256:e15d5edf...40bec`, not the source image. Its verification
summary is `found: 2, not_found: 0, unknown: 0`.

The plan explains the result. Actions 1–3 and 5–7 are commands named
`SCOPE_EXCLUDED_NOOP` and only list existing old JARs. Action 4 replaces
libraries in S2-045 and S2-052. Action 8 replaces `struts2-rest-plugin` in
S2-045 and S2-052. Thus the image still contains vulnerable occurrences in
other WARs. This is a confirmed incomplete-scope cause, not stale scanner data:
the AFTER artifact carries the patched image digest and the same vulnerable
package paths/versions remain observable.

## 4. AFTER exploit investigation

The AFTER environment validation is valid for both CVEs and records the same
patched image ID `sha256:e15d5edf...40bec`, container `victim-after-lkW2d`, IP
`172.18.0.5`, network `kalama-net`, and run ID `lkW2d`.

Both configurations reference the BEFORE config and have
`same_invariant_config: true`. The Metasploit output is a complete negative:
exit code 0, explicit module check, “target is not exploitable/not vulnerable,”
exploit attempted, no session created, and `session_evidence.attribution` is
`NO_NEW_SESSION`. There is no recorded environment error or timeout.

Therefore the failure was not merely a transport failure. Under the current
oracle contract it is a valid `NOT_VULNERABLE` observation. However, because
Trivy still reports the CVEs, the remediation comparator sets
`evidence_conflict: true` and final status `INCONCLUSIVE`. The artifacts do not
prove that every vulnerable application path was blocked; they only prove the
tested configurations did not create sessions on the patched container.

## 5. Patch execution investigation

Attempt 2 is linked to attempt 1 by `retry.mode = EDIT_PLAN`, reason
`FORCED_POST_PATCH_SMOKE_FAILED`, and `retry_of` equal to the previous result
hash. All eight actions have exit code 0 and result `SUCCEEDED`.

The important distinction is effect:

- Actions 1–3, 5–7: `SCOPE_EXCLUDED_NOOP ...`, `ls` old JAR, then
  `*_UNCHANGED_OK`. These verify presence, not replacement.
- Action 4: downloads and checksum-verifies replacement Struts ecosystem JARs,
  removes old libraries, and copies replacements into S2-045 and S2-052.
- Action 8: verifies and installs `struts2-rest-plugin-2.3.34.jar` into S2-045
  and S2-052.

The patch result's `validation_evidence` is a file-list/checksum validation in
the patch workspace, not a scan of every WAR and not an exploit-based proof.
The executor writes action success from command execution (`src/kalama/remediation/execution_orchestrator.py:118-170`),
while `src/kalama/verification/comparison.py:73-77` separately marks scanner
remediation verified only when the intended CVE is `NOT_FOUND`.

## 6. State machine investigation

`src/kalama/state/models.py:25-34` defines both legacy `STEP_5_PATCH` and the
sub-stages `STEP_5_PATCH_PLAN` and `STEP_5_PATCH_EXECUTION`.

The current remediation planner requires the legacy boundary to be
`STEP_5_PATCH` with `PATCH_NOT_INTEGRATED`, then marks only
`STEP_5_PATCH_PLAN` succeeded and advances to `STEP_5_PATCH_EXECUTION`
(`src/kalama/remediation/orchestrator.py:82-87, 282-290`). The execution
orchestrator similarly marks only `STEP_5_PATCH_EXECUTION` succeeded and moves
to AFTER scan (`src/kalama/remediation/execution_orchestrator.py:168-171`).

Thus `STEP_5_PATCH = NOT_STARTED` is expected legacy-umbrella behavior in this
pipeline version, not evidence that patch execution did not happen. It mainly
affects presentation and any consumer that incorrectly treats the umbrella as
the authoritative stage; resume/retry paths use the sub-stages.

## 7. Evaluation trace

For each CVE the trace is:

`BEFORE EXPLOIT_SUCCEEDED` → `PATCH SUCCEEDED` → `AFTER scan FOUND` →
`AFTER exploit EXPLOIT_FAILED / oracle NOT_VULNERABLE` → `final INCONCLUSIVE`.

The original remediation artifact records for both CVEs:

```text
after_scan.status = FOUND
after_scan.scanner_remediation_verified = false
after_exploit.disposition = EXPLOIT_FAILED
after_exploit.oracle = NOT_VULNERABLE
comparability.same_invariant_config = true
final.evidence_conflict = true
final.status = INCONCLUSIVE
```

This is the correct conservative classification under the current contract:
the exploit oracle is negative, but the independent scanner evidence is
positive. It is not equivalent to `VERIFIED`.

## 8. Root-cause classification

1. **CVE remains FOUND — `CONFIRMED_ROOT_CAUSE`, high confidence.** The
   patch commands changed only two web applications while the scan covers many
   WAR occurrences; unchanged occurrences remain in the patched image.
2. **AFTER exploit failure — observed cause `CONFIRMED_ROOT_CAUSE`, remediation
   interpretation `UNRESOLVED`, medium-high confidence.** The negative result is
   complete and correctly attributed to the patched container, but it cannot
   establish all vulnerable paths were fixed while scan evidence conflicts.
3. **8/8 versus no validation — `CONFIRMED_ROOT_CAUSE`, high confidence.** The
   counter is shell-command success/checksum/listing success, not a semantic
   vulnerability fix. The result explicitly has `remediation_verified: false`.
4. **Legacy stage inconsistency — `CONFIRMED_ROOT_CAUSE`, high confidence.**
   Separate sub-stage writes leave the umbrella enum untouched by design/current
   implementation.

## 9. Recommended corrective actions

- Environment/configuration: make the patch scope enumerate every vulnerable
  WAR occurrence and require a complete target inventory before execution.
- Patch strategy: reject `SCOPE_EXCLUDED_NOOP` for an intended vulnerable
  occurrence; make the plan fail or request confirmation when replacement scope
  is incomplete.
- Target/evidence: retain per-WAR package inventory, patched container facts,
  and scanner target identity in the final remediation record.
- State machine: either explicitly model `STEP_5_PATCH` as a derived umbrella
  status or remove/rename it so reports cannot imply an unstarted patch.
- Evaluation/reporting: keep the current conflict rule; require scanner
  `NOT_FOUND` plus a valid negative exploit result for `VERIFIED`, and expose
  affected package paths in the final report.

## Direct answers

1. Both CVEs remained found because most vulnerable JAR occurrences were not in
   the patch scope; only S2-045/S2-052 were changed.
2. Both AFTER exploits failed with complete, correctly attributed negative
   observations on the patched container; failure is not itself proof that all
   vulnerable paths were remediated.
3. The eight successes mean six no-op/presence checks plus two-application
   replacement work and validation commands exited successfully.
4. `STEP_5_PATCH` is a legacy umbrella enum left untouched while plan and
   execution sub-stages are updated.
5. Yes. `INCONCLUSIVE` is the correct conservative classification.
6. `lkW2d` is trustworthy as a historical record of a full attempted pipeline,
   but not as a verified successful remediation run.
