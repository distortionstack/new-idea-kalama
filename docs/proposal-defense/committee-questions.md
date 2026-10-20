# Committee interrogation: `lkW2d`

Each answer is deliberately conservative. “Insufficient” means the evidence gap must be admitted, not filled by current-code assumptions.

1. **Which exact run is shown?** `lkW2d` is the strongest complete candidate, but no screenshot is retained; exact screenshot identity is insufficient. Evidence: `run-identification.md`; follow-up: where is the screenshot? Safe answer: it is missing.
2. **What is the run ID?** `lkW2d`, directly in state and artifact index. Follow-up: can it be forged? Safe answer: hashes establish lineage, not independent provenance.
3. **What image was scanned?** Before digest `7aa...e47db`; after digest `e15...40bec`. Evidence: state and Trivy artifacts. Follow-up: exact build provenance? Not retained.
4. **What Git commit ran it?** Current HEAD is `5699dc...`; the run does not record it. Evidence: `git log`, state. Safe answer: exact run commit is unverified.
5. **Why Top-30?** The artifact requests and returns 30 under `kalama-priority-v1`. Follow-up: why 30 scientifically? Evidence supports policy, not empirical weight justification.
6. **What is the scoring formula?** `CVSS + 3*EPSS + 3*KEV_listed`. Evidence: `src/kalama/prioritizer/scoring.py:16-51`. Follow-up: why those weights? Implementation choice only.
7. **Were scores reproducible?** The artifact freezes EPSS and KEV snapshots. Follow-up: external source availability? Snapshot hashes help, but full network provenance is not independently proven.
8. **Why only three exploit attempts?** Human submission selected three; 13 were skipped and 14 lacked modules. Evidence: before attack summary. Follow-up: was this automatic? No, selection required human input.
9. **What happened to the other 27?** 14 no module, 13 user skipped. Evidence: result and metrics exclusions. Follow-up: are they safe? No, untested.
10. **Does 2 successes mean 2/30 success rate?** No; only 2 were metric-eligible, with 6.67% empirical coverage. Evidence: metrics. Follow-up: can precision be generalized? No.
11. **What does EXPLOIT_SUCCEEDED mean?** Attributable impact/session evidence, not just exit code. Evidence: oracle and before result. Follow-up: session logs? Run-specific attack artifact.
12. **What was the third attempt?** `CVE-2017-9791`, INCONCLUSIVE. Evidence: attack delta. Follow-up: why? Attribution/impact was insufficient.
13. **Were failures environment errors?** Before summary records zero environment errors; after records complete negatives. Evidence: run summary. Follow-up: can a false negative remain? Yes.
14. **What exactly are eight successful patches?** Eight plan actions mechanically succeeded in attempt 2. Evidence: patch result. Follow-up: eight CVEs fixed? No.
15. **How many actions were actual replacements?** The audit identifies two targeted replacement actions and six no-op/presence guards. Evidence: patch plan/root-cause report. Follow-up: where are the other occurrences? Still in image.
16. **Why was revision 2 needed?** A forced post-patch-smoke failure caused `EDIT_PLAN` retry. Evidence: patch form metadata. Follow-up: did retry prove remediation? No.
17. **Did patching change the image?** A new patched digest was produced and scanned. Evidence: after Trivy. Follow-up: complete diff? Only recorded scoped validations, not whole-image proof.
18. **Were fixed versions verified?** Commands used checksum/file validation and selected 2.3.34. Evidence: patch form/delta. Follow-up: scanner result? Still FOUND.
19. **Why did scanner still find both CVEs?** Vulnerable occurrences outside S2-045/S2-052 remained. Evidence: root-cause analysis and after scan. Follow-up: stale scan? Digest identity and paths argue against that.
20. **Did re-exploit use the patched image?** The after config and result bind to `e15...40bec` and `victim-after-lkW2d`. Evidence: after artifacts. Follow-up: same target config? `same_invariant_config=true` is recorded.
21. **What does after EXPLOIT_FAILED prove?** Only that the tested configurations produced no attributable session. It does not prove all paths are fixed. Evidence: root-cause analysis. Follow-up: scanner conflict? Causes INCONCLUSIVE.
22. **Why not VERIFIED?** Scanner remained FOUND; classifier requires no conflicting scanner evidence. Evidence: `src/kalama/reexploit/classifier.py:22-49`. Follow-up: is this conservative? Yes.
23. **Why not FAILED?** After exploit did not succeed, so evidence does not show residual exploitability for the tested configs; scanner/exploit conflict is classified INCONCLUSIVE. Evidence: remediation result.
24. **What is remediation coverage?** The global evaluation coverage is 0 for evaluable remediation targets because both targets are inconclusive. Evidence: metrics. Scoped later summary is a different scoped view and must not replace authoritative status.
25. **Was dynamic scanning used?** No run-linked dynamic-probe artifact is present. Evidence: artifact index. Safe answer: not proven for this run.
26. **Was an LLM used?** No run-linked request/provider/response exists. Evidence: artifact index and technical deep dive. Safe answer: LLM use is unverified.
27. **Was human confirmation required?** Yes, attack and patch forms/submissions record human gates. Evidence: form artifacts and resolver state. Follow-up: could the agent act autonomously? Not shown.
28. **Can current code prove historical behavior?** No. Current source is code-supported only; historical execution requires run artifacts. Evidence: audit classification policy. Follow-up: what is direct evidence? Artifact index/results.
29. **Why does STEP_5_PATCH say NOT_STARTED?** It is a legacy umbrella while plan/execution sub-stages succeeded. Evidence: state models and root-cause report. Follow-up: reporting risk? It can mislead unless explained.
30. **Is the run a success?** It is a completed pipeline attempt, not successful remediation. Evidence: final report and remediation result. Follow-up: thesis claim? Defend pipeline observability and fail-closed uncertainty, not patch effectiveness.
31. **Could 8/8 be a misleading metric?** Yes, if interpreted semantically; it is action success. Evidence: patch result and no-op actions. Safe answer: report both mechanical and semantic outcomes.
32. **Is Precision@30=1.0 impressive?** It is limited to two eligible positives and incomplete recall. Evidence: metrics. Safe answer: do not generalize.
33. **Were all scanner findings deduplicated?** The normalized artifact records occurrences and duplicate counts; exact parser behavior is code-supported. Follow-up: does deduplication remove application scope? It can; occurrence paths must be checked.
34. **Can scanner absence prove non-exploitability?** No. Scanner is package evidence; exploit oracle is empirical but target-specific. Evidence: technical deep dive. Follow-up: what is needed? Both coherent after-scan and re-exploit evidence.
35. **Can no after session prove patch success?** No, because scanner still finds both CVEs. Evidence: remediation result. Follow-up: what would be sufficient? `NOT_FOUND` plus valid negative re-exploit under the comparator contract.
36. **Is the run reproducible?** Artifacts make it auditable, but no replay was performed and environment/build provenance is incomplete. Safe answer: reproducibility is unverified.
