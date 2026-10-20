# Task 7.5.7 — Fresh Evidence Sufficiency Ablation Design (Kalama LLM Patch Assist)

## 1. Scope and non-execution statement

This is a research design / replay-planning task. No production resolver code was
implemented. No patch was executed. No Patch Form was submitted. No AFTER scan
was run. No re-exploit was run. No evaluation was run. No VALIDATED remediation
Knowledge was written.

UZBL5 was used only as a retrospective case-study basis. UZBL5 was not mutated,
its pipeline was not rerun, its proposal was not improved, and no new network
evidence was created except by read-only reference to already-established
artifacts. All level-by-level capability judgments for L2–L5 beyond observed
L1/L3-replay facts are explicitly marked as estimates/projections.

Inputs (read-only, hashes as recorded in prior reports):

- `PATCH_REASONING_SEED/manifest.json` SHA-256 `89386175433caf5b6db9b0123a9c430e62aa030809d4cbcb6aadc1380a790130`
- Baseline `source_graph.json` SHA-256 `82af3843d8d5980c2f50458b4a964d3c9d6b9d5b528097da7e21ca3d1c2d49b2` (136 records: 97 retrieved, 34 fetch-failed, 1 unanchored-rejected S255, 0 missing parents, valid:true)
- Baseline proposal SHA-256 `8a8897233c3982e4f436b0e299819b184c030c4a856accda071fe995e934a457` (8 actions: 5 READY, 3 WAITING with `PATCH_STRATEGY_UNRESOLVED`)
- `missing_evidence.json`: `DEPENDENCY_ARTIFACT_UNREACHABLE` (ognl:ognl:3.0.21, xstream:1.4.10 for patch-004/008; freemarker:2.3.23 for patch-007) + `SOURCE_PATH_MISSING`
- Task 7.5.6 design review verdict: `DESIGN_ACCEPTED_WITH_CHANGES`
- Task 7.5.6A replay: 15 sources (3 derived roots, 12 retrieved, 0 failed, valid:true); all 3 missing coords POM+JAR+SHA1 reachable with SHA-1 match; verdict `REPLAY_SUPPORTS_DESIGN_WITH_GUARDRAILS`

Dirty tree was preserved. No reset, clean, stash, checkout, revert, or delete of
unrelated files was performed.

## 2. Research question

Not "can the agent patch this target if it can research freely?" but:

**At what evidence level can the agent produce each class of remediation output
(C1–C10) without fabricating unsupported facts?**

Core hypothesis: scanner/runtime evidence alone suffices for vulnerability
identification and partial version recommendation, but not for a safe executable
patch plan. The ablation determines which additional layers (advisory authority,
native registry, upstream docs, runtime vendor docs) are actually necessary for
each output class.

## 3. Evidence levels L0–L5

- **L0 — Scanner + Runtime Only.** Allowed: frozen scanner findings, normalized
  vulns, package/version/scanner-FixedVersion/path/PURL, runtime inventory,
  image identity, JAR paths, locally computed hashes, observed deployment
  layout, BEFORE exploit evidence. Forbidden: opening references, advisories,
  registries, POM/artifact/checksum-from-publisher, upstream or vendor docs.
- **L1 — L0 + Scanner Reference Graph.** Adds: References[]/PrimaryURL/
  DataSource traversal + runtime-derived URLs (e.g. `TOMCAT_TGZ_FALLBACK_URL`)
  with deterministic children. Forbids PURL-derived registry roots unless they
  appear through the graph, arbitrary registries, LLM-invented sites.
  This level ≈ Task 7.5.5.
- **L2 — L1 + Advisory Authority Query.** Adds deterministic NVD/OSV/GHSA/KEV
  queries from CVE/package identity; advisory references become typed candidate
  roots; third-party links not auto-promoted.
- **L3 — L2 + PURL / Native Registry Roots.** Adds Kalama-owned deterministic
  PURL→registry mappings; typed ops (metadata, POM, artifact, checksum);
  dependency-coordinate roots when coords are parsed from anchored metadata.
  Registry homepage/repo/docs links are candidates, not authority.
  This level ≈ design supported by Task 7.5.6A.
- **L4 — L3 + Upstream Project Docs / Release Notes.** Adds promoted homepage,
  docs, source repo, security page, release notes, changelogs, migration guides
  via deterministic confidence rules; metadata-only links need corroboration.
- **L5 — L4 + Runtime Vendor Documentation.** Adds vendor docs from proven
  runtime identity/derived URLs (e.g. Tomcat deployer docs, base-image docs).

## 4. Capability classes C1–C10

C1 Vulnerability Identification · C2 Version Recommendation · C3 Artifact
Provenance · C4 Artifact Integrity · C5 Dependency Closure · C6 Patch Strategy ·
C7 Patch Procedure/Command · C8 Validation Procedure/Command · C9 Safe
Abstention · C10 Production Validator Readiness (validator-ready ≠ remediation
correct; see §10/G).

## 5. Scoring rubric

- `SUPPORTED` — sufficient and directly attributable to cited source(s).
- `PARTIALLY_SUPPORTED` — some fields supported, material gaps remain (must
  carry caveats + UNKNOWNs).
- `INSUFFICIENT_EVIDENCE` — cannot safely produce; fields stay
  UNKNOWN/INSUFFICIENT_EVIDENCE, commands stay null.
- `UNSUPPORTED_FABRICATION_RISK` — would require guessing/memory/unanchored
  sources; forbidden.
- `NOT_APPLICABLE` — not relevant for this action/case (justify).

Tracked per level: supported/unknown/fabricated counts, correct abstentions,
provenance completeness, external-root / retrieved / promoted-vs-candidate
counts, validator readiness. Full rubric + counts: `capability_scoring.json`.

## 6. UZBL5 retrospective ablation matrix

Full cell-level matrix (status + justification + source + caveat) is
`evidence_level_matrix.json`. Summary:

| Level | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | C10 |
|---|---|---|---|---|---|---|---|---|---|---|
| L0 | SUP | PART | PART | PART | INSUFF | PART | INSUFF | INSUFF | PART | INSUFF |
| L1 (≈7.5.5) | SUP | SUP | PART | PART | PART | PART | PART | PART | SUP | PART (5/8) |
| L2 | SUP | SUP | PART | PART | PART | PART | PART | PART | SUP | PART (5/8 est.) |
| L3 (≈7.5.6A) | SUP | SUP | SUP | SUP | SUP | SUP | PART | PART | SUP | PART (source 8/8; validator still 5/8 observed) |
| L4 | SUP | SUP | SUP | SUP | SUP | SUP | SUP* | PART | SUP | PART |
| L5 | SUP | SUP | SUP | SUP | SUP | SUP | SUP | SUP | SUP | SUP (per-action passable) |

SUP=SUPPORTED, PART=PARTIALLY_SUPPORTED, INSUFF=INSUFFICIENT_EVIDENCE.
`*` L4 C7 SUPPORTED only jointly with L5 procedure; see Q6.

Key retrospective anchors: L1 reached advisories (S001/S002), Struts tags,
staging POM/JAR/checksums (S013/S100–S156), Tomcat docs (S014–S017), donor
equality for struts2-core/xwork-core 2.3.32 (S102/S113 + artifact_integrity.json),
and correctly abstained on 3 actions (404s S208–S210/S226–S228/S241–S243;
S255 rejected). L3 replay reached all 3 missing coords with SHA-1 match
(xstream `dfecae23…`, ognl `f9db8f1e…`, freemarker `cd143cd8…`; R002–R015).

## 7. Minimum evidence level findings

1. **VERSION_RECOMMENDATION: L1.** Scanner FixedVersion (L0) gives candidates
   only; S2-045/S2-052 + version notes at L1 confirm per-CVE/module selection.
   L2 adds corroboration, not the minimum.
2. **ARTIFACT_PROVENANCE: L3** (general case; 5 donor-covered 2.3.32 actions
   were partial already at L1 via S2-048 donor + staging repo).
3. **DEPENDENCY_CLOSURE: L3.** Coords visible at L1 but unresolvable; L3
   dependency-coordinate roots complete the closure.
4. **EXECUTABLE_PATCH_PLAN: L3 (draftable) + L4/L5 (safely emittable).**
   Production gate: L3 ∧ L4 ∧ L5 per action before `command`/
   `validation_command` may be suggested.
5. **L3 sufficient for the 3 blockers?** Yes for source/artifact/integrity
   reachability (3/3 POM+JAR+SHA1, SHA-1 match); no for automatic validator
   readiness (commands undrafted in replay by design).
6. **L3 alone enough for safe commands?** No. L3 = what to install; L4 =
   whether the jump is compatible; L5 = how to install in this runtime.
   UZBL5's 5 ready commands already depended on partial-L5 Tomcat docs.
7. **Deterministic vs LLM:** deterministic = identity normalization, advisory/
   registry/metadata/POM/checksum retrieval, redirect recording, domain
   classification, graph build+validation, hashing, confidence rules, policy
   rejection. LLM-assisted (downstream only) = advisory/note interpretation,
   tradeoff reasoning, procedure drafting from evidence, abstention
   explanation, review notes. LLM never creates roots or promotes authority.
8. **Mandatory before command suggestion:** L3 ∧ L4 ∧ L5 jointly (narrow
   reviewed donor-exception allowed; see production_recommendations.json B).
9. **UNKNOWN unless L4/L5:** compatibility/migration/upgrade rationale (L4);
   deploy/redeploy/backup/WAR-handling/smoke criteria (L5); `command` and
   `validation_command` stay null until L3+L4+L5 jointly hold.
10. **When insufficient:** abstain on blocked fields (null + typed code), keep a
    partial proposal for supported actions, request human input
    (`WAITING_FOR_USER_INPUT` + `missing_evidence`), mark unsupported fields
    UNKNOWN/INSUFFICIENT_EVIDENCE, retain candidate-only sources as
    considered-but-not-trusted. Never guess. (UZBL5 positive control: 5 READY +
    3 WAITING, S255 rejected-not-used.)

Machine-readable: `sufficiency_findings.json`.

## 8. Which levels are deterministic vs LLM-assisted

L0–L3 retrieval mechanics are fully deterministic (Kalama-owned maps, typed
ops, hashed bytes, rule-based confidence/promotion). L4/L5 add deterministic
discovery + promotion rules around upstream/vendor docs. LLM interpretation
enters only downstream of a validated evidence pack (compat reading, strategy
tradeoffs, procedure drafting, abstention narratives). The LLM is never in the
root-derivation or authority-promotion path. (Per Task 7.5.6 §6.)

## 9. Findings from Task 7.5.5 and Task 7.5.6A integrated into the matrix

- 7.5.5 explains the L1 row: 8 actions, 5 READY via donor+advisory+procedure
  evidence, 3 abstained on `DEPENDENCY_ARTIFACT_UNREACHABLE` /
  `SOURCE_PATH_MISSING` / `PATCH_STRATEGY_UNRESOLVED`; S255 rejection proves
  the boundary held.
- 7.5.6A explains the L3 row: the gap was a missing allowed route (staging-only
  policy), not missing upstream artifacts; deterministic native-registry roots
  parented to anchored POM coords closed all 3 with integrity match and zero
  policy violations — while explicitly not claiming validator readiness.
- Together they validate the hypothesis gradient L0 < L1 < L3 < L4+L5 and fix
  the L3-gate (source-complete) vs L4/L5-gate (procedure-safe) distinction that
  structures the production recommendations.

## 10. Production recommendations

Machine-readable: `production_recommendations.json`. Summary:

- **A. Minimal pack for Patch LLM Assist:** frozen scanner+runtime seed (incl.
  PURL, BEFORE-exploit scope) + L1 typed traversal + L2 advisory queries + L3
  native-registry typed retrieval + L4 promoted docs + L5 runtime-vendor docs,
  all under a validated source graph (parentage, hashes, redirect chains).
- **B. Minimal pack for allowing commands:** per-action L3 (every closure
  artifact has metadata+artifact+checksum with hash match) ∧ L4 (version backed
  by advisory+release-note evidence; major-move approval workflow) ∧ L5
  (runtime deploy/backup/WAR procedure cited; validation_command = absence-of-old
  + presence+hash-of-new; AFTER-scan/re-exploit kept separate). Donor-exception
  only with byte-equality (or fully hashed frozen donor) + L5 docs + human review.
- **C. Optional:** KEV (where applicable), deps.dev corroboration (never
  authority), unproven base-image docs, release-note smoke criteria.
- **D. Mandatory:** seed+PURL+scope, advisory confirmation (L1 min, L2
  preferred), L3 artifact+checksum per closure member, closure attestation or
  typed missing-evidence, L4 compat basis, L5 procedure, graph valid:true.
- **E. Guardrails:** Kalama-owned registry map; structured-evidence resolver
  inputs; derivation+parentage on every root; metadata links candidate-until-
  promoted; deps.dev corroboration-only; redirect review; validation failures on
  missing parent/hash/unapproved transition; evidence-pack-only LLM inputs;
  report UNTRUSTED/NEEDS_REVIEW/rejected; per-field citation or validator fail.
- **F. Missing evidence in Form/UI:** null commands (never placeholders), typed
  reason codes, per-action missing[]+evidence[]+impact records, explicit
  UNKNOWN/INSUFFICIENT_EVIDENCE with blocking level, per-action READY vs
  WAITING with run-level WAITING until all resolved, candidate-vs-promoted
  separation.
- **G. Separation:** source coverage (L1: 5/8 actions; L3 replay: 8/8
  source-reachable) vs validator readiness (UZBL5: 5/8 READY; replay: still 5/8
  observed) vs remediation success (NOT_STARTED; never inferred).

## 11. Risks and limitations

- L2/L4/L5 rows are projections: advisory queries, full upstream-doc
  promotion, and generalized vendor-doc retrieval were designed but not
  executed on UZBL5 (only partial precedents S001/S002/S004–S007/S014–S017).
- Replay covered 3 coords' POM/JAR/SHA1 only; deeper transitive closures below
  those POMs were not enumerated — production needs recursion + depth policy.
- SHA-1 sidecars are registry integrity signals, not modern digests; record
  both sidecar and locally computed SHA-256.
- deps.dev/POM metadata links remain poisoning vectors (fork/mirror/takeover,
  `http://`/`git@` forms observed as candidate-only in replay) — promotion
  rules + namespace corroboration are load-bearing.
- Donor-pattern success (5/8) is UZBL5-specific (co-resident S2-048); do not
  generalize into "donor replaces registry."
- Validator readiness ≠ remediation correctness; AFTER-scan, re-exploit, and
  app-behavior stages are separate and were NOT_STARTED.

## 12. Next experiment suggestion

**Task 7.5.8 — L3→L5 command-drafting gate replay (still no execution):**
starting from the L3 replay evidence pack, (a) retrieve L4 release/compat
notes for 2.3.34 and 2.5.10.1 under promotion rules, (b) retrieve L5 Tomcat
8.5.20 deployer procedure under runtime-identity derivation, (c) draft (but do
not submit/execute) commands + validation_commands for patch-004/007/008, (d)
run read-only production-validator checks, (e) record which of the 3 convert to
READY vs remain WAITING and why. Success = all new citations parented +
validator delta attributable to L4/L5 evidence, not memory. Stop before Patch
Form submission, patch execution, AFTER scan, re-exploit, evaluation, Knowledge
writes.

## 13. Git status and files created/modified

New research-only folder `research/llm_reasoning/prospective_experiment/task_7_5_7_evidence_sufficiency/`:

- `task_7_5_7.md` (this report)
- `evidence_level_matrix.json` (L0–L5 × C1–C10 retrospective matrix)
- `capability_scoring.json` (rubric, metrics, separation rule)
- `sufficiency_findings.json` (Q1–Q10 + hypothesis verdict)
- `production_recommendations.json` (packs A–G)

No production code modified. No UZBL5 artifact modified. No patch executed,
no Patch Form submitted, no AFTER scan, no re-exploit, no evaluation, no
Knowledge write. Pre-existing dirty-tree files outside this folder were left
untouched (see `git status --short` output captured at verification time).

TASK_7_5_7_STATUS: ABLATION_DESIGN_READY
