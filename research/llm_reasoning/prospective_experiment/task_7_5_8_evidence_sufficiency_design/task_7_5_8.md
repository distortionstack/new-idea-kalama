# Task 7.5.8 — Evidence Sufficiency Design Section (Kalama / EVVP)

## 1. Scope and non-execution statement

This task writes a design/theory section only. No new experiment was run. No
production code was implemented and no pipeline behavior was modified. No
patch was executed, no Patch Form was submitted, no AFTER scan was run, no
re-exploit was run, and no evaluation was run. UZBL5 was not mutated, and no
VALIDATED remediation Knowledge was written.

All empirical claims below are grounded in existing local research artifacts
from Tasks 7.5.5–7.5.7 (read-only reference; see §3). No web research was
used. The dirty tree was preserved: no reset, clean, stash, checkout,
revert, or delete of unrelated files was performed. Companion files created
in this task: `evidence_sufficiency_section_thesis_draft.md`,
`design_principles.json`, `terminology_glossary.json`,
`production_architecture_implications.json` (§15).

## 2. Problem statement

Scanner findings can identify vulnerable components and sometimes fixed
versions, but they do not by themselves provide enough evidence for safe
remediation. A scanner `FixedVersion` is not equivalent to any of the
following:

- **artifact provenance** — where the fixed artifact lives, who published it,
  and whether it is available;
- **dependency closure** — which companion modules and versions the fixed
  release requires, and whether each resolves;
- **compatibility evidence** — whether the fixed release is a drop-in fix or
  a migration across release lines, plugin APIs, or module alignment;
- **runtime deployment semantics** — how the target runtime (e.g. Tomcat
  appBase exploded-deploy vs WAR expansion, container layout, redeploy
  behavior) must be handled during replacement;
- **executable patch command** — concrete, environment-specific, backup-
  preserving steps grounded in the above;
- **validation procedure** — how to confirm the patch applied (old absent,
  new present with matching hashes), kept separate from scanner-after and
  exploit-after confirmation.

Conflating "the scanner names a fixed version" with "we have a safe patch
plan" is the central error this design prevents.

## 3. Empirical basis from Tasks 7.5.5–7.5.7

**Task 7.5.5 — Evidence-Anchored Patch Reasoning (UZBL5).** Source discovery
was limited to scanner/runtime anchored evidence and deterministic traversal
(136 source records: 97 retrieved, 34 fetch-failed, 1 unanchored rejection
S255, valid:true). Result: 8 Patch Actions, of which 5 became
production-validator ready (2.3.32 line via the frozen S2-048 runtime donor
with local SHA-256 plus upstream equality for struts2-core/xwork-core, and
Tomcat 8.5.20 archive docs S014–S017 grounding WAR-preserve/exploded-patch
procedure) while 3 abstained (`PATCH_STRATEGY_UNRESOLVED`) because the graph
could not reach `ognl:ognl:3.0.21`, `com.thoughtworks.xstream:xstream:1.4.10`
(404s S208–S210, S241–S243), or `org.freemarker:freemarker:2.3.23` (404s
S226–S228). Scanner/reference traversal proved useful but insufficient, and
the safe abstention — refusing the unanchored registry guess — was itself a
valuable outcome.

**Task 7.5.6 — Upstream Source Resolver Design Review
(DESIGN_ACCEPTED_WITH_CHANGES).** Scanner references alone are too narrow:
they describe the vulnerable project, not the third-party artifacts its
fixed releases depend on. PURL-derived native registry roots are acceptable
only under guardrails: typed, deterministic, parented to package-identity
evidence, restricted to allowed operations (metadata, POM, artifact,
checksum), with metadata links as candidates until corroborated promotion.

**Task 7.5.6A — Upstream Source Resolver Replay
(REPLAY_SUPPORTS_DESIGN_WITH_GUARDRAILS).** Replay-only, no production code.
Deterministic Maven native registry roots derived from already-anchored POM
dependency coordinates reached all three missing dependencies
(POM+JAR+JAR.sha1, each SHA-1 sidecar matching, 15 replay sources, 0
failures, valid:true) without any LLM-invented website; deps.dev records
(R005/R010/R015) stayed candidate-only corroboration. Source reachability
improved deterministically. No remediation success, validator readiness, or
command claim was made — reachability only.

**Task 7.5.7 — Evidence Sufficiency Ablation (ABLATION_DESIGN_READY).**
Retrospective L0–L5 × C1–C10 matrix over UZBL5. Minimums: version
recommendation L1; artifact provenance L3; dependency closure L3; executable
patch plan L3∧L4∧L5 jointly. Deterministic components: retrieval, source
graph, validation. LLM role: downstream interpretation/drafting only; never
creates roots or promotes authority.

## 4. Evidence sufficiency model

- **L0 — Scanner + Runtime Only.** Contains: frozen findings, normalized
  vulns, package/version/FixedVersion/path/PURL, runtime inventory, image
  identity, JAR paths, local hashes, observed layout, BEFORE-exploit scope.
  Supports: C1 identification, version candidates (C2 partial), local donor
  observation. Cannot safely support: confirmed version selection, provenance,
  closure, strategy, procedure, validation, validator readiness. Retrieval:
  pipeline freeze (deterministic, no interpretation).
- **L1 — L0 + Scanner Reference Graph.** Adds: References[]/PrimaryURL/
  DataSource traversal plus runtime-derived URLs and deterministic children.
  Supports (observed): advisory-confirmed version selection (S2-045→2.3.32,
  S2-052→2.3.34-REST, 2.5.10.1 notes), direct-artifact provenance/integrity
  where the graph reaches, partial procedure via archive docs. Cannot support:
  third-party closure when the graph has no allowed route (the 3/8 gap).
  Retrieval deterministic; version/module alignment needs interpretation.
- **L2 — L1 + Advisory Authority Query.** Adds deterministic NVD/OSV/GHSA/KEV
  queries; references typed, third-party links not auto-promoted. Supports:
  stronger affected/fixed confidence and vulnerability context. Cannot
  support: artifacts, closure, or commands beyond L1. Retrieval
  deterministic; advisory meaning needs interpretation.
- **L3 — L2 + PURL / Native Registry Roots.** Adds Kalama-owned deterministic
  registry mappings with typed operations, including dependency-coordinate
  roots parsed from anchored metadata. Supports (replay-observed): provenance,
  integrity sidecars, and closure completion for all three blockers. Cannot
  alone support: compatibility judgment or safe command emission (replay
  explicitly stopped before commands). Retrieval deterministic.
- **L4 — L3 + Upstream Project Documentation / Release Notes.** Adds promoted
  homepage/docs/repo/security pages, release notes, changelogs, migration
  guides under deterministic promotion rules. Supports: version-selection
  rationale, compatibility interpretation, module-alignment decisions.
  Discovery deterministic; upgrade/migration reasoning requires
  interpretation.
- **L5 — L4 + Runtime Vendor Documentation.** Adds vendor docs from proven
  runtime identity/derived URLs. Supports: runtime-specific patch procedure,
  deploy/redeploy behavior, validation procedure, safe command drafting.
  Discovery deterministic; procedure drafting requires interpretation over
  cited docs.

## 5. Capability classes

C1 Vulnerability Identification · C2 Version Recommendation · C3 Artifact
Provenance · C4 Artifact Integrity · C5 Dependency Closure · C6 Patch
Strategy · C7 Patch Procedure/Command · C8 Validation Procedure/Command ·
C9 Safe Abstention · C10 Production Validator Readiness. Full definitions in
`terminology_glossary.json`; per-cell L0–L5 status in the Task 7.5.7 matrix.

These must be separated because they have different evidence requirements
and different failure costs. In particular: **version recommendation is
weaker than executable remediation** (naming 2.3.34 proves nothing about
whether its OGNL/XStream companions resolve or whether the REST-module move
is compatible); **validator readiness is weaker than remediation success**
(5/8 READY in 7.5.5 coexisted with STEP_5_PATCH through STEP_8 NOT_STARTED —
validation checks form and evidence linkage, not outcome); and **remediation
success requires AFTER scan + re-exploit + evaluation** (§7.7), never a
pre-execution evidence claim.

## 6. Central design principle

> "LLM Patch Assist must not be activated merely because a scanner reports a
> fixed version. It requires sufficient evidence for artifact provenance,
> dependency closure, compatibility, and runtime deployment semantics."

Operationally: deterministic retrieval gathers evidence; the source resolver
controls where evidence may come from; the LLM reasons only over the
resulting evidence pack; a human reviews the proposal; the validator checks
Patch Form consistency and evidence linkage; and the EVVP pipeline validates
remediation empirically through scan-after, re-exploit, and evaluation. Each
stage can only pass forward what the previous stage proved — the LLM cannot
backfill missing provenance, the human cannot authorize an unevidenced
command, the validator cannot certify remediation, and no pre-execution
stage can claim exploit-validated success.

## 7. Separation of responsibilities

**7.1 Scanner.** Identifies candidate vulnerable components and provides the
seed: CVE, package, installed version, path, fixed-version candidates,
references. It does not prove executable remediation — its FixedVersion is
an input to confirmation, not a patch plan.

**7.2 Source Resolver.** Derives allowed source roots from scanner
references, runtime URLs, PURL/native-registry mappings, and advisory
queries. Never uses LLM-created domains. Records derivation, parent
evidence, authority class, confidence, and allowed operations for every
root in the source graph.

**7.3 Remediation Evidence Retriever.** Retrieves advisories, POMs, artifacts,
checksums, release notes, and runtime docs from allowed roots only;
classifies promoted vs candidate sources; hashes all bytes with timestamps
and redirect chains; records missing evidence with attempted source IDs
(e.g. 404s) instead of silently dropping gaps; returns
EVIDENCE_GRAPH_INSUFFICIENT when closure cannot complete under policy.

**7.4 LLM Patch Assistant.** Interprets retrieved evidence, drafts Patch Form
suggestions, and may propose command/validation_command only when the
L3+L4+L5 threshold is met per action. Cannot create roots, promote
authority, treat candidates as authority, emit below-threshold commands, or
mark remediation verified.

**7.5 Human Gate.** Reviews suggestions with evidence citations; approves,
edits, or rejects; explicitly approves major-version moves; owns final
confirmation and submits the Patch Form.

**7.6 Production Validator.** Validates Patch Form structure and per-field
evidence support (uncited non-UNKNOWN field fails; blocked actions must carry
null commands with typed reason codes). Does not prove remediation success.

**7.7 EVVP Evaluation.** Executes the approved patch, then establishes
remediation empirically: AFTER scan, re-exploit with the originally
confirming exploit, and final remediation classification including
behavior-regression observation.

## 8. Evidence thresholds for production

- **A. Version suggestion: L1 or higher** (advisory-confirmed; scanner field
  alone is candidate-only).
- **B. Artifact/provenance suggestion: L3** (native-registry or reviewed
  donor-exception evidence per artifact).
- **C. Dependency closure suggestion: L3** (every closure member resolved or
  explicitly missing-coded).
- **D. Command suggestion: L3 + L4 + L5 jointly** per action.
- **E. validation_command suggestion: L3 + L5**, plus L4 where
  compatibility/version behavior affects validation.
- **F. Abstain when:** missing artifact, missing checksum, incomplete closure,
  unclear deployment semantics, major-version compatibility uncertainty, or
  any step requiring an unanchored source. Abstention shape: null commands,
  UNKNOWN/INSUFFICIENT_EVIDENCE fields, typed codes
  (`PATCH_STRATEGY_UNRESOLVED`, `DEPENDENCY_ARTIFACT_UNREACHABLE`,
  `SOURCE_PATH_MISSING`, `COMPATIBILITY_UNKNOWN`, `PROCEDURE_UNKNOWN`),
  per-action missing-evidence records, run-level WAITING_FOR_USER_INPUT.

## 9. Source authority and provenance

Discoverability is separate from authority: that a page exists, looks
official, or is linked from metadata does not authorize it. PURL-derived
native registry roots are allowed because they are deterministic identity
derivations — the package coordinates imply the registry path by
ecosystem construction, not by model guess — and they authorize only typed
operations on exact coordinates. deps.dev is discovery/corroboration, never
final artifact authority. Metadata-embedded homepage, repository, tracker,
and docs links are candidates until deterministic promotion
(corroboration + namespace alignment) accepts them. Every source needs
parent evidence, byte hash, timestamp, redirect chain, and authority class;
graph validation fails otherwise.

## 10. Safe abstention as a positive result

Task 7.5.5's 3/8 abstention was not failure but boundary enforcement working
as designed: the graph demonstrably stopped (logged 404s), the single
unanchored guess (S255) was rejected and left unused, and the blocked
actions carried explicit missing-evidence records instead of fabricated
commands. A system that emits plausible patches without provenance is more
dangerous than one that reports "version known, artifacts unreachable, here
is exactly where I looked." Abstention preserved auditability, gave
operators actionable codes, and scoped the principled fix (deterministic
native-registry roots) that 7.5.6A later validated — without ever weakening
the boundary.

## 11. Production architecture implication

```text
Scanner / Runtime Evidence
        ↓
Source Root Derivation  (Upstream Source Resolver, deterministic)
        ↓
Remediation Evidence Retriever  (typed retrieval, promoted vs candidate, hashed)
        ↓
Evidence Pack  (frozen bundle + validated source graph + missing-evidence records)
        ↓
LLM Patch Assistant  (downstream interpretation/drafting, threshold-gated)
        ↓
Human Gate  (review, approve/edit, own confirmation, submit)
        ↓
Production Validator  (structure + evidence-linkage checks)
        ↓
Patch Execution  (post-approval only)
        ↓
AFTER Scan + Re-exploit + Evaluation  (remediation success classified here)
```

The LLM sits downstream of evidence, never upstream of source discovery:
information flows from machine-derived sources through retrieval into a
frozen pack, and only then to model reasoning, human judgment, mechanical
validation, authorized execution, and empirical confirmation. No stage can
be skipped or reordered without breaking the property the next stage
assumes.

## 12. Risks and guardrails

- **Package metadata poisoning** (malicious POM fields) → parse structurally;
  never trust metadata links as authority; hash raw bytes; corroborate.
- **Malicious homepage/repository fields** (fork/mirror/lookalike org, e.g.
  `http://`/`git@` forms seen candidate-only in replay) → candidate-until-
  promoted; require namespace alignment + independent corroboration.
- **Dependency confusion** (public name shadowing private package) →
  ecosystem-scoped resolution, exact-coordinate paths, namespace checks.
- **Repository takeover** (abandoned/transferred/renamed packages) →
  timestamp evidence, compare registry vs advisory vs scanner identity,
  NEEDS_REVIEW on disagreement.
- **Redirect abuse** → record full chains; downgrade unexpected cross-domain
  transitions to review triggers.
- **deps.dev over-trust** → hard rule: corroboration only, never artifact
  authority; its links unpromoted by default.
- **Unanchored source laundering** (LLM URL → "candidate" → root) → resolver
  inputs are structured evidence only; LLM URLs are rejected observations;
  promotion rules are deterministic and logged.
- **LLM memory leakage** (guessed versions, checksums, URLs) → per-field
  citation requirement; uncited non-UNKNOWN fails validation; Kalama owns
  the registry map.
- **Conflating validator readiness with remediation success** → three
  separate report fields forever: source coverage vs validator readiness vs
  remediation success (§5, §7.7); never infer the third from the first two.

## 13. Thesis-ready summary

Scanner output identifies vulnerability but cannot, by itself, justify
remediation: fixed-version strings carry no provenance, closure,
compatibility, procedure, or validation content. The evidence sufficiency
model (L0–L5) makes this explicit by grading, for each capability class
(C1–C10), which evidence tier actually supports it — identification at L0,
advisory-confirmed versions at L1, provenance/integrity/closure at L3,
compatibility at L4, and runtime procedure at L5, with executable commands
gated on the conjunction of the last three. Deterministic components own
everything upstream of reasoning — root derivation, retrieval, hashing,
graph validation, confidence rules — while the language model works
strictly downstream, interpreting evidence, drafting threshold-gated
proposals, and abstaining in typed, auditable form when evidence runs out.
Human review authorizes, mechanical validation checks form and linkage, and
only the exploit-validated pipeline — rescan plus re-exploit plus
evaluation — may declare remediation successful. The case-study sequence
bears this out: bounded traversal earned five validator-ready actions and
three principled abstentions; a deterministic resolver extension closed the
artifact gap without admitting a single model-invented source; and the
ablation fixed the thresholds that turn this episode into reusable method.

## 14. Next work

1. Implement a research-prototype (non-production) Source Resolver per the
   7.5.6 schema with Kalama-owned registry maps and deterministic promotion
   rules.
2. Generate L0–L5 evidence packs automatically for a held-out CVE/image
   (prospective, not UZBL5).
3. Run a prospective evaluation comparing LLM output quality (supported
   fields, abstention correctness, fabrication count) across evidence
   levels.
4. Execute patches only after the L3+L4+L5 threshold plus human review and
   validator pass.
5. Measure validator readiness vs actual remediation success (AFTER scan +
   re-exploit) to quantify the §5 gap empirically.

## 15. Files and git status

New research-only folder
`research/llm_reasoning/prospective_experiment/task_7_5_8_evidence_sufficiency_design/`:

- `task_7_5_8.md` (this design/theory section)
- `evidence_sufficiency_section_thesis_draft.md` (standalone academic prose:
  scanner limits, sufficiency levels, resolver rationale, LLM role, safe
  abstention, EVVP validation; no remediation-success overclaim from 7.5.6A,
  no readiness-equals-correctness claim, no all-ecosystem generalization)
- `design_principles.json` (7 principles with task grounding)
- `terminology_glossary.json` (13 terms)
- `production_architecture_implications.json` (components, thresholds, root
  classes, LLM/human/validator/evaluation roles)

No previous task outputs overwritten. No production code, pipeline, UZBL5,
or Knowledge state modified. Pre-existing dirty-tree files elsewhere were
left untouched; per-folder status captured at verification time below.

TASK_7_5_8_STATUS: DESIGN_SECTION_READY
