# Task 7.5.2.2 — Historical Human Reasoning Gap Audit

## Executive answer — what did the human actually have to do?

For `lkW2d`, the historical record shows substantially more than typing scalar
form values.  The system had scanner and resolver suggestions, Maven sources
and checksums, and a patch plan; the submitted procedure selected an in-scope
2.3.x closure, preserved the deployment boundary, and later incorporated
dependency changes plus a validation procedure.  The record is consistent with
an iterative response to runtime failures.  It does **not** support automatic
execution: scope approval and submission remained human responsibilities.

`cOqnU` cannot be audited as requested because its exact run state and
run-specific artifacts are not retained in this repository.  A generic mention
in `docs/AGENT_README.md` is not a substitute for historical state.

## Discovery

| Run | Discovery result | State / target | Final recorded state | Quality |
|---|---|---|---|---|
| `lkW2d` | Found exact state, resolver forms/config, attack results, discovery, plans/forms r1+r2, patch results, after scan/re-exploit/evaluation. | `2d8ru/struts2:latest`, source image `sha256:7aa…47db`; after image `kalama/struts2:patched-lkw2d`, `sha256:e15…0bec`. Recorded after container `374091…546fa6`; attempt-2 workspace `bde762…228cd3`. | `STEP_8_EVALUATION`; before 5638/9805 succeeded with attributable sessions; r2 patch executed; after scan still found both intended CVEs and after exploits failed. | DIRECT |
| `cOqnU` | No exact-ID state/manifest/form/result/plan/review artifact found by content search of `output`, `review-bundles`, `diagnostics`, `attack`, `research`, docs and repository files. | NOT_RECORDED | NOT_RECORDED | NOT_RECORDED |

`docs/session-log-2026-09-09.md` gives a secondary retrospective timeline;
the `lkW2d` state and form/result paths listed in `lkW2d/state_inventory.json`
are the primary evidence.

## lkW2d timeline

1. The run was created at `2026-09-08T23:48:31Z`; scan/prioritization selected
   30 CVEs. Resolver at `23:53:03Z` had 16 items waiting for user input.
2. Attack form/submission at `23:53:05Z`/`23:54:53Z`; before result at
   `23:58:35Z` records two `EXPLOIT_SUCCEEDED`, one `INCONCLUSIVE`, 13 skipped.
   The session note identifies 5638 and 9805 as attributable-session successes.
3. Patch planning created eight actions. The system supplied package/version
   candidates, Maven URI/checksum suggestions, and `HUMAN_COMMAND` strategy.
4. r1 submission executed 8/8 actions. A forced post-patch-smoke failure then
   produced r2 `EDIT_PLAN` (`FORCED_POST_PATCH_SMOKE_FAILED`).
5. r2 added a full dependency closure, a run/layout-specific command, and
   validation that checks added/removed libraries and unchanged WAR SHA-256.
   Execution itself succeeded; that is not evidence that remediation verified.

## Attack delta and reuse

The unsubmitted attack form has suggested/default values with no confirmations;
the submitted form/config retains confirmed selections. The material historical
delta is candidate confirmation/selection, plus environment-bound listener
configuration. Exact per-field before/after values are available in the two
YAML documents but are not reconstructed when the submission lacks an explicit
per-field provenance marker; those are `NOT_RECORDED`, not guesses.

The retrospective session note says lkW2d mirrored approved J1Thf
module/protocol/payload choices and used a new LPORT. That is **PARTIAL** reuse
evidence: module/protocol/payload are plausible `SAFE_REUSE_CANDIDATE`s;
IP/LHOST/LPORT are `ENVIRONMENT_BOUND`; `targeturi` is
`REQUIRES_REVALIDATION`. The same note records baseline probes for `/S2-045/`
(302) and `/S2-052/orders/3` (200), supporting path inspection rather than
blind reuse. It does not, by itself, prove every individual copied field.

## Patch delta and runtime trace

The direct r2 form records `2.3.34` for the in-scope core/rest actions,
Maven Central sources, confirmed hashes, and replacement only in the exploded
`S2-045`/`S2-052` `WEB-INF/lib` trees. The supplied command semantically does:
fetch → SHA-1 verify → define two deployment paths → remove obsolete jars →
copy exact closure → inventory. Its validation procedure verifies expected
libraries, absence of superseded jars, and unchanged WAR SHA-256.

The session log records the following progression: `TypePermission` → xstream
1.4.10; `SimpleNode.isSequence` → ognl 3.0.21; `EmptyVisitor` → asm and
asm-commons 3.3; `VERSION_2_3_0` → freemarker 2.3.22. The r2 command contains
exactly those versions. This is **STRONG**, not DIRECT, causal evidence because
the original runtime logs/intermediate forms are not retained as paired lkW2d
artifacts. The same source reports that Maven/POM metadata was examined; r2
form/source/checksum values directly prove use of Maven Central and checksum
verification, but do not themselves prove the human’s source consultation.

The historical evidence supports scanner-fixed-version candidates of 2.3.32
for 5638 and 2.3.34 for 9805. The selected common 2.3.34 is directly in the
form and is consistent with staying on 2.3.x; the fixed-version-policy claim
is **DIRECT** for recorded candidates and **STRONG** for common-version
selection rationale.

## Required final table

| run | phase | field/output | before | after | human_delta | derivation_class | evidence_used | deterministic_possible | current_llm_scope | llm_opportunity | evidence_quality |
|---|---|---|---|---|---|---|---|---|---|---|---|
| lkW2d | attack | candidate selection | waiting for input | 3 attempted, 13 skipped | HUMAN_CONFIRM_ONLY | SELECTION | resolver, form, result | partly | in scope context | KNOWLEDGE_REUSE | DIRECT |
| lkW2d | attack | target/targeturi/rport/payload/protocol | suggested/default | confirmed config exists | NOT_RECORDED per field | NOT_RECORDED | paired forms/config | partly | in scope context | EVIDENCE_EXTRACTION | PARTIAL |
| lkW2d | patch | target_version | 2.3.32 / 2.3.34 candidates | 2.3.34 in scope | HUMAN_EDIT | CROSS_EVIDENCE_SYNTHESIS | plan, r2 form, session note | partly | in scope context | LLM_SYNTHESIS_CANDIDATE | STRONG |
| lkW2d | patch | source/checksum | Maven suggestion | same confirmed | HUMAN_CONFIRM_ONLY | COPY | r2 form | yes | out of current scope for checksum | EVIDENCE_EXTRACTION | DIRECT |
| lkW2d | patch | command | no direct draft recorded | fetch/verify/replace/protect | HUMAN_GENERATED_PROCEDURE | CROSS_EVIDENCE_SYNTHESIS | r2 form, deployment evidence | partly | OUT_OF_CURRENT_LLM_SCOPE | LLM_SYNTHESIS_CANDIDATE | DIRECT |
| lkW2d | patch | validation_command | no direct draft recorded | files/absence/WAR-hash checks | HUMAN_GENERATED_PROCEDURE | CROSS_EVIDENCE_SYNTHESIS | r2 form/result | partly | OUT_OF_CURRENT_LLM_SCOPE | LLM_SYNTHESIS_CANDIDATE | DIRECT |
| lkW2d | revision | dependency closure | not recorded as system proposal | xstream/ognl/asm/freemarker changes | HUMAN_FILLED_GAP | RUNTIME_DIAGNOSIS | session log + r2 form | partly | OUT_OF_CURRENT_LLM_SCOPE | LLM_RUNTIME_DIAGNOSIS_CANDIDATE | STRONG |
| cOqnU | all | all requested outputs | NOT_RECORDED | NOT_RECORDED | NOT_RECORDED | UNSUPPORTED | repository search | unknown | unknown | INSUFFICIENT_EVIDENCE | NOT_RECORDED |

## Work classification and opportunity

- Typing burden: long commands and validation commands.
- Information-search burden: version candidates, artifact locations/checksums,
  deployment inventory, WAR/exploded-app boundary.
- Cross-source synthesis: select one compatible target version and turn
  component/deployment facts into a constrained procedure.
- Runtime diagnosis: map error signatures to dependency adjustments.
- Human-only: approve scope, decide whether to execute, review command safety,
  and submit the form.

Patch-command assistance: **PARTIALLY_SUPPORTS**. One direct historical case
shows a lengthy, evidence-bound command with deployment-sensitive paths and
dependency decisions; it is a strong draft-for-review candidate, never an
automatic-action candidate. Validation-command assistance: **PARTIALLY_SUPPORTS**
for the same reason. The absence of a complete cOqnU record and direct
intermediate logs limits the claim.

## Answers to Q1–Q15

Q1: Resolver knew scanner candidates, module metadata/defaults, package
versions, Maven source/checksum suggestions and patch actions. Q2: the human
confirmed selections and supplied procedures; r2 contains the dependency
closure and validation procedure. Q3: source/checksum/fix-type confirmations
are copy/confirmation. Q4: listener allocation, URL construction, artifact
URL/checksum extraction, and safe no-op guards are deterministic candidates.
Q5: validated module/protocol/payload reuse can be Knowledge-assisted but
target path and network values require revalidation. Q6: common target version,
closure and procedures combine multiple sources. Q7: yes, strong evidence,
though not every original log is retained. Q8: session log plus r2 form
supports the listed dependency changes, with STRONG evidence. Q9: yes for r2:
it combines artifact, checksum, layout, inventory and safety facts; no single
record shows it was copied wholesale. Q10/Q11: partially support human-review
drafting only. Q12: constrained patch/validation procedure drafts and
runtime-diagnosis notes. Q13: command, validation command, dependency revision
and diagnosis note are out of current scope. Q14: yes. Q15: lkW2d r1→r2
dependency/procedure revision is the strongest case; no benchmark was created.

## Limits, safety, and accounting

`cOqnU` is unavailable. No exploit, patch, scanner, Docker target, AFTER run,
or LLM/API was invoked. Historical objects were read only. Files written are
only this audit tree. The worktree was already dirty before the audit; no
existing modification was changed. JSON was syntactically validated after
creation. Production behavior and current LLM field policy are unchanged.

TASK_7_5_2_2_STATUS: HISTORICAL_REASONING_GAP_FOUND
