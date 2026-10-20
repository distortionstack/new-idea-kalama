# Phase 4 Report — Cross-Arm Evaluation and Findings (EXP-PROC-7X9D-01)

Evaluation of frozen artifacts only. No proposal/review revision, no
retrieval, no execution, no scan, no re-exploit, no Knowledge write, no
production change in this phase.

## 1. Experiment identity

EXP-PROC-7X9D-01 / run 6WUM1 / action patch-001: apache2
2.4.10-10+deb8u12, CVE-2019-10092 (+incidental CVE-2019-10098), three
frozen arms ARM_A_L3, ARM_B_L3_L4, ARM_C_L3_L4_L5. Research question: does
adding genuine L5 runtime/vendor procedure evidence enable
evidence-grounded command/validation_command proposals without increasing
unsupported claims or human refinement?

## 2. Input-integrity verification

- Pack SHAs match Phase-1 identities exactly: A 0c5e127b…, B 768320fa…,
  C 403dce78… (recomputed from frozen bytes).
- Proposal→pack binding verified in all arms (candidate_binding.pack_sha256
  equals pack hash).
- Review→pack and review→proposal bindings verified in all arms against
  frozen file bytes.
- Agent validation PASS and Human Review validation PASS recorded in all
  arms; validation files record no sibling reads, no retrieval, no
  execution — zero recorded isolation violations.
- ONE input issue recorded (not repaired): ARM_B agent_validation.json
  records proposal_sha256=df6e1aae…, which does not match the frozen
  proposal file bytes (aca2e0df…). The file's own validation notes its
  hash method (canonical re-serialization rather than frozen file bytes),
  so this is an agent-side digest-method deviation, NOT post-freeze
  tampering: the Phase-3 reviewer independently recomputed file bytes
  (aca2e0df…), bound the review to them, and current bytes still hash
  aca2e0df…. Review↔proposal↔pack bindings in ARM_B are sound on actual
  bytes. Status: EVALUATION_COMPLETE_WITH_INPUT_ISSUES for this single
  recorded deviation; no arm excluded.
- Cosmetic variances (recorded, non-blocking): some validation files use
  lowercase experiment_id and result-vs-overall key names; ARM_C review
  validation leaves human_review_sha256 as "pending". None affect metrics.

## 3. Per-arm metrics

| Metric | ARM_A_L3 | ARM_B_L3_L4 | ARM_C_L3_L4_L5 |
|---|---|---|---|
| Proposed fields | 6/8 applicable | 6/8 applicable | 8/8 applicable |
| Accepted without edit | 6 | 6 | 8 |
| human_refinement_rate | 0.0 (0/6) | 0.0 (0/6) | 0.0 (0/8) |
| major_refinement_rate | 0.0 | 0.0 | 0.0 |
| unsupported_claim_rate | 0.0 (0/9) | 0.0 (0/9) | 0.0 (0/9) |
| citation_validity_rate | 1.0 | 1.0 | 1.0 |
| abstention_correctness | 1.0 (2/2) | 1.0 (2/2) | null (no abstentions) |
| agent_supported_field_rate | 0.75 | 0.75 | 1.0 |
| validator before → after | PASS → PASS | PASS* → PASS | PASS → PASS |
| semantic_critical_edits | 0 | 0 | 0 |

(*B-before carries the §2 digest-method note; all other checks PASS.)
Source: arms/*/evaluation_result.json (mechanically derived; see
derivation fields therein).

## 4. Field-coverage comparison

| Field | ARM_A_L3 | ARM_B_L3_L4 | ARM_C_L3_L4_L5 |
|---|---|---|---|
| fix_type | PROPOSED_ACCEPTED (C) | PROPOSED_ACCEPTED (C) | PROPOSED_ACCEPTED (C) |
| strategy | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| target_version | PROPOSED_ACCEPTED (deb8u16) | PROPOSED_ACCEPTED (deb8u16) | PROPOSED_ACCEPTED (deb8u16) |
| artifact_source | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| source_identifier | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| build_system | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| command | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | PROPOSED_ACCEPTED |
| validation_command | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | PROPOSED_ACCEPTED |
| notes | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |

Proposed counts 6 → 6 → 8; accepted-without-edit 6 → 6 → 8. Nothing was
edited or rejected in any arm. fix_type=C proposed and accepted in all
arms — the 7.5.9B SYSTEM_CONTRACT_GAP does not reproduce here, consistent
with the semantic-ablation finding that contract exposure resolves it
(contract was a separate input in all three arms).

## 5. Human-refinement comparison

NO_EDIT over PROPOSED fields: 6/6, 6/6, 8/8 — refinement 0.0 in all arms,
major 0.0. As in 7.5.9B, the experiment shows refinement preserved at
zero while coverage grew (6→8), not refinement reduced.

## 6. Unsupported-claim comparison

Zero unsupported claims in all 27 field reviews
(unsupported_claim_detected=false throughout; no failed-source citation,
no invented URL/checksum, no command smuggling into gated arms). Quality
floor held constant as coverage grew from 6 to 8 proposed fields.

## 7. Abstention comparison

- Correct gate-honoring abstentions: command + validation_command in A and
  B (4/4 accepted) under INSUFFICIENT gates — abstention preserved due to
  gate (pattern E).
- Zero abstentions in C: both procedural fields became PROPOSED under
  SUPPORTED gates and were accepted.
- Abstention correctness 1.0 where abstentions exist; null (not 0) in C
  where none exist.

## 8. Evidence-level capability transitions (L3 → L3+L4 → L3+L4+L5)

- A. Capability already supported at L3: fix_type, strategy,
  target_version, artifact_source, source_identifier, notes (6 fields).
- B. Interpretation/rationale improved with L4: identical coverage (6
  fields), but target_version citations deepen to deficiency records
  (S010/S013/S014/S021 vs A’s S008/S010/S011) and strategy cites DLA
  records (S006/S012/S013) — the deficient-fix rationale is now
  evidence-backed. Capability unchanged despite richer evidence (pattern D
  on counts, B on rationale).
- C. New proposal capability enabled only after L5: command +
  validation_command move ABSTAINED→PROPOSED and are accepted without
  edits (pattern C). Coverage 6→8 with refinement and unsupported rates
  unchanged at zero.
- E. Abstention preserved due to gate in A/B for both procedural fields.
- No causation claimed beyond this controlled single case.

## 9. Scanner FixedVersion vs corrected-version finding

Scanner FixedVersion: 2.4.10-10+deb8u15. Agent selected 2.4.10-10+deb8u16
in ALL THREE arms — including ARM_A, from L3 index evidence alone
(live index carries deb8u16; deb8u15 stanza absent/superseded). L4 added
the authoritative rationale (DLA-1900-2: deb8u15 fix incomplete +
balancer-manager regression, bug 941202; deb8u16 correct upstream patch),
visible in B/C citations. The surrogate Reviewer accepted deb8u16 with
NO_EDIT in all arms. This demonstrates, for this case, that Scanner
FixedVersion functioned as evidence input rather than an unquestionable
remediation answer — the Agent reconciled scanner, index, and (where
visible) release evidence toward the corrected revision. Not generalized
beyond this case.

## 10. Command capability result

Frozen transition (mechanical):
- A command = ABSTAINED / ABSTENTION_ACCEPTED (gate INSUFFICIENT).
- B command = ABSTAINED / ABSTENTION_ACCEPTED (gate INSUFFICIENT).
- C command = PROPOSED / NO_EDIT (gate SUPPORTED).
Identical transition for validation_command. Answer to the research
question for this case: YES — L5 changed command capability. Accepted C
command (frozen): apt-get update, exact-pinned install of apache2 and
pinned siblings at deb8u16, apache2ctl configtest, apache2ctl graceful —
each operational element traceable to pack procedure claims (S015–S018).
Accepted C validation_command (frozen): apache2ctl configtest.
Permitted case-specific support: "Under this case and contract,
procedure-level L5 evidence enabled the Agent to construct command and
validation_command proposals accepted by the surrogate Reviewer without
edits." NOT claimed: universal necessity/sufficiency, operational success.

## 11. Validation-command limitation

Acceptance of `apache2ctl configtest` does NOT mean: exploit blocked,
remediation VERIFIED, AFTER scan passes, or all validation dimensions
covered. The accepted validation checks configuration syntax ONLY — it
does not verify installed version output (e.g. -v) or service/process
state, though that evidence (S017/S020) was available in the arm. The
Reviewer accepted syntax-only validation as sufficient for the field
semantics (NO_EDIT, no missing-evidence flag on the field). This
experiment measures proposal/review quality, not remediation success.

## 12. Threats to validity

Single held-out Apache/Debian case; OpenCode as Agent and surrogate
Reviewer (sub-agents orchestrated from one parent process — process
isolation does not prove independent model memory; same model family may
create reviewer-alignment bias toward acceptance, consistent with three
straight zero-refinement outcomes); no real human review-time
measurement; no patch execution; no AFTER scan; no exploit retest; no
remediation-success measurement; Debian package-manager case may not
generalize to Maven/source-build/image replacement; contamination
PARTIALLY_CONTAMINATED at shared-image level; Semantic Contract is
Kalama-owned and designed by the same research team; acceptance of
command does not establish operational correctness; accepted validation
is narrower (syntax-only) than complete remediation validation; ARM_B
agent-side digest-method deviation (§2) shows surrogate-agent harness
imperfections that review binding contained but did not prevent.

## 13. Conclusions permitted (tested against artifacts)

1. L3 was sufficient for non-procedural remediation fields in this case
   (6/8 applicable proposed and accepted in ARM_A). SUPPORTED.
2. L4 provided authoritative interpretation of the deficient
   scanner-fixed revision and supported the corrected deb8u16 choice
   (B/C citations + rationale; A already selected deb8u16 on index
   evidence). SUPPORTED.
3. Without L5, command and validation_command remained correctly
   abstained (A/B, 4/4 accepted abstentions). SUPPORTED.
4. With L5, command and validation_command became PROPOSED (C, 8/8
   applicable). SUPPORTED.
5. The surrogate Reviewer accepted the ARM_C command and
   validation_command without edits (NO_EDIT, zero unsupported flags).
   SUPPORTED.
6. Unsupported claim rate remained zero across arms (0/27). CONFIRMED.
7. Human refinement remained zero across proposed fields (0/6, 0/6, 0/8).
   CONFIRMED.
8. Evidence growth increased proposal coverage (6→8) without reducing
   observed review acceptance in this case. SUPPORTED.

Main hypothesis (evidence growth increases accepted-without-edit coverage
while holding zero unsupported claims and zero refinement):
SUPPORTED_BY_THIS_CASE. Command hypothesis (L5 enables accepted
command/validation proposals): SUPPORTED_BY_THIS_CASE.

## 14. Conclusions not permitted

Remediation succeeded; CVEs actually fixed; command executes
successfully; L5 universally necessary or sufficient; ecosystem
generalization; production readiness; human reviewer performance/time;
exploit validation success; anything beyond this case. In particular, the
accepted command's operational correctness is untested (no execution),
and the accepted validation is syntax-only (§11).

## 15. Production/research implications

- Research architecture validated end-to-end for one case: Evidence Pack
  (case facts) + Semantic Contract (system meaning) → gated Agent
  proposal → surrogate review → deterministic evaluation, with
  abstention discipline holding where evidence was thin and command
  capability unlocking where procedure evidence was genuinely present.
- No production change implied: Task 6 MVP still forbids LLM command
  content; the gated-command policy remains a researched future
  candidate. Any path to production would additionally need: execution
  trials, human-factors measurement, multi-ecosystem replication, and
  hardening of surrogate-harness details (cf. §2 digest deviation).
- Metric convention preserved from 7.5.9B (NOT_APPLICABLE excluded from
  supported-field denominator; refinement over PROPOSED only).

## 16. Recommended next experiment

Do not execute; recommendation only, pending findings above: a second
procedure-capable held-out case in a DIFFERENT ecosystem (e.g. a
Maven/source-build case with upstream build-procedure docs, or an image
case with vendor replacement procedure) to test whether the L5→command
transition replicates outside Debian packaging — ideally one where the
evidence also supports a materially contestable command choice, so the
reviewer must do more than accept (testing the zero-refinement streak
against reviewer-alignment bias). A safe execution trial under explicit
human confirmation should wait until at least two ecosystems replicate.
