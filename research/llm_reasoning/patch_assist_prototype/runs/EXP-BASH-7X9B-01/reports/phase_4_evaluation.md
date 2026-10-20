# Phase 4 Report — Cross-Arm Evaluation and Findings (EXP-BASH-7X9B-01)

Evaluation of frozen artifacts only. No new reasoning, review, retrieval,
revision, execution, submission, scan, re-exploit, Knowledge write, or
production change in this phase.

## 1. Experiment identity

EXP-BASH-7X9B-01 / run B9X4K / action patch-001: bash 4.3-11+deb8u1,
CVE-2019-9924 (+incidental CVE-2016-9401), three frozen arms ARM_A_L1,
ARM_B_L3, ARM_C_L3_L4_L5.

## 2. Input integrity

All pack SHAs match Phase 1 (c7d22143… / 35ee4458… / a780084f…).
Proposal↔pack and review↔proposal↔pack bindings verified True in all arms.
Agent validation PASS and Human Review validation PASS in all arms, with
zero recorded isolation violations. No hash/binding mismatch; no arm
excluded. (Step-1 verification commands and full check listings are
retained in the task transcript; frozen files unmodified.)

## 3. Per-arm metrics

| Metric | ARM_A_L1 | ARM_B_L3 | ARM_C_L3_L4_L5 |
|---|---|---|---|
| Proposed fields | 2/9 | 4/8 applicable | 5/8 applicable |
| Accepted without edit | 2 | 4 | 5 |
| human_refinement_rate | 0.0 (0/2) | 0.0 (0/4) | 0.0 (0/5) |
| major_refinement_rate | 0.0 | 0.0 | 0.0 |
| unsupported_claim_rate | 0.0 | 0.0 | 0.0 |
| citation_validity_rate | 1.0 (5/5) | 1.0 (13/13) | 1.0 |
| abstention_correctness | 1.0 (7/7) | 1.0 (4/4) | 1.0 (3/3) |
| agent_supported_field_rate | 0.2222 | 0.5 | 0.625 |
| validator before → after | PASS → PASS | PASS → PASS | PASS → PASS |
| semantic_critical_edits | 0 | 0 | 0 |

Source: `arms/*/evaluation_result.json` (mechanically derived; see
`derivation` fields therein).

## 4. Field-coverage table

| Field | ARM_A_L1 | ARM_B_L3 | ARM_C_L3_L4_L5 |
|---|---|---|---|
| fix_type | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED |
| strategy | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | PROPOSED_ACCEPTED |
| target_version | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| artifact_source | ABSTENTION_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| source_identifier | ABSTENTION_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |
| build_system | ABSTENTION_ACCEPTED | NOT_APPLICABLE | NOT_APPLICABLE |
| command | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED |
| validation_command | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED | ABSTENTION_ACCEPTED |
| notes | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED | PROPOSED_ACCEPTED |

Proposed counts 2 → 4 → 5; accepted-without-edit 2 → 4 → 5.
Semantic-critical proposed (target_version/strategy/artifact set/command/
validation_command with status PROPOSED): A=1, B=3, C=4 — all accepted
without edit. Capabilities appearing with evidence: version at L1;
provenance/integrity/closure-backed artifact fields at L3; strategy at
L3+L4. Nothing was edited or rejected in any arm.

## 5. Human refinement comparison

NO_EDIT distribution over PROPOSED fields: 2/2, 4/4, 5/5 — refinement 0.0
in all arms, so the experiment shows refinement *preserved at zero* rather
than reduced. accepted_proposal_rate (NO_EDIT / PROPOSED, experiment-only):
1.0 in all arms. Abstentions are not counted as refinement in any rate.

## 6. Unsupported-claim comparison

Zero unsupported claims in all arms (reviewer
`unsupported_claim_detected=false` on all 27 field reviews; frozen
validations confirm no failed-source citation, no invented URL/checksum,
no command smuggling). Quality floor held constant as coverage grew.

## 7. Abstention comparison

- (A) Disappeared with evidence: artifact_source + source_identifier (L1
  abstain → L3 propose+accept on index/artifact evidence); strategy (L1/L3
  abstain → L3+L4 propose+accept on index + DLA backport evidence);
  build_system abstention reclassified to NOT_APPLICABLE at L3 (maven-locked
  vocabulary argument).
- (B) Remained on deterministic gates: command + validation_command in all
  arms (L5 PROCEDURE_UNKNOWN) — correct gate-honoring, accepted 6/6 total.
- (C) Missing remediation evidence: the (A) abstentions above.
- (D) Missing system semantics: fix_type in ALL arms (see §9), and
  contributorily strategy in A/B.

## 8. Evidence-level capability changes

L1→L3 added artifact_source, source_identifier (+ build_system
resolution); L3→L3+L4 added strategy; version and notes present throughout
with deepening citations (2 → 5+ → 7 refs on target_version/notes);
command/validation_command never became proposable (L5 absent). Monotonic,
artifact-derived — not assumed.

## 9. System Contract Gap

fix_type was ABSTAINED in every arm *despite* L3 evidence establishing the
deb OS-package nature of the candidate. Both Agent and Reviewer records
attribute this to the permitted contract input naming FixType{A,B,C}
without a semantic mapping for selecting among them (production audit
defines the enum in `remediation/models.py:10-14`; the FixType A/B/C
meanings live in discovery/executor semantics outside the Agent-visible
pack). Classification: SYSTEM_CONTRACT_GAP, not
EVIDENCE_SUFFICIENCY_FAILURE. Design implication: future LLM Assist input
needs a deterministic semantic contract (enum meanings + fix_type/strategy
compatibility rules, cf. `guidance/patch_proposal.py:80-97`) shipped
alongside — not inside — the remediation Evidence Pack. 7.5.9A contracts
are NOT modified by this finding; it is recorded for future work.

## 10. Command-capability limitation

command and validation_command gates were INSUFFICIENT in every arm, so no
command text was ever proposed, reviewed, or refined.
COMMAND_CAPABILITY_NOT_TESTED_DUE_TO_GATE. Nothing is concluded about
Agent command-drafting ability, L5 necessity, or procedure sufficiency.
A later held-out case with retrievable procedure evidence is required for
that question.

## 11. Threats to validity

Single held-out case; OpenCode as both Agent and surrogate Reviewer
(separate contexts reduce but do not eliminate model-family bias;
reviewer may be overly aligned with Agent interpretation); Debian
OS-package case does not generalize to Maven/source-build/image
replacement; command capability untested; no execution/scan/re-exploit so
no remediation-success signal; no real human review-time comparison;
contamination PARTIALLY_CONTAMINATED at lab-doc level; zero-refinement
outcome may partly reflect reviewer alignment rather than pure proposal
quality. No overclaim is made beyond §12.

## 12. Conclusions permitted

- In this case, accepted-without-edit proposals grew 2→4→5 with evidence
  (version → +artifact set → +strategy).
- Refinement stayed 0.0, unsupported claims 0, citations valid, abstentions
  7/7→4/4→3/3 correct.
- Abstention behaved as designed, including gate-honored command refusal.
- fix_type exposes a system-contract gap, not an evidence gap.

## 13. Conclusions NOT permitted

Remediation success or correctness; command-drafting ability; L5
necessity; generalization beyond this case/ecosystem; human-factors
claims; production readiness.

## 14. Recommended next experiment

A second held-out case where L5 procedure documentation IS retrievable
under policy (e.g. a runtime with vendor docs linked from runtime
evidence), testing whether command/validation_command move from
ABSTENTION_ACCEPTED to PROPOSED_ACCEPTED/EDITED, plus shipment of a
deterministic FixType/strategy semantic contract to retest the §9 gap.

## Interpretation status

Main hypothesis ("increasing evidence coverage increased the number of
Agent-proposed remediation fields accepted without human edits while
maintaining zero unsupported claims and correct abstention behavior"):
SUPPORTED_BY_THIS_CASE (case-specific only).
COMMAND_HYPOTHESIS: NOT_TESTED.
