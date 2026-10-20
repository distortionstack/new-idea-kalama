# Semantic Ablation Report — EXP-BASH-7X9C-SEM-01

## 1. Objective

Test whether the 7.5.9B Phase 4 FixType abstention was caused by missing
remediation evidence or by missing exposure of existing Kalama internal
semantics. No new remediation evidence was acquired; no commands drafted
beyond the existing gate; no prior artifacts modified.

## 2. Exact independent variable

KALAMA_SEMANTIC_CONTRACT_EXPOSURE (contract v1, sha256:51c96caf…).
remediation_evidence_changed=false; semantic_contract_changed=true.

## 3. Evidence-pack identity proof

`arm/evidence_pack.json` is a byte-identical copy of
EXP-BASH-7X9B-01 ARM_C pack (file-hash equality verified at copy time);
inner pack_sha256 recomputes to
a780084f1983f6b2136a90617d359353df034546cd6f4c021e64ababcfc24707,
matching the expected value. Pack unmodified.

## 4. Semantic contract provenance

`semantic_contracts/kalama_patch_semantics_v1.json` (validated PASS):
FixType A/B/C meanings + selection rules from discovery providers
(os_package.py:22-39,270-300; source_build.py:18-24,98-175;
service.py:42-49), strategy enum from remediation/models.py:16-25,
compatibility rules from patch_proposal.py:85-97, build vocabulary from
patch_proposal.py:99-102 + source_build.py, ownership from
patch_proposal.py:26-58, field-design corroboration from
docs/LLM_FIELD_LEVEL_DESIGN.md and docs/LAB_CASES.md. No D value exists;
no case/CVE/remediation facts inside; no external evidence.

## 5. Baseline outcome (7.5.9B ARM_C)

5 PROPOSED (strategy ARTIFACT_REPLACEMENT, target_version,
artifact_source, source_identifier, notes), fix_type ABSTAINED, 1
NOT_APPLICABLE, 2 ABSTAINED (commands); 0 refinement, 0 unsupported,
abstentions 3/3.

## 6. Augmented Agent outcome

6 PROPOSED: fix_type=C (refs SEED-01/S010/S011 + [SEM:v1 fix_types.C]),
strategy=PACKAGE_MANAGER (refs S011/S013 + pairing/compat tags),
target_version/artifact_source/source_identifier/notes as baseline;
build_system NOT_APPLICABLE; command/validation_command ABSTAINED per
INSUFFICIENT gates. Proposal sha
3cd2cc3578d70c9b3770f1ca5a12780df9fc92e9a767a6bf4fadb75540a5c1e1,
frozen + validated PASS. Note: strategy value differs from baseline
(PACKAGE_MANAGER vs ARTIFACT_REPLACEMENT) — both are contract-valid
choices; the comparison of interest is proposed-vs-abstained, and the
reviewer judges the augmented value on its own merits (see §7).

## 7. Human Review outcome

7 NO_EDIT (including fix_type=C and strategy=PACKAGE_MANAGER), 2
ABSTENTION_ACCEPTED (commands). Zero unsupported flags, zero edits,
zero rejects. Validation PASS. Process note: one review attempt bound to
a stale pre-freeze hash was discarded unused; the trial was re-run
against the frozen hash with identical verdicts; no reviewer content was
edited by the experimenter.

## 8. Per-field comparison (baseline → augmented)

fix_type ABSTAINED→PROPOSED(C)/NO_EDIT; strategy PROPOSED→PROPOSED
(value ARTIFACT_REPLACEMENT→PACKAGE_MANAGER, both NO_EDIT in their own
trials); target_version/artifact_source/source_identifier/notes unchanged
PROPOSED/NO_EDIT; build_system N/A unchanged; commands ABSTAINED in both.
Proposed count 5→6; accepted-without-edit 5→6.

## 9. Unsupported claims

Zero in both trials (all reviewer flags false; no failed-source citation,
no invented URL/checksum, no command smuggling, no success claims).

## 10. Refinement comparison

human_refinement_rate 0.0 → 0.0 (0/5 → 0/6); major 0.0 → 0.0.
Refinement preserved at zero while coverage grew by one field.

## 11. Semantic-resolution result

fix_type_baseline_status=ABSTAINED; fix_type_augmented_status=PROPOSED(C);
fix_type_review_class=NO_EDIT; no new unsupported evidence introduced.
semantic_contract_resolution_success=true.

## 12. Threats to validity

One case; OpenCode Agent + surrogate Reviewer (same model family may bias
review toward acceptance); Debian package case only; contract derived by
the same team running the trial (provenance is Kalama-owned, but selection
of excerpts involved judgment); command capability still untested; no
execution/scan/re-exploit; no real human timing; strategy-value divergence
(§6) shows same-evidence choice variation exists and was not adjudicated
against a reference answer (by design — no reference answers in this
protocol).

## 13. Production implication

Recommend future architecture: Evidence Pack (case facts) + Kalama
Semantic Contract (system-language meaning) → LLM Patch Assist, kept as
separate inputs because they answer different questions (what is true
about this case vs what Kalama words mean). No production change in this
task. Note: evaluation_result.json `arm` field carries ARM_C_L3_L4_L5 per
the frozen schema enum (pack lineage); the ablation identity lives in
`experiment_id` EXP-BASH-7X9C-SEM-01.

## 14. Conclusions permitted

With identical remediation evidence, exposing Kalama-owned semantics
resolved the fix_type abstention (→C, accepted unedited) and kept
refinement at zero with zero unsupported claims. Gates held (commands
still correctly refused). SYSTEM_SEMANTICS_EXPOSURE_GAP_RESOLVED for this
case. Hypothesis: SUPPORTED_BY_THIS_CASE.

## 15. Conclusions not permitted

Generalization beyond this case; command-drafting ability; L5 necessity;
production readiness; human-factors claims; remediation success; or that
PACKAGE_MANAGER is uniquely correct (strategy variation under identical
evidence is an open question, §12).
