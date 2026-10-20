# Evaluation Plan — Patch Assist Prototype

Research evaluation only. No patch execution, no AFTER scan, no re-exploit,
no remediation-success claims. Validator readiness ≠ remediation correctness
throughout.

## 1. Primary metrics

Denominator convention: **reviewable proposed fields** = fields with status
`PROPOSED` (excludes `ABSTAINED` and `NOT_APPLICABLE`). Abstentions are
scored separately under abstention correctness.

### 1. Human Refinement Rate

```text
human_refinement_rate = (MINOR_EDIT + MAJOR_EDIT + REJECT) / reviewable proposed fields
major_refinement_rate = (MAJOR_EDIT + REJECT) / reviewable proposed fields
```

Answers: "how much of the agent's proposal had to be touched / substantially
reworked?" Report both; the worked example scores 1/6 ≈ 0.1667 and 0.0.

### 2. Critical Field Accuracy Proxy

Critical fields: `target_version`, `strategy`, artifact/dependency set
(`artifact_source`, `source_identifier`), `command`, `validation_command`.
Report the NO_EDIT / MINOR / MAJOR / REJECT / ABSTENTION_ACCEPTED
distribution over these fields, plus `semantic_critical_edit_count`
(MAJOR_EDIT + REJECT among criticals; example: 0).

### 3. Unsupported Claim Rate

```text
unsupported_claim_rate = unsupported claims / proposed factual claims
```

A claim is unsupported when its value is not directly attributable to its
cited pack sources (wrong source, over-read source, or model-memory fact).

### 4. Citation Validity

```text
citation_validity_rate = valid evidence refs / total refs
```

Covers `missing_citation_count` (PROPOSED factual field with empty refs)
and `invalid_evidence_reference_count` (ref to a source_id absent from the
pack or not supporting the field). Example: 8/8 = 1.0.

### 5. Abstention Correctness

```text
abstention_correctness_rate = accepted abstentions / total abstentions
```

Null when the proposal contains no abstentions. Example: 2/2 = 1.0.
A rejected abstention (agent declined where evidence sufficed) and a missing
abstention (agent guessed where evidence was insufficient) are both defects.

### 6. Validator Readiness

Report `validator_pass_before_review` vs `validator_pass_after_review`
using production validation semantics (structure + evidence linkage, e.g.
codec reasons such as `PATCH_STRATEGY_UNRESOLVED`, confirmation tamper and
`PATCH_EXECUTION_TARGET_INVALID` checks). A pass means "well-formed and
evidence-linked", never "remediation correct".

Also record `agent_supported_field_rate` = PROPOSED / (total fields −
NOT_APPLICABLE) (example 6/8 = 0.75), and `review_duration_seconds` /
`agent_duration_seconds` where measurable.

## 2. Per-field results

`evaluation_result.schema.json` requires a `per_field` entry for every
proposal field (`review_class`, `unsupported_claim`, `citation_valid`).
Do not collapse evaluation into one subjective score.

## 3. Experiment arms (future work — NOT run in this task)

Same underlying vulnerable case across arms where possible; the Agent sees
only the evidence permitted in its arm:

- **ARM A — L1:** scanner/runtime + scanner-reference evidence. Expect version
  suggestions; expect command/validation abstentions.
- **ARM B — L3:** arm A + native registry / artifact / integrity / dependency
  evidence. Expect provenance + closure; commands still gated (L4/L5 absent).
- **ARM C — L3+L4+L5:** arm B + compatibility/release evidence + runtime
  deployment documentation. Only arm in which command/validation_command
  proposals are admissible.

Compare arms on metrics 1–6. The hypothesis: refinement and unsupported-claim
rates fall and abstention correctness stays high as evidence rises — i.e.
evidence completeness dominates output quality.

## 4. Worked example consistency

`examples/evaluation_result_example.json` (ARM_B_L3) is arithmetically tied
to the companion pack/proposal/review examples: 9 fields = 6 NO_EDIT + 1
MINOR_EDIT + 2 ABSTENTION_ACCEPTED; refinement 1/6; critical edits 0;
citations 8/8; abstentions 2/2; validator true → true.
