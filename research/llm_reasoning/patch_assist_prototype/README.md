# Patch Assist Prototype — Research-Only (Task 7.5.9A)

Feasibility/protocol experiment, NOT a human-subject study and NOT a
production LLM integration. No external LLM API; no OpenAI/Anthropic/Gemini/
Ollama integration. No production pipeline changes, no patch execution, no
Patch Form submission, no AFTER scan, re-exploit, or evaluation. UZBL5 and
all prior experiments untouched.

## Purpose

Answer: "Given a controlled Evidence Pack, can an LLM-like agent produce a
Patch Form proposal that requires little human refinement while remaining
fully evidence-grounded and auditable?" — with strict separation of evidence
acquisition, sufficiency gating, agent reasoning, human review, mechanical
validation, and research evaluation.

Prior basis: 7.5.5 (5/8 ready, 3/8 safe abstentions) · 7.5.6 (resolver design
accepted with changes) · 7.5.6A (deterministic replay closed the artifact
gap) · 7.5.7 (L0–L5 × C1–C10 ablation; command needs L3+L4+L5) · 7.5.8
(deterministic retrieval before LLM reasoning; FixedVersion ≠ plan;
readiness ≠ success; abstention is valid).

## Directory layout

```text
research/llm_reasoning/patch_assist_prototype/
  README.md                  this file
  architecture.md            production audit (§1), architecture, data flow, compatibility
  protocol.md                PHASE A (Agent) / PHASE B (Reviewer) isolation procedure
  decision_ownership.md      who owns each decision; LLM-forbidden boundaries
  evaluation_plan.md         metrics, arms ARM_A_L1 / ARM_B_L3 / ARM_C_L3_L4_L5 (future)
  schemas/
    evidence_pack.schema.json
    source_reference.schema.json
    agent_proposal.schema.json
    human_review.schema.json
    evaluation_result.schema.json
  examples/
    evidence_pack_example.json       synthetic L3 pack (RUN-DEMO, CVE-2099-0001)
    agent_proposal_example.json      gated proposal (commands ABSTAINED)
    human_review_example.json        6 NO_EDIT + 1 MINOR + 2 ABSTENTION_ACCEPTED
    evaluation_result_example.json   arithmetically tied metrics
```

## Role separation (summary)

ROLE A (Agent surrogate): frozen pack in → evidence-grounded proposal out;
no web, no history, no gate overrides, no hidden reasoning. ROLE B (Human
Reviewer surrogate): pack + frozen proposal in → per-field review classes
out; no new evidence, no pack edits. Full rules: `protocol.md`;
responsibilities: `decision_ownership.md`. Dual-role leakage is an explicit,
disclosed threat to validity — use a fresh session for ROLE B where possible.

## Schemas

Five JSON Schemas (draft 2020-12) plus four synthetic examples using
placeholder identities (`RUN-DEMO`, `CVE-2099-0001`, `org.example:
example-package`) so no historical remediation answer can leak. The worked
example demonstrates the core gate: an L3 pack (L4/L5 missing) forces
`command`/`validation_command` abstention, the reviewer accepts both
abstentions, and metrics tie out (refinement 1/6, critical edits 0,
citations 8/8, abstentions 2/2).

## Future experiment sequence

1. Build frozen L1 / L3 / L3+L4+L5 packs for one held-out case (new
   prototype packs, not UZBL5 mutation). 2. Run PHASE A per arm. 3. Freeze +
   mechanical validation. 4. PHASE B in fresh sessions. 5. Score with
   `evaluation_result.schema.json`. 6. Compare arms on refinement,
   unsupported-claim, citation, abstention, and validator-readiness deltas.
   Execution, AFTER scan, re-exploit, and Knowledge writes remain out of
   scope until a later authorized task.
