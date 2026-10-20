# Role Isolation Protocol — Patch Assist Prototype

Surrogate dual-role protocol. NOT a human-subject study. NOT production LLM
integration. No external LLM API is used; "Agent" and "Human Reviewer" are
logical roles executed by OpenCode in separate, isolated steps.

## PHASE A — AGENT (ROLE A: Agent / LLM surrogate)

**Inputs (only):**

- One frozen Evidence Pack (`evidence_pack.schema.json`), verified by
  `pack_sha256`
- `agent_proposal.schema.json`
- Production field constraints summary (eligible vocabulary, forbidden
  fields, fix_type/strategy pairings — see architecture.md §1)

**Forbidden:**

- Web search and any source discovery beyond the pack
- Historical runs (UZBL5, HdiiR, lkW2d), Knowledge remediation answers,
  reference answers not contained in the pack
- Hidden experiment expected results
- Overriding `evidence_sufficiency` gates: if `command`/`validation_command`
  is `INSUFFICIENT`, those fields MUST be `ABSTAINED` (null + typed reason
  code in `abstentions`)
- Hidden chain-of-thought: only `reason_summary` (concise, auditable,
  evidence-oriented) is recorded
- Forbidden proposal content: human confirmation state,
  `remediation_verified`, AFTER/evaluation outputs, execution results

**Output:** one `AgentProposal` conforming to `agent_proposal.schema.json`,
with `candidate_binding.pack_sha256` equal to the input pack hash.

**Freeze:** compute and record `proposal_sha256` before review; ROLE B
receives the frozen bytes.

## PHASE B — HUMAN REVIEWER (ROLE B: Human Reviewer surrogate)

**Inputs (only):**

- The same frozen Evidence Pack
- The frozen Agent Proposal
- `human_review.schema.json` + production field constraints

**Forbidden:**

- Hidden Agent reasoning (only `reason_summary` is visible, as in production)
- Historical successful patch answers or reference solutions
- Changing the Evidence Pack or obtaining new evidence during review
- Silent re-research: the reviewer may judge evidence quality and flag
  `missing_evidence_detected`, but new retrieval belongs to a new pack
  revision, not to the review

**Output:** one `HumanReview` conforming to `human_review.schema.json`,
with per-field `review_class` (NO_EDIT / MINOR_EDIT / MAJOR_EDIT / REJECT /
ABSTENTION_ACCEPTED), `edit_reason`, `evidence_refs`, and the two detection
flags per field.

## Threat to validity (explicit)

Because OpenCode may perform both roles, cognitive leakage is possible:
wording, hypotheses, or conclusions from PHASE A may persist into PHASE B
despite the input restrictions. This protocol is therefore a **surrogate
dual-role protocol, not perfect cognitive isolation**. Mitigations: run
ROLE B in a fresh context/session where possible; pass only the three
frozen artifacts (pack, proposal, schemas) into the review session; record
`reviewer_context` describing the isolation actually achieved. Residual
leakage must be disclosed in any results report, and single-surrogate
findings must not be presented as human-factors evidence.
