# Decision Ownership — Patch Assist Prototype

Research-only. No role may silently perform another role's responsibility.
"LLM: forbidden" means the Agent must neither perform the decision nor
influence it outside its owned suggestion fields.

| Decision | Owner | Agent (ROLE A) | Human reviewer (ROLE B) | Notes |
|---|---|---|---|---|
| SOURCE ROOT CREATION | Deterministic system | Forbidden | Reviews pack quality only; must not add roots | Roots derive from scanner references, runtime URLs, PURL/registry maps, advisory queries |
| SOURCE AUTHORITY PROMOTION | Deterministic system/policy | Forbidden | Forbidden to promote during review | Promoted vs CANDIDATE_ONLY per confidence rules + corroboration |
| EVIDENCE RETRIEVAL | Deterministic system | Forbidden | Forbidden; reviewer must not fetch new evidence | All bytes hashed, parented, timestamped |
| EVIDENCE SUFFICIENCY STATUS | Deterministic policy | Cannot override | Cannot override; may judge quality, not status | Gates from Task 7.5.7 thresholds (L1/L3/L3+L4+L5) |
| TARGET VERSION INTERPRETATION | Agent suggestion | Suggest with citations | Review / approve / edit | Minimum L1 advisory confirmation |
| PATCH STRATEGY | Agent suggestion when evidence permits | Suggest; abstain if gate INSUFFICIENT | Review / approve / edit | FixType/strategy pairing constraints apply |
| ARTIFACT SET | Agent suggestion from retrieved evidence | Suggest exact retrieved artifacts only | Review / approve / edit | No invented URLs, checksums, or versions |
| DEPENDENCY CLOSURE | Deterministic evidence + Agent interpretation | Interpret retrieved POM/metadata; list unresolved explicitly | Review / approve / edit | Incomplete closure → typed missing-evidence, command blocked |
| COMMAND DRAFT | Agent only when evidence threshold permits (L3+L4+L5) | Draft or abstain (null + reason code) | Final authority | Current production Task 6 MVP forbids LLM command entirely; prototype studies the gated future policy (see architecture.md §8) |
| VALIDATION COMMAND DRAFT | Agent only when evidence threshold permits (L3+L5 [+L4]) | Draft or abstain | Final authority | Same policy-delta note as command |
| SUBMISSION | Human only | Forbidden | Owns (surrogate records decision; real submission stays with the human operator) | Agent output is a suggestion, never a submission |
| PATCH EXECUTION | Production pipeline after human submission | Forbidden | Forbidden in prototype | Out of scope; no execution in this research |
| REMEDIATION SUCCESS | EVVP AFTER scan + re-exploit + evaluation | Forbidden from declaring | Forbidden from declaring pre-execution | Validator readiness ≠ remediation success |

Ownership violations (e.g. a proposal citing a source not in the pack, a
review silently adding evidence, a success claim before evaluation) are
recorded as evaluation defects: unsupported_claim / invalid_evidence_reference.
