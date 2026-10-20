# Architecture — Patch Assist Prototype (research-only)

No production code is modified, no LLM provider is integrated, nothing is
executed. This prototype studies the question: "Given a controlled Evidence
Pack, can an LLM-like agent produce a Patch Form proposal that requires
little human refinement while remaining fully evidence-grounded and
auditable?"

## 1. Current Production Contract Audit

Audited 2026-09-18 against the repository (field inventory only; policy
unchanged).

**Patch Form envelope** (`src/kalama/remediation/confirmation.py:22-24`,
builders in `remediation/orchestrator.py:114-144`,
`remediation/confirmation_orchestrator.py:51-62`,
`remediation/retry_orchestrator.py:324-353`):
`schema` (`kalama.patch-form/v1`, `resolution/artifacts.py:24`), `run_id`,
`phase` (`"patch"`), `revision`, `base_patch_plan_sha256`, `actions` map.
Identity binding enforced (`confirmation_orchestrator.py:79-82`):
schema/run/phase/revision/plan-hash mismatch → `PATCH_FORM_*_MISMATCH` /
`STALE_PATCH_FORM`.

**Per-action allowed keys** (`confirmation.py:34-36`): `target_cves`,
`package`, `input_reasons`, `fix_type`, `target_version`, `artifact`,
`strategy`, `command`, `validation_command`, `notes`,
`major_version_approved`, `execution_target`, `disposition`,
`disposition_reason`. Per-action detail: `target_cves` list; `package{name,
ecosystem, before_versions, scanner_fixed_versions}` with tamper-equality
checks (`confirmation.py:43-55`); `fix_type{suggested,confirmed}`,
`strategy{suggested,confirmed}`, `target_version{scanner_candidates (initial
form only), suggested, confirmed}`; `artifact{suggested_source,
confirmed_source, checksum{suggested,confirmed}}` plus continuation-form
`source_identifier, build_system, image_reference→replacement_target,
image_id→checksum` (`confirmation_orchestrator.py:56-61`);
`command{confirmed}`, `validation_command{confirmed}`;
`execution_target` must equal `"patch-workspace"`
(`PATCH_EXECUTION_TARGET_INVALID` otherwise); `major_version_approved`
(`None`/`True`); `notes` allowlisted but never read (display-only).
`disposition{EXECUTE, SKIP_OUT_OF_SCOPE}` + `disposition_reason`
(`models.py:37-43`); SKIP requires a non-empty reason.

**Enums** (`remediation/models.py:10-56`): `FixType{A,B,C}`; `PatchStrategy`
9 values (`COPACETIC, PACKAGE_MANAGER, ARTIFACT_REPLACEMENT, MUTATION,
REBUILD, PREBUILT_IMAGE_REPLACEMENT, IMAGE_REPLACEMENT, DOCKER_COMMIT,
HUMAN_COMMAND`); `PlanningStatus` (`READY_FOR_PATCH_EXECUTION,
SKIP_OUT_OF_SCOPE, WAITING_FOR_USER_INPUT, ...`); `PlanningReason`
(`FIX_TYPE_UNRESOLVED, TARGET_VERSION_UNRESOLVED,
ARTIFACT_SOURCE_UNRESOLVED, PATCH_STRATEGY_UNRESOLVED,
BUILD_PLAN_REQUIRES_HUMAN_INPUT, MAJOR_VERSION_CONFIRMATION_REQUIRED, ...`).
FixType/strategy compatibility pairings + `HUMAN_COMMAND`-with-any-type rule
(`guidance/patch_proposal.py:80-97`); build-system vocabulary locked to
`{"maven"}` (`patch_proposal.py:99-102`).

**Validators:** codec `validate_patch_plan` (`remediation/codec.py:44-95`)
recomputes per-action reasons (incl. strategy-specific artifact/command
requirements and `execution_target` check for `HUMAN_COMMAND`) and plan
readiness; `apply_patch_confirmations` (`confirmation.py:22-139`) rejects
unknown fields/actions, enforces suggested-value tamper equality, and records
`human_confirmed_fields` (`fix_type, strategy, target_version,
artifact_source, source_identifier, build_system, image_reference, image_id,
artifact_checksum, command, validation_command, execution_target,
major_version_approved`).

**Current LLM field policy (Task 6 MVP):** eligible suggestion fields are
`fix_type, strategy, target_version, artifact_source, source_identifier,
build_system, notes` (`patch_proposal.py:26-34`); **forbidden** to the LLM
are `command, validation_command, replacement_target, checksum, trusted,
source_authority, source_type, human_confirmed_fields,
major_version_approved, execution_target, disposition, disposition_reason,
readiness, remediation_verified` (`patch_proposal.py:43-58`). Every
execution-relevant suggestion must cite the exact EvidencePack
(`_EVIDENCE_BACKED_FIELDS`, `patch_proposal.py:104-114`); the sidecar binds
`evidence_pack_sha256/candidate_digest/field_evidence_sha256/patch_binding`
(`patch_proposal.py:360-376`).

**Identity/source linkage:** `PatchAction` carries `action_id` (`patch-NNN`),
`target_cves`/`incidental_cves`, `package_key` (= purl or name),
`package_name/ecosystem/occurrences/before_versions/scanner_fixed_versions`
(`models.py:94-113`); image identity lives on plan artifacts and
`CandidateContext{run_id, vulnerability_id, component, ecosystem,
installed_versions, image_identity, target_identity, container_id, phase}`
(`evidence/models.py`). `RemediationCandidate` carries
`source_type/source_authority/source_identifier/source_url/checksum/trusted/
replacement_target/build_system/evidence[]` (`models.py:60-85`); human
confirmation sets `trusted=True, source_authority="human_patch_form"`.

**Evidence layer available for reuse** (`src/kalama/evidence/`):
`EVIDENCE_PACK_SCHEMA="kalama.evidence-pack/v1"`, `SourceKind` (RUNTIME,
KNOWLEDGE, MSF_*, VENDOR_UPSTREAM, NVD, CISA_KEV), `EvidenceResultState`,
`EvidenceItem` (authority, resource_identity, snapshot_sha256),
`EvidenceCache`, `SourcePolicy.ordered_sources()` covering patch fields
`fix_type/target_version/strategy/artifact_source/source_identifier/
build_system/notes`.

**Per-field classification for the prototype:**

| Production field | Class | Rationale |
|---|---|---|
| fix_type, strategy, target_version, artifact_source, source_identifier, build_system, notes | AGENT_SUGGESTIBLE | Current Task 6 MVP eligible set; prototype keeps it, gated by sufficiency |
| command, validation_command | HUMAN_ONLY in production today; AGENT_SUGGESTIBLE only under L3+L4+L5 in prototype | Explicit researched policy delta (§8); adapter must enforce current forbiddance |
| target_cves, package{...}, input_reasons, suggested_* values | DETERMINISTIC_ONLY | Tamper-equality protected; agent/human never rewrite seed |
| status/readiness/reasons, confirmations-added fields | VALIDATOR_DERIVED | Recomputed by codec/confirmation, never proposed |
| disposition/disposition_reason, major_version_approved, execution_target | HUMAN_ONLY | Human scope/approval decisions |
| trusted/source_authority/source_type/human_confirmed_fields/remediation_verified | HUMAN_ONLY or VALIDATOR_DERIVED; never agent-proposed | Trust boundary |
| AFTER scan / re-exploit / evaluation outputs, execution results | EXECUTION_RESULT_ONLY | Out of scope for proposal and review |
| Knowledge VALIDATED writes | OUT_OF_SCOPE_FOR_PROTOTYPE | No Knowledge writes in this research |

## 2. Prototype architecture

```text
Scanner / Runtime Seed
        ↓
Source Resolver / Evidence Retriever   (deterministic; §decision_ownership.md)
        ↓
Evidence Pack Builder                  (frozen pack + pack_sha256)
        ↓
Evidence Sufficiency Gate              (deterministic SUPPORTED/PARTIAL/INSUFFICIENT per capability)
        ↓
ROLE A: Agent                          (proposal from pack only; protocol.md PHASE A)
        ↓
Agent Proposal                         (frozen + proposal_sha256)
        ↓
Mechanical Proposal Validation         (schema, gate compliance, citation presence, production pairing rules)
        ↓
ROLE B: Human Reviewer                 (review/edit/reject; protocol.md PHASE B)
        ↓
Human Review / Edited Proposal
        ↓
Research Evaluation                    (evaluation_plan.md metrics; no execution)
```

No production API integration at any stage. Agent and Reviewer are logical
roles, not provider implementations.

## 3. Data flow

One action per triple: a frozen pack (`pack_sha256`) → one proposal bound to
it (`candidate_binding.pack_sha256`) → one review bound to both hashes →
one evaluation record. Hash mismatches invalidate the triple. Multi-action
runs repeat the triple per action; cross-action reasoning is out of scope.

## 4. Evidence Pack

`schemas/evidence_pack.schema.json`. Frozen, auditable, self-contained:
candidate_identity (run/action/CVE/package/ecosystem/installed/image/target/
phase), evidence_level (`satisfied_levels`/`missing_levels` over L0–L5),
deterministic `evidence_sufficiency` gates (version/provenance/integrity/
closure/strategy: SUPPORTED|PARTIAL|INSUFFICIENT; command/validation_command:
SUPPORTED|INSUFFICIENT), sectioned evidence (scanner, runtime, advisory,
registry, upstream docs, runtime docs, artifact, dependency), source graph
summary + portable `source_references` (`source_reference.schema.json`),
`missing_evidence` codes, `pack_sha256`. Baseline gates follow Task 7.5.7:
version L1; provenance/closure L3; command L3+L4+L5; validation L3+L5 (+L4
when compatibility affects it). The Agent cannot override gates.

## 5. Agent Proposal

`schemas/agent_proposal.schema.json`. Field-level over the production-audited
vocabulary (`fix_type, strategy, target_version, artifact_source,
source_identifier, build_system, command, validation_command, notes`);
each field: `value`, `status` (PROPOSED/ABSTAINED/NOT_APPLICABLE),
`evidence_refs` (pack source_ids; required non-empty for PROPOSED factual
fields), `confidence`, `reason_summary` (no hidden chain-of-thought). Gate
enforcement: `command`/`validation_command` INSUFFICIENT → null +
`abstentions[]` typed reason (e.g. `COMMAND_GATE_INSUFFICIENT`).
Forbidden as proposals: human confirmation state, `remediation_verified`,
AFTER/evaluation outputs, execution results.

## 6. Human Review

`schemas/human_review.schema.json`. Surrogate reviewer sees pack + frozen
proposal only (no hidden reasoning, no historical/reference answers).
Per-field `review_class`: NO_EDIT (semantically unchanged) / MINOR_EDIT
(format/path/syntax/clarity, logic unchanged) / MAJOR_EDIT (version,
strategy, dependencies, artifact identity, command behavior, or validation
semantics changed) / REJECT (unsafe/unsupported/unusable) /
ABSTENTION_ACCEPTED (correct decline on insufficient evidence); plus
`edit_reason`, `evidence_refs`, `unsupported_claim_detected`,
`missing_evidence_detected`. The reviewer judges evidence quality but never
fetches new evidence or edits the pack.

## 7. Evaluation

`schemas/evaluation_result.schema.json` + `evaluation_plan.md`. No single
subjective score: counts (field/no_edit/minor/major/reject/abstention
accepted/unsupported/missing-citation/invalid-ref/semantic-critical),
rates (supported-field, refinement, major-refinement, unsupported-claim,
citation-validity, abstention-correctness), validator pass before vs after
review, durations, per-field results. Future arms ARM_A_L1 / ARM_B_L3 /
ARM_C_L3_L4_L5 compare the same case across evidence tiers (not run here).

## 8. Production compatibility

```text
Research Proposal  →  Projection / Adapter  →  Production Patch Form  →  Existing production validator
```

The adapter maps research fields onto confirmed-form slots
(`target_version.confirmed`, `artifact.confirmed_source/checksum.confirmed`,
`strategy/fix_type.confirmed`, `command/validation_command.confirmed`)
while re-enforcing production policy — including today's Task 6 MVP rule
that the LLM may not set `command`/`validation_command` at all. The
prototype's threshold-gated command drafting is therefore a **researched
future-policy candidate**, not a bypass: any command text the Agent drafts
enters production only as human-reviewable draft content subject to human
confirmation, never as a confirmation itself. The prototype prefers reusing
production validation semantics (codec reasons, tamper checks, target
check) later, and modifies none of them now.

## 9. Security boundaries

Trust flows one way: seed → deterministic retrieval → frozen pack → gated
suggestion → human decision → mechanical validation. The Agent cannot create
roots, promote authority, override gates, or declare success; the Reviewer
cannot add evidence; the adapter cannot weaken production forbiddances;
evaluation cannot execute. Violations are measurable defects, not silent
behavior.

## 10. Threats to validity

Dual-role cognitive leakage (same harness as Agent and Reviewer); single-case
results do not generalize; surrogate behavior may differ from any future API
model; evidence completeness may dominate model quality (confounded with
agent skill); edit-classification involves judgment (mitigate with the
§6 semantic definitions + edit reasons); validator pass ≠ remediation
success; synthetic examples prove schema shape only, not real remediation.
