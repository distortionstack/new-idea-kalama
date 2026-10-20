# Kalama Field-Level LLM Contract Design (Task 7.5)

Status: DESIGN ONLY. No production integration. Production code wins over
every statement below; file/symbol references are against the accepted
Task 7.4 checkout. Task 7.6 decides implementation.

LLM is NOT the knowledge base. Knowledge and Evidence remain sources of
truth. The LLM is a bounded evidence interpreter. LLM may prefill. LLM
NEVER submits — the human Submit gate is preserved.

## 1. Motivation and Task 7.3/7.4 evidence

- Task 7.3: qwen3:8b CPU-only, `think=false`, full Attack Case B
  (`~3216` user prompt chars) needs `>=512` output tokens, `~109 s`
  extended, truncated JSON; Patch Case F times out at 45 s. Semantic
  capability unmeasured — the contract itself may be the bottleneck.
- Task 7.4 (`kalama.llm-field-decomposition-evaluation/v1` artifacts
  `llm_field_decomp_qwen3-8b_20260915T185655Z.json`): narrow
  `{value, evidence_refs}` requests, same evidence, `think=false`,
  45 s, `num_predict=128`: 4/4 in budget, 4/4 structured, 3/4 value
  correct, 4/4 attribution, 0 forbidden, 0 timeouts. Output `21–48`
  tok (mean 32) vs `>=512`; latency max `20.47 s` vs timeout/`109 s`
  at the same `~6 tok/s`. RESULT: DECOMPOSITION_PROMISING.
- Remaining failure: B `target` returned the string
  `"component: pkg:maven/…"` instead of `{"index":0,"name":"Universal"}`.
  Hypothesis: contract mismatch — 7.4 described `value` as
  scalar-or-null, but production `target` is an object
  (`src/kalama/guidance/validator.py:82-86`). §13 of the task validates
  this with a typed schema; this document designs the full registry.

## 2. Non-goals / locked invariants

No change to resolver ranking, Patch planner, prioritizer, scanners,
Trivy/Grype/Nuclei, Knowledge validation semantics, evidence authority,
Attack/Patch Form schemas, executors, AFTER pipeline,
evaluation/classification semantics, frontend, or production validators
"merely to make the experiment pass". No exploit/patch execution, scans,
VALIDATED writes, submits, Grype work, fine-tuning, RAG/vector DB, GPU
requirement, budget increases, or Submit-gate removal.

## 3. Current monolithic flow

1. `resolution/llm_fields.py:effective_fields` (Attack) /
   `remediation/patch_llm.py:effective_fields` (Patch) compute
   unresolved = eligible − deterministic − knowledge.
2. `GuidanceService.guide_with_field_pack / guide_with_patch_pack`
   (`src/kalama/guidance/service.py:56-231`) embeds the full Task 1–3
   pack into one provider call; model must echo `candidate_digest`,
   `field_evidence_sha256` (+ `action_id`, `patch_binding` for Patch)
   and emit up to 3 proposal fields with `reason` + `reasoning_summary`
   under `PROPOSAL_FORMAT` / `PATCH_PROPOSAL_FORMAT`
   (`src/kalama/guidance/ollama.py:54-107`).
3. Production validator accepts/rejects; `resolution/artifacts.py`
   / `remediation/patch_llm.py:project_patch_guidance` prefill
   `suggested` slots; human submits.

## 4. Proposed field-level flow

Per unresolved field: FieldRequest (Kalama-owned id + digests) →
minimal candidate projection + routed evidence → ONE typed
`{value, evidence_refs}` provider call with field-specific JSON Schema
→ deterministic post-parse check → Kalama-bound FieldResult →
assembler builds the existing proposal/envelope representation →
EXISTING validator unchanged → existing prefill → Form → USER SUBMIT.
LLM failure at any step leaves the field unresolved for manual entry;
the deterministic pipeline never fails because of the LLM.

## 5. Audited production field types

### 5.1 Attack (`LLM_ELIGIBLE_FIELDS`: `resolution/llm_fields.py:43`, `guidance/service.py:18`)

| field | canonical type | LLM schema (`ollama.py:95-99`) | validator (`validator.py`) | submission (`resolution/submission.py`) |
|---|---|---|---|---|
| `target` | `TargetSelection{target_index:ExploitValue(int), target_name:ExploitValue(str)}` (`resolver/config_models.py:106-120`); values are `ModuleTarget{index:int,name:str}` (`resolver/models.py:67-72`) | `object{index?:integer,name?:string}`, `additionalProperties:false` | Mapping, keys ⊆ `{index,name}`, **index must equal a known `meta["targets"]` index** (so index is effectively required), name `None`-or-equal (`:82-86`) | index int non-bool ∈ valid indexes, name str ∈ targets, cross-checked if both (`:172-202`) |
| `targeturi` | `ExploitValue(str)`, `required=True` when module declares TARGETURI (`resolver/config.py:171-193`) | `string` | str ∧ `startswith("/")` ∧ no URL scheme (`:87-88`) | confirmed must be str (`:204-208`; `/`/scheme check is validator-only) |
| `rport` | `ExploitValue(int)` in `EnvironmentBinding` (`resolver/models.py:235-248`); `_normalize_port` enforces `1..65535` (`resolver/config.py:57-64`) | `integer` | int non-bool ∈ supported ports ∪ resolver suggested (`:80-81`, `_supported_ports:16-22`) | int non-bool `1..65535`, sets `port_binding_source="human_attack_form"` (`:311-317`); `rhosts` read-only |
| `payload` | `ExploitValue(str)` + `compatible_payloads` + `discovery_status` (`resolver/models.py:142-156`) | `string` | str ∧ `payload_discovery_status=="FOUND"` ∧ ∈ `full_compatible_payloads` (`:78-79`) | str ∧ FOUND ∧ ∈ compatible; then live option introspection (`:214-228`) |

Prefill (`resolution/artifacts.py:100-152`): each `suggested` set only if
the corresponding `confirmed is None`; `target` splits `value.index →
index.suggested`, `value.name → name.suggested` independently.

### 5.2 Patch (`PATCH_LLM_ELIGIBLE_FIELDS`: `guidance/patch_proposal.py:26-34`)

`FixType{A,B,C}` (`remediation/models.py:10-13`); `PatchStrategy` 9 values:
`COPACETIC, PACKAGE_MANAGER, ARTIFACT_REPLACEMENT, MUTATION, REBUILD,
PREBUILT_IMAGE_REPLACEMENT, IMAGE_REPLACEMENT, DOCKER_COMMIT,
HUMAN_COMMAND` (`:16-25`). `_INVALID_PAIRINGS` (`patch_proposal.py:89-97`):
`(C,REBUILD), (C,PREBUILT_IMAGE_REPLACEMENT), (A,PACKAGE_MANAGER),
(A,PREBUILT_IMAGE_REPLACEMENT), (A,IMAGE_REPLACEMENT),
(B,PACKAGE_MANAGER), (B,REBUILD)`; `HUMAN_COMMAND` allowed with any.

| field | validator (`patch_proposal.py:_validate_value:294-336`) |
|---|---|
| `fix_type` | ∈ `{A,B,C}` |
| `strategy` | ∈ 9 strategies ∧ pairing valid vs sibling/resolved `fix_type` |
| `target_version` | str, non-blank, `≤200`, no whitespace, **same-major** as installed (else needs human `major_version_approved`) |
| `artifact_source` | str, non-blank, `≤2000`, no `\n` |
| `source_identifier` | str, non-blank, `≤500`, no `\n` |
| `build_system` | ∈ `{maven}` only (`_BUILD_SYSTEMS:102`) |
| `notes` | str, non-blank, `≤2000`; display-only, refs optional (`_EVIDENCE_BACKED_FIELDS:107-114` excludes it) |

Forbidden (14, `:43-58`, top-level or smuggled suggestion ⇒ whole-proposal
REJECTED): `command, validation_command, replacement_target, checksum,
trusted, source_authority, source_type, human_confirmed_fields,
major_version_approved, execution_target, disposition,
disposition_reason, readiness, remediation_verified`.
`project_patch_guidance` (`remediation/patch_llm.py:363-420`) fills only
blank `suggested` slots; `source_identifier`/`build_system`/`notes` have
no form slot (sidecar guidance artifact only).

## 6. FieldContract registry

Single deterministic registry owned by Kalama (new module in Task 7.6,
e.g. `kalama/field_contracts.py`; exact class shape is an implementation
choice — the property that matters is: **Kalama knows the type, the LLM
does not invent it**). Per field: name, domain, JSON value schema
(including required object keys, enums), nullability, candidate
projection, evidence relevance policy, deterministic post-parse
validation (mirroring the validator rows above, never looser),
normalization (none, except documented `str.strip()` where the validator
already strips — no coercion: `"8080"` never becomes `8080`).

Registry entries (value schema OR null; null handled by §10 abstention):

- Attack `target`: object, `additionalProperties:false`,
  `required:["index"]`, `index:integer`, `name:string` optional;
  post-check = validator `target` rule verbatim (index ∈ known targets,
  name absent/`None`/equal). NOTE: schema requires `index`; production
  schema leaves both optional but the validator rejects index-less
  values, so the registry is strictly more precise, not looser.
- Attack `targeturi`: string, must start with `/`, no scheme.
- Attack `rport`: integer (non-bool), `1..65535`, ∈ runtime-supported ∪
  resolver-suggested set available at assembly time.
- Attack `payload`: string ∈ `compatible_payloads` with status FOUND
  (allow-list injected into the prompt as data, never as the answer —
  the model selects, Kalama verifies membership).
- Patch `fix_type`: enum `[A,B,C]`.
- Patch `strategy`: enum of the 9 `PatchStrategy` values; pairing
  checked against sibling proposal or resolved `fix_type`.
- Patch `target_version`: string, `≤200`, no whitespace, same-major rule.
- Patch `artifact_source`: string, `≤2000`, no newline.
- Patch `source_identifier`: string, `≤500`, no newline.
- Patch `build_system`: enum `[maven]`.
- Patch `notes`: string, `≤2000`, refs optional, never drives
  scheduling or assembly into semantic slots.

## 7. Candidate-projection matrix (minimal per field)

| field | candidate facts exposed |
|---|---|
| Attack `target` | CVE, component/package, ecosystem, installed versions, selected MSF module (+ its full target list as *data* for selection), default target |
| Attack `targeturi` | CVE, component, selected module, module TARGETURI default, runtime endpoint facts |
| Attack `rport` | CVE, component, reachable/observed ports, module default RPORT |
| Attack `payload` | CVE, component, architecture, compatible payload list (as data), discovery status, selected module |
| Patch `fix_type` | CVE, component/ecosystem, installed versions, discovery classification |
| Patch `strategy` | CVE, component, resolved `fix_type`, installed versions |
| Patch `target_version` | CVE, component/ecosystem, installed versions (same-major check needs them), resolved `fix_type` |
| Patch `artifact_source` | CVE, component, resolved fix/strategy |
| Patch `source_identifier` | CVE, component, resolved fix/strategy |
| Patch `build_system` | CVE, component, manifest facts (pom.xml), resolved fix/strategy |
| Patch `notes` | CVE, component (display context only) |

Never expose: expected answers, digests/hashes, action/plan identity,
resolved-field values for OTHER fields (prevents the 7.4 `target` error
mode where the model echoed the `component:` line — see §10
anti-echo rule: candidate lines carry only the facts in this matrix,
and prompts state the exact output shape).

## 8. Evidence-routing matrix (precedence preserved)

Deterministic observed facts > compatible VALIDATED Knowledge >
authoritative external evidence (field-appropriate) > LLM suggestion >
user edit/submit. If deterministic/Knowledge resolves a field, the LLM
is never called for it (existing `effective_fields` schedulers already
enforce this: `resolution/llm_fields.py:109-123`,
`remediation/patch_llm.py:107-122` + `has_useful_evidence` gate).

| field | relevant sources |
|---|---|
| `target` | MSF structured metadata; VALIDATED compatible Knowledge |
| `targeturi` | MSF option metadata/docs; runtime endpoint facts; compatible Knowledge |
| `rport` | runtime ports; module default; compatible Knowledge |
| `payload` | MSF structured metadata; runtime architecture; VALIDATED compatible Knowledge |
| `fix_type` | discovery classification; VALIDATED Knowledge |
| `strategy` | discovery classification; VALIDATED Knowledge; vendor build docs (field-appropriate) |
| `target_version` | compatible VALIDATED Knowledge; vendor/upstream; NVD where appropriate |
| `artifact_source` | vendor/upstream; VALIDATED Knowledge |
| `source_identifier` | vendor/upstream; VALIDATED Knowledge |
| `build_system` | manifest/runtime facts; VALIDATED Knowledge |
| `notes` | any supplied context (display only) |

No global "best source score". Evidence stays bounded (per-field pack,
not the whole collector dump).

## 9. Typed output schemas

One field request ⇒ exactly `{"value": <typed-or-null>,
"evidence_refs": [...]}`. No digests, binding, action/plan fields,
`reason`/`reasoning_summary`, unrelated fields, or model-invented
confidence/authority/commands. The provider receives the field's JSON
Schema via structured output (`format`) — the model never infers the
shape from prose. `target` gets the object schema (this is the §13
validation).

## 10. Abstention rules (deterministic)

Canonical: `{"value": null, "evidence_refs": []}`. Rules: insufficient
evidence ⇒ abstain; conflicting evidence without deterministic
resolution ⇒ abstain; never fabricate refs; `null` + non-empty refs is
REJECTED (no defined semantics); non-null + empty refs is REJECTED for
all evidence-backed fields (`notes` excepted). Assembler maps
all-fields-abstain to the existing `INSUFFICIENT_EVIDENCE` status path.

## 11. Kalama-owned request binding

`FieldRequest R` stores: `request_id, run_id, candidate_digest,
field_name, field_evidence_sha256, allowed_evidence_ids` (+ Patch:
`action_id, package_key, plan_revision, base_patch_plan_sha256`). The
LLM returns only value+refs; Kalama associates the response with the
in-flight request and constructs the bound result itself. Fail closed on:
unknown/consumed request, wrong candidate (digest mismatch), cross-field
response, ref outside the request set, changed pack SHA / plan revision
/ base SHA, stale or duplicate response. Candidate isolation unchanged.

## 12. Assembler design (existing validators NOT bypassed)

Per validated FieldResult, Kalama builds the exact
`{value, evidence_refs, reason}` suggestion entries (`reason` set to `""`
— the validators only `str(reason)[:1000]`, non-empty is not required)
and fills every other envelope field from authoritative request state:
`schema/status/run_id/cve_id/evidence_pack_sha256/action_id/
candidate_digest/field_evidence_sha256/patch_binding` plus deterministic
`missing_evidence:[]`, `guidance_notes:[]`, `reasoning_summary:""`
(which no validator constrains). The assembled object goes through the
UNMODIFIED `validate_proposal` / `validate_patch_proposal`, then the
existing prefill projections. Semantic content (value) + refs come from
the LLM; protocol identity from Kalama; deterministic values from
Resolver/Patcher/Knowledge. No validator change is required for the
assembled path to validate: every field the assembler must set is either
request state or unconstrained. (One review point for 7.6: Attack
`reason`/`reasoning_summary` emptiness is permissible today but should
be covered by an explicit test so future validator tightening does not
silently break the field path.)

## 13. Attack flow

Scheduler (`effective_fields`) → per unresolved eligible field:
FieldRequest → projection (§7) + routed evidence (§8) → typed call (§9)
→ post-check (§6/§10) → binding (§11) → assembler (§12) →
`validate_proposal` → `attack_form` prefill (`suggested` only) → user.

## 14. Patch flow

Same, via `effective_fields`/`schedule_patch_guidance`, with
action/plan identity in the request store. Accepted values project only
into blank `suggested` slots (`fix_type/strategy/target_version/
artifact_source`); `source_identifier/build_system/notes` remain
sidecar-only until 7.6 defines form slots (no slot invention here).

## 15. Failure handling

Provider unavailable/timeout, malformed JSON, wrong type, unknown ref,
unsupported value, abstention, stale/changed candidate/evidence/plan:
field stays unresolved → user fills manually. Never substitute model
memory; never overwrite deterministic/Knowledge values; never auto-submit.

## 16. Concurrency/stale response behavior

Requests are single-consumer: first response consumes the request id;
late/duplicate responses are rejected as stale. Any candidate, evidence,
or plan change invalidates in-flight requests for that field (digest
comparison at attach time). Cross-candidate attach is impossible by
construction (digest is part of the store key comparison, not of the
model output).

## 17. Provider compatibility

FieldContracts are provider-independent. Ollama receives the schema via
`format`; a future remote provider receives the equivalent typed-schema
parameter of its API. The monolithic `propose`/`propose_patch` path
remains available as migration fallback until 7.6 proves the field path.
No vendor lock-in; no qwen-specific logic in the contract.

## 18. Migration strategy

Phase 0 (7.5): design + research validation only. Phase 1 (7.6): add the
field path alongside the monolithic path, scheduler-gated per field,
assembler-tested against existing validators. Phase 2: measure parity
(field coverage/attribution vs monolithic) then switch default per
field. Rollback: per-field flag back to monolithic/manual; monolithic
code is not deleted until parity is demonstrated.

## 19. Tests required for Task 7.6

Attack: typed `target` object (incl. index-required, extra-key reject),
`targeturi` `/`-prefix/scheme, `rport` range+membership, `payload`
allow-list+FOUND, protected/resolved skip, Knowledge-resolved skip,
wrong-type, fabricated ref, injection evidence, timeout, malformed
output, stale candidate, cross-request. Patch: `fix_type` enum,
`strategy` enum+pairings, `target_version` same-major, artifact/source-id
bounds, `build_system` maven-only, `notes` inert, forbidden impossible,
Knowledge-resolved skip, stale action/revision/base-SHA, provider
failure. Human gate: prefill-only, no auto-submit, user edits
authoritative. Plus: assembler-output-passes-unmodified-validators
(feeds assembled proposals through the real validators), and
empty-`reason` acceptance pinning (see §12).

## 20. Rollback/fallback behavior

Any field-path failure ⇒ field unresolved ⇒ manual entry. Global kill
flag ⇒ monolithic path. No partial writes: binding consumes requests
atomically; prefill only touches blank `suggested` slots.

## 21. Unresolved questions

1. `target` assemblies where evidence lists multiple targets: selection
   among equals needs a documented tie-break (currently first-match in
   validator `any()`; assembler should preserve order, not choose).
2. Whether `rport` membership sets should be snapshotted into the
   request (ports can change between call and assembly) — recommendation:
   yes, snapshot + re-verify at attach.
3. Form slots for `source_identifier`/`build_system`/`notes` — 7.6 scope
   decision (sidecar vs new slots; schema change requires care).
4. Grouped calls: deferred (see §22 of task — conditions only, no
   implementation).
