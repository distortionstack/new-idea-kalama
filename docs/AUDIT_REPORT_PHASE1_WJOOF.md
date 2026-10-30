# AUDIT REPORT — PHASE 1 (§8.1) — Run WJoOf

- **Run**: `WJoOf` (2026-10-24)
- **Protocol**: AGENTS.md — PHASE 1 AUDIT (read-only, no code edits, no Phase 2/3 action)
- **Method**: primary audit (§1 ground truth) + 5 parallel subagents (§12/§13) + primary re-verification (≥3 citations per sub-report)
- **Buckets**: provider | gate | validator (kept strictly separate per §0.6)

---

## 8.1.1 Scope & files read

Primary (self-read + grep + git + .env redacted):

- `src/kalama/config.py`
- `src/kalama/guidance/openai_compatible.py`
- `src/kalama/guidance/service.py`
- `src/kalama/guidance/validator.py`
- `src/kalama/guidance/ollama.py`
- `src/kalama/resolution/llm_fields.py`
- `src/kalama/resolution/orchestrator.py`
- `src/kalama/resolver/config.py`
- `src/kalama/runtime.py`
- `src/kalama/evidence/sources.py`, `src/kalama/evidence/policy.py`
- `output/resolver/guidance/llm_guidance_2026-10-24_WJoOf.json` (14 lines, full read)
- `.env` (non-secret LLM settings only; `KALAMA_LLM_API_KEY` redacted, value never displayed)
- `git status` / `git log` / `git show HEAD:<path>` (read-only)

Subagents (5, all read-only, all findings-only):

| Role | Scope | Bucket |
|---|---|---|
| audit-provider | `guidance/*.py`, `config.py`, `runtime.py` (wiring), `.env` | provider (+C1/C2 validator) |
| audit-wiring | `resolution/{llm_fields,orchestrator}.py`, `runtime.py`, `evidence/*.py`, `resolver/config.py` | gate |
| audit-run | the three `*WJoOf*` artifacts | gate / provider / validator |
| audit-tests | the four unit-test files + one allowed unittest run | all |
| audit-discrepancy | §2/§3 claims vs code/artifacts/git | all |

**Note (D-F1)**: the §13 agent types (`audit-provider`, `audit-wiring`, `audit-run`, `audit-tests`, `audit-discrepancy`) are **not registered in this session** (`Unknown agent type`). Fallback: `general` subagents with the §12.2 role card + §12.4 report format injected verbatim. All five returned in §12.4 format.

---

## 8.1.2 Provider & config findings (A1–A3)

### A1 — exact base_url and model the process loads

- `.env:2-5` (primary verified):
  - `KALAMA_LLM_ENABLED=true`
  - `KALAMA_LLM_PROVIDER=openai-compatible`
  - `KALAMA_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai`
  - `KALAMA_LLM_MODEL=gemini-3.8-flash`
  - `KALAMA_LLM_API_KEY` present at `.env:6` — **value never displayed, referenced only as `api_key`**
- Load path: `src/kalama/config.py:65-74` (process env wins over `.env`; `.env` path is cwd-dependent, `config.py:66`) → `src/kalama/runtime.py:199` (`self._session_llm_config or load_config()`) → `runtime.py:210-213` constructs `OpenAICompatibleProvider(OpenAICompatibleConfig(base_url=..., model=..., api_key=config.api_key or "", timeout=KALAMA_LLM_TIMEOUT or 45))`.
- Endpoint: `src/kalama/guidance/openai_compatible.py:56` `url = base_url.rstrip("/") + "/chat/completions"`; POST with `Authorization: Bearer` at `:57-60`.
- **Conclusion: model = `gemini-3.8-flash`, NOT `gemini-3.5-flash`.** Corroborated by the artifact `llm_guidance_2026-10-24_WJoOf.json:4`.
- Session override: desktop `configure_llm` is in-memory only (`runtime.py:70-76`); no artifact trace (UNKNOWN U7 partially mitigated by artifact model field).

### A2 — `openai_compatible.py` behavior summary

| Item | Value | Line |
|---|---|---|
| `timeout` | 45 | `:33` |
| `max_response_bytes` | 256 KiB | `:34` |
| `max_tokens` | 384 | `:35` |
| `max_tokens_limit` | 1024 | `:36` |
| `transient_retries` | 2 (retries) | `:37` |
| `retry_backoff_seconds` | 1.0 | `:38` |

- Budget init: `budget = max(64, min(384, 1024)) = 384` — `:80`.
- **`finish_reason=="length"` → budget doubling**: `:124-127` — `budget = min(limit, budget*2); length_retries += 1; continue`. First doubling: **384 → 768** (matches §2.5's `max_tokens:768` arithmetically; see D-3).
- **HTTP 400 → schema→json_object fallback**: `:100-102` — one-shot (`use_schema = False; continue`); a second 400 raises.
- **Bounded transient retry**: `:103-106` — status set literal `{429, 500, 502, 503, 504}` (not all 5xx), `transient_attempt < 2` → **1 initial + 2 retries = 3 attempts**, backoff **1.0s then 2.0s** (`retry_backoff_seconds * 2**attempt`).
- `last_call_metadata` captured:
  - success path `:119-123`: `model`, `max_tokens`, `structured_output`, `transient_attempts`, `finish_reason`, `usage`
  - HTTP-error path `:107-111`: adds `http_status`; no `finish_reason`/`usage`
  - process-local only, never written to run artifacts (`:51-53`)
- **Observations (findings only)**:
  - `length_retries` (`:83`, `:126`) is incremented but never read or bounded; the loop is bounded only by `budget == max_tokens_limit`, after which a still-truncated body hits `json.loads` (`:128`) and raises.
  - `transient_attempt` is **not reset** on a length-triggered budget doubling.
  - §2.6 numeric claims ("<=3 attempts", "1→2s") are exact; the "5xx" wording is not literal (501/505 excluded).

### A3 — api_key leakage surface

- Used in Authorization headers at exactly two HTTP call sites: `src/kalama/guidance/openai_compatible.py:59`, `src/kalama/doctor.py:112` (primary repo-wide grep; key never placed in a URL).
- Other references are config/validation/in-memory only: `config.py:37,44`, `runtime.py:212`, `desktop/application.py` (UI intake), browser→bridge send.
- Persisted exception path: `service.py:49-53` and `:147-152` store `f"{type(exc).__name__}: {str(exc)[:500]}"` into `GuidanceOutcome.issues` (serialized by `models.py`). Reachable exceptions: `HTTPError` (code/reason/URL only), `ValueError` at `openai_compatible.py:64/:130`, `json.JSONDecodeError` — **none interpolate `api_key`**.
- Defense-in-depth: `evaluation/llm_eval.py:251-257` rejects artifacts containing `api_key`/`apikey`/`token`/`secret`/`password` keys.
- **Conclusion: CONFIRMED — no interpolation of `api_key` outside Authorization headers anywhere in `src/`.**

---

## 8.1.3 Evidence gate & wiring findings (B1–B4)

### B1 — factory receives live Resolver context (post-fix working tree)

- Call site in `schedule_field_guidance` passes **all four** arguments:
  - `llm_fields.py:455-461` — `_collector_from_factory(factory, knowledge_store=knowledge_store, target_facts=target_facts, occurrences=occurrences_all, candidates_by_cve=candidates_by_cve)`
- Fallback `build_production_collector(...)` `:462-470` — same four + `output_root`/`evidence_config`.
- `occurrences_all` aggregated at `:379-387`; `candidates_by_cve` via `selected_candidate_for_item` at `:388-393` — both built **before** the per-CVE loop.
- Production factory `runtime.py:235-244`: keyword-only, all-default parameters + `**_ignored` → VAR_KEYWORD branch (`llm_fields.py:326-331`) forwards the full dict.
- Wiring chain: `runtime.py:156-164` (`evidence_collector_factory=self._evidence_collector_factory()`) → `orchestrator.py:199-201` → `orchestrator.py:202-209` (`schedule_field_guidance(...)`).
- **⚠ Status of this fix: UNCOMMITTED working-tree change only** (see D-2/D-3).

### B2 — signature inspection, no broad `except TypeError`

- `llm_fields.py:301-343` `_collector_from_factory`:
  - `inspect.signature(factory)` wrapped narrowly in `except (TypeError, ValueError)` → raises `EVIDENCE_COLLECTOR_FACTORY_SIGNATURE_UNAVAILABLE` (`:321-324`) — introspection only.
  - `except TypeError` exists only around `signature.bind(**kwargs)` (`:334`) and the zero-arg probe `signature.bind()` (`:337`).
  - **The actual invocations `factory()` (`:342`) and `factory(**kwargs)` (`:343`) are bare** — a `TypeError` raised *inside* a factory propagates and is recorded as `COLLECTOR_SETUP_ERROR:TypeError` (`:471-473`).
- Outer handling catches broad `Exception` (not `TypeError`) at `:452-473` — deliberate nonfatal diagnostics, distinct from signature misclassification.
- **Compliant with §0.8.** Regression test: `test_resolver_llm_field_scheduling.py:375`.

### B3 — `has_useful_evidence()` + complete skip-reason catalog

`llm_fields.py:215-223`:

```python
def has_useful_evidence(collection: Any) -> bool:
    try:
        items = getattr(collection.pack, "items", ())
    except Exception:
        return False
    if not items:
        return False
    return any(bool(getattr(item, "facts", None)) for item in items)
```

Skip conditions: (a) pack/items inaccessible → False; (b) zero items → False; (c) no item with truthy `facts` → False.

**Diagnostic reason strings (13 in `schedule_field_guidance` + 1 in orchestrator):**

| # | Reason | Line |
|---|---|---|
| 1 | `CVE_STATUS_{status}` | `llm_fields.py:414` |
| 2 | `RESOLVER_CONFIGURATION_INCOMPLETE` | `:417` |
| 3 | `FIELD_RESOLUTION_ERROR` | `:426` |
| 4 | `NO_UNRESOLVED_ELIGIBLE_FIELDS` | `:429` |
| 5 | `CANDIDATE_CONTEXT_ERROR` | `:437` |
| 6 | `NO_STABLE_COMPONENT_IDENTITY` | `:440` |
| 7 | `FIELD_REQUEST_ERROR` | `:450` |
| 8 | `COLLECTOR_SETUP_ERROR:{type}` | `:472` |
| 9 | `EVIDENCE_COLLECTION_ERROR:{type}` | `:477` |
| 10 | `NO_USEFUL_EVIDENCE` | `:480` |
| 11 | `GUIDANCE_SERVICE_FIELD_PACK_UNSUPPORTED` | `:486` |
| 12 | `GUIDANCE_CALL_ERROR:{type}` | `:497` |
| 13 | `GUIDANCE_NOT_INVOKED` | `:502` |
| 14 | `GUIDANCE_SCHEDULER_ERROR:{type}` (cve_id=None) | `orchestrator.py:213-217` |

**Silent skips (no diagnostic, even post-fix)**: (i) cve_id extraction failure `:400-403`; (ii) `KALAMA_GUIDANCE_CVES` allowlist filter `:404-409`; (iii) exception inside status/config guard `:418-420`; (iv) early `return ()` when no CVEs / no service `:367-371`. ⇒ `outcome_count=0` with an **empty diagnostics list is possible with no recorded reason**.

### B4 — diagnostics → artifact; `NO_ELIGIBLE_EVIDENCE_OR_FIELDS`

- `orchestrator.py:191` allocates `guidance_diagnostics = []` → `:208` passes `diagnostics=` → `:266` writes key `"diagnostics"` (working tree only; **`git show HEAD:orchestrator.py` has no such key**).
- **Status set at `orchestrator.py:264`** (HEAD `:257`):
  `"status": "OUTCOMES_RECORDED" if guidance_outcomes else "NO_ELIGIBLE_EVIDENCE_OR_FIELDS"`
  ⇒ any zero-outcome run gets this one label, regardless of cause — a pure gate-level label, never a provider/validator result (§0.6).
- Artifact written whenever `guidance_outcomes or self.guidance_service is not None` (`:252`); write failure is nonfatal (`:269-272`).
- Source reality (post-fix): MSF sources return `NOT_APPLICABLE` unless `candidates_by_cve` contains the CVE (`evidence/sources.py:74-76`, `:93-96`); `RuntimeEvidenceSource` needs occurrence matches (`:30-33`) and unresolved-field keys (`:39-40`). The fixed call site now delivers both.

---

## 8.1.4 Validator authority findings (C1–C2)

### C1 — field whitelist + evidence_refs / digest requirements

- `LLM_ELIGIBLE_FIELDS = frozenset({"target","targeturi","rport","payload"})` — `service.py:18`; intersected at `service.py:92`.
- `ALLOWED_TOP` — `validator.py:9-11`; `ALLOWED_FIELDS` (broader vocabulary) — `validator.py:12-13`. The effective gate is `allowed = pack.document["allowed_proposal_fields"]` (`validator.py:60,65-66`), which `service.py:103` sets to the exact unresolved eligible subset (overwrite, never merge).
- Compact schema third gate: `_compact_attack_schema` hard-filters to the four fields (`openai_compatible.py:144-145`), proposals `maxProperties` ≤ 3 (`:172`), `evidence_refs` maxItems 2 (`:156`), `reason` maxLength 160 (`:157`).
- Digest rules (`validator.py`):
  - identity triple `(run_id, cve_id, evidence_pack_sha256)` must equal pack's (`:34-36`) → else REJECTED
  - `candidate_digest` echo required when the pack carries it (`:41-44`)
  - `field_evidence_sha256` echo required when the pack carries it (`:48-51`) — pack SHA is never substituted after model output
- `evidence_refs`: list of strings, every ref ∈ `pack.references`, non-empty whenever `value is not None` (`:71-74`); merged reference set includes legacy refs + field-pack `snapshot_refs`/`provenance_ref`/`snapshot_sha256`/`field_evidence.<kind>` (`service.py:108-125`).
- Per-field value gates (`validator.py:77-98`): `module` ∈ candidate_modules; `payload` requires discovery FOUND + ∈ compatible set; `rport` ∈ supported ports; `target` index/name match; `targeturi` starts `/` no scheme; options keys ∈ schema; `execution_protocol` enum; `preconditions` single-line + shell-token blocklist.
- Final states (`:104-106`): `PARTIALLY_ACCEPTED` / `ACCEPTED_AS_SUGGESTION` / `REJECTED`.

### C2 — no path sets "confirmed" or writes the attack form from LLM output

- `ProposalValidationState` enum = exactly `ACCEPTED_AS_SUGGESTION`, `PARTIALLY_ACCEPTED`, `REJECTED`, `INSUFFICIENT_EVIDENCE` (`guidance/models.py:15-19`, primary verified). **No `confirmed` value exists.**
- Projection path: `orchestrator.py:229` builds `guidance_by_cve` (knowledge-protected fields stripped at `:218-227`) → `attack_form(...)` `:305-307`.
- `resolution/artifacts.py:132-148`: LLM accepts projected **only** into `suggested` + `confirmation_status: "SUGGESTED"`, and only when `destination.get("confirmed") is None`. `module`/`module_options`/`payload_options`/`execution_protocol` are **not** projected from LLM at all.
- `_value_projection` sets `confirmed` only from a resolver `ExploitValue.value` whose `.confirmed` is true (`artifacts.py:57-62`); those originate from resolver `AUTO_CONFIRMED` (`resolver/config.py:90,224,263`) or human form submission (`resolution/submission.py`).
- **Conclusion: CONFIRMED — no code path sets `validation_state` to `confirmed`, and LLM output can never populate an attack-form `confirmed` slot.**

---

## 8.1.5 Reference run WJoOf findings (D1–D3)

### D1 — CVEs with MSF modules (resolver artifact; primary verified)

30 CVEs total (`cves` L12; summary `selected_count=30` L16083). Exactly **3** have a module candidate; **27** are `NO_MSF_MODULE` (L16081); `ready_to_execute=0` (L16082); `waiting_for_user_input=3` (L16086).

| CVE | Entry lines | module_path | Line | Class | status |
|---|---|---|---|---|---|
| CVE-2019-2215 | L14–1265 | `exploit/android/local/binder_uaf` | L32 | exploit | `WAITING_FOR_USER_INPUT` (L1237) |
| CVE-2019-13272 | L1635–3194 | `exploit/linux/local/ptrace_traceme_pkexec_helper` | L1653 | exploit | `WAITING_FOR_USER_INPUT` (L3156) |
| CVE-2017-9798 | L9677–12724 | `auxiliary/scanner/http/apache_optionsbleed` | L9695 | **auxiliary/scanner** | `WAITING_FOR_USER_INPUT` (L12646) |

- Validation issues (resolver): CVE-2019-2215 — `TARGET_REQUIRED`, `MODULE_OPTION_REQUIRED/SESSION`, `EXECUTION_PROTOCOL_REQUIRED`, `PAYLOAD_SELECTION_REQUIRED` (L1239–ff); CVE-2019-13272 — `TARGET_REQUIRED`, `MODULE_OPTION_REQUIRED` (COMPILE/COMPILER/SESSION/WritableDir), `EXECUTION_PROTOCOL_REQUIRED` (L3158–ff); CVE-2017-9798 — `TARGETURI_REQUIRED`, `MODULE_OPTION_REQUIRED` ×11, `ENVIRONMENT_RPORT_REQUIRED`, `EXECUTION_PROTOCOL_REQUIRED` (L12647–ff) — **no `PAYLOAD_SELECTION_REQUIRED`** (primary grep: 0 hits in L9677–12724).
- The other 27 CVEs: status lines at L1616, L3412, L3669, L3920, L4160, L4593, L5000, L5678, L6386, L6619, L6954, L7557, L7812, L8042, L8297, L8970, L9658, L12961, L13276, L13528, L14146, L14400, L14713, L14953, L15280, L15710, L16059.
- `errors` empty for all 30 entries.

### D2 — guidance artifact (full 14-line read)

```json
{
  "artifact": {
    "created_at": "2026-10-24T11:00:52Z",
    "model": "gemini-3.8-flash",          // L4
    "outcome_count": 0,                    // L5
    "phase": "before",
    "provider": "openai-compatible",       // L7
    "resolver_sha256": "8f491ba2…",
    "run_id": "WJoOf",
    "status": "NO_ELIGIBLE_EVIDENCE_OR_FIELDS"   // L10
  },
  "cves": [],                              // L12
  "schema": "kalama.llm-guidance/v1"
}
```

- **`cves` is empty (L12)** ⇒ there are **zero outcomes** ⇒ no per-outcome `validation_state` / `issues` exist to report.
- **No `diagnostics` key at all** (top-level keys = `artifact`, `cves`, `schema` only). Also no `request_settings`.
- `resolver_sha256` (L8) matches `attack_form_WJoOf_r1.yaml:5` `base_resolver_sha256` — same resolver snapshot.

### D3 — attack form pending gates (3 CVEs; L8, L298, L636)

**CVE-2019-2215** (module AUTO_CONFIRMED L18-20; rhosts AUTO_CONFIRMED L279-281):
- `target.index` required, `confirmed: null` (L49-55); `target.name` required, null (L56-62)
- `module_options.SESSION` required, null (L199-206)
- `payload` required, `UNRESOLVED`, null (L231-237)
- `execution_protocol` null (L267-274)
- non-blocking: `environment.rport` UNRESOLVED required=false (L283-289); `lhost` SUGGESTED (L290-296); `targeturi` UNRESOLVED required=false (L63-69)

**CVE-2019-13272** (module AUTO_CONFIRMED L306-310; rhosts AUTO_CONFIRMED L617-619):
- `target.index`/`target.name` null (L338-351)
- `module_options` COMPILE (L376-383), COMPILER (L384-391), SESSION (L520-527), WritableDir (L552-559) — required, null
- `execution_protocol` null, mode `check-only` (L605-612)
- non-blocking: `payload` required=false UNRESOLVED (L560-566); `rport` required=false (L621-627)

**CVE-2017-9798** (module AUTO_CONFIRMED L645-649; rhosts AUTO_CONFIRMED L1230-1233):
- `targeturi` required, null (L691-697)
- `module_options` required+null ×11: BUGS (L699-706), DOMAIN (L731-738), HTTP::Auth (L755-762), HTTP::KrbOfferedEncryptionTypes (L779-786), KrbCacheMode (L1075-1082), KrbClockSkew (L1083-1090), REPEAT (L1099-1106), ShowProgress (L1107-1114), ShowProgressPercent (L1115-1122), SSLVersion (L1147-1154), THREADS (L1155-1162)
- **`payload` `required: true`, `UNRESOLVED`, `compatible: []`, `discovery_status: ERROR`** (L1197-1206)
- `execution_protocol` null, mode **`exploit-only`** (`run_exploit: true`) (L1219-1226)
- `environment.rport` required=true, SUGGESTED=80, null (L1235-1241)

The 27 `NO_MSF_MODULE` CVEs are absent from the form.

---

## 8.1.6 Test results (E1–E2)

### E1 — tests and the invariant each protects (29 tests)

**`tests/unit/test_openai_compatible.py` (4) — provider**
- `test_uses_chat_completions_shape_and_parses_json_content` (:11) — chat-completions request shape, model in body, `response_format` json_schema name `kalama_guidance`, temperature 0, content parse
- `test_compacts_prompt_and_retries_length_with_larger_budget` (:31) — **length-doubling 384→768** (assert :53), prompt compaction, `last_call_metadata["finish_reason"]`
- `test_retries_transient_http_error` (:59) — HTTP 503 retried once (`calls==2`, :72)
- `test_rejects_non_json_response_content` (:74) — unparseable content raises (no silent success)

**`tests/unit/test_guidance.py` (7)**
- `test_valid_payload_is_suggestion_only` (:42) — **ACCEPTED_AS_SUGGESTION, confirmed stays False**
- `test_hallucinated_payload_module_port_reference_and_rhosts_are_rejected` (:51) — hallucinated values / fabricated refs / oracle → all REJECTED
- `test_executable_precondition_is_rejected` (:66) — non-whitelisted field rejected
- `test_invalid_json_timeout_and_unavailable_fall_back` (:71) — UNAVAILABLE / DISABLED
- `test_ollama_parses_bounded_json_envelope` (:78)
- `test_no_unresolved_fields_skips_provider` (:87) — gate: provider never called
- `test_no_module_status_skips_provider` (:103) — gate: NO_MSF_MODULE skip

**`tests/unit/test_resolver_llm_field_scheduling.py` (7)**
- `test_eligible_fields_are_locked` (:136) — exactly the 4 fields; 9 forbidden names excluded
- `test_partial_knowledge_exact_wiring` (:143) — exact unresolved set, digest binding, confirmed never flips
- `test_fully_resolved_short_circuit` (:248) — no collector/provider call
- `test_no_evidence_skips_provider` (:293) — empty pack → provider never called
- `test_contextual_factory_receives_live_occurrences_and_candidates` (:314) — **direct regression for the §2.1 wiring bug**: factory receives `target_facts`/`occurrences`/`candidates_by_cve` (:349-352)
- `test_production_collector_uses_live_context_from_runtime_factory_contract` (:355) — live context binding
- `test_factory_internal_type_error_is_not_retried_as_legacy_signature` (:375) — **no broad-TypeError swallowing**: called once, `COLLECTOR_SETUP_ERROR:TypeError` (:393-397)

**`tests/unit/test_resolver_llm_candidate_binding.py` (11)**
- digest distinguishes all 9 identity axes (:142); cross-candidate rejection (:175); same-CVE different-version rejection (:212); pack-SHA mismatch without substitution (:222); disallowed-field rejection (:236); protected-field overwrite rejected (:261); fabricated **and foreign** refs rejected (:283); injection-shaped evidence treated as data (:310); malformed/provider-failure nonfatal (:344); **human gate mandatory** (:380); LLM provenance audit trail, never contains `confirmed`/`VALIDATED` (:400)

**Coverage gaps (findings)**: no test for HTTP 400 schema→json_object fallback; no 429-specific retry test; no assertion that `api_key` is absent from outputs; no positive legacy zero-arg factory test; no assertion of a named diagnostic skip-reason string.

### E2 — unittest run (verbatim)

Primary re-ran the exact allowed command:

```
Ran 29 tests in 0.029s

OK
```

Subagent run (same command): `Ran 29 tests in 0.049s` / `OK` — identical pass/fail result. **29/29 pass, 0 failures, 0 errors.**

---

## 8.1.7 Discrepancy log (F1)

1. **D-F1 (process)**: §13 agent types are not registered in this session (`Unknown agent type` ×5) → used `general` subagents with injected role cards; all returned §12.4 format.
2. **§2.1 "FIXED" does not exist in git history**: the fix is an **uncommitted working-tree change only** (`git status`: ` M src/kalama/resolution/llm_fields.py`, ` M .../orchestrator.py`, ` M src/kalama/runtime.py`; `src/kalama/guidance/openai_compatible.py` and `tests/unit/test_openai_compatible.py` are `??` untracked). The only commit touching `llm_fields.py` (`afa9347`, 2026-10-20) still contains the bug.
3. **Actual bug mechanism (imprecise in §2.1)**: `git show HEAD:src/kalama/resolution/llm_fields.py:381` = `active = factory()` with a `TypeError` fallback carrying the kwargs — but the production factory has all-default parameters (`runtime.py:235-236`), so **`factory()` succeeds and the fallback is dead code** → collector built with empty `target_facts/occurrences/candidates_by_cve`. Not "TypeError swallowed" but "zero-arg call succeeded with empty defaults."
4. **HEAD rejects non-Ollama providers outright**: `git show HEAD:src/kalama/runtime.py:193` = `if config.error() is not None or config.provider != "ollama": return None`. The entire OpenAI-compatible/Gemini path is new and uncommitted.
5. **WJoOf artifact predates the fix**: `created_at 11:00:52Z` vs file mtimes of the fix (18:25–18:55 +0700), and the artifact **has no `diagnostics` key** — proof it was produced by HEAD code (which has no such key) → that run exercised the gate **before** the fix; **no provider call was made in that run**.
6. **§2.4 "model string inconsistent" is overstated**: `gemini-3.5-flash` occurs **only in prose** (`AGENTS.md`, `setup-kalama-opencode.sh`, role cards) — zero occurrences in any config or artifact. Live `.env:5` and the sole Gemini artifact `:4` both say `gemini-3.8-flash`.
7. **§2.3 and §2.5 have no in-repo evidence**: the HTTP 503 "high demand" body and the replay metadata (`finish_reason:"length"`, `max_tokens:768`, `structured_output:true`, `completion_tokens:17`) are recorded nowhere; `last_call_metadata` is process-local by design (`openai_compatible.py:51-53`). §2.5 is arithmetically consistent (384→768 = one doubling) but should be classified UNKNOWN, not VERIFIED.
8. **§2.6 wording**: retry set is literally `{429,500,502,503,504}` — not all 5xx (501/505 excluded). The numeric claims (`<=3 attempts`, `1→2s`) are exact.
9. **Internal inconsistency in the artifacts themselves — CVE-2017-9798**: attack form marks `payload.required: true` with `discovery_status: ERROR` (L1197-1206) while the resolver's own validation for the same CVE has **no** `PAYLOAD_SELECTION_REQUIRED` (primary grep = 0 in L9677–12724). Root cause visible: `requires_payload = protocol.run_exploit and not module_path.startswith("auxiliary/")` (`resolver/config.py:385`) correctly excludes auxiliary modules from the validation issue, but `payload.required = protocol.run_exploit` (`config.py:452-453`) plus `run_exploit = not check_supported` (`:201-207`) still marks it required in the form.
10. **Same CVE, protocol contradiction**: form sets `execution_protocol.mode: exploit-only` / `run_exploit: true` (L1219-1226) for module `auxiliary/scanner/http/apache_optionsbleed` — an auxiliary scanner, not an exploit module (same origin as #9).
11. **Counting**: audit-discrepancy reported "12 reasons"; primary counted from the file: **13** in `schedule_field_guidance` + **1** in orchestrator = 14.

---

## 8.1.8 UNKNOWN items + resolving evidence

| # | UNKNOWN | Evidence that would resolve it |
|---|---|---|
| U1 | §2.3 HTTP 503 "high demand" — did it occur, against which model? | raw response capture or a new replay; no record exists in repo |
| U2 | §2.5 cause of `finish_reason:"length"` at 17 completion tokens — schema, hidden reasoning, or provider | a new completion with persisted `last_call_metadata` |
| U3 | §3.2 which other Gemini Flash models this key can access | persisted doctor result / model-list response (`doctor.py:104-135` currently persists nothing) |
| U4 | whether the (uncommitted) fix makes any WJoOf CVE pass `has_useful_evidence()` | replay `schedule_field_guidance` against existing WJoOf artifacts with current code |
| U5 | whether `KALAMA_GUIDANCE_CVES` silently filtered CVEs during WJoOf (silent skip :404-409) | env snapshot from that run, or a replay with known env |
| U6 | §3.4 whether CVE-2017-9798 would produce a validator-accepted suggestion given a normal completion | a real completion + validator decision |
| U7 | whether the WJoOf process loaded this same `.env` (cwd-dependent) | weakened: artifact `model: gemini-3.8-flash` matching `.env:5` is strong indirect evidence |

---

## 8.1.9 Bottleneck statement

**Bottleneck = GATE.** The WJoOf run never reached the provider: HEAD code called `factory()` zero-arg (`git show HEAD:src/kalama/resolution/llm_fields.py:381`) against a factory whose parameters all default, so the kwargs fallback was dead code and the collector was built with empty `target_facts`/`occurrences`/`candidates_by_cve` → every CVE failed `has_useful_evidence()` → `guidance_outcomes = ()` → `orchestrator.py:264` wrote `NO_ELIGIBLE_EVIDENCE_OR_FIELDS` with `cves: []` and no diagnostics key at all; the validator never received a proposal and the provider was never called in that run — while the provider-level claims (503 / `finish_reason=length`) and any validator-level verdict remain UNKNOWN with zero in-repo evidence and must stay in separate buckets per §0.6.

---

*End of §8.1 AUDIT REPORT. No code was edited. No Phase 2/3 action taken. Awaiting "proceed to plan".*
