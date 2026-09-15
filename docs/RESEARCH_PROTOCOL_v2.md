# Kalama / EVVP Research Protocol v2

**Status:** immutable after publication  
**Protocol version:** `v2`  
**Created at:** `2026-09-11T23:03:49Z`  
**Predecessor:** `docs/RESEARCH_PROTOCOL_v1.md`, SHA-256 `03e59159e93643667e7b2e6629f589f9fd75ad1a8427092e2d0df7ab50f195a2`

## Immutability and applicability

This document freezes the questions, hypotheses, variables, interpretation rules, and the currently observable implementation/provenance facts before confirmatory data collection. It must not be edited in place. Any correction or change requires a new protocol version and new hash.

Every future confirmatory paired run must record this exact protocol version and the SHA-256 in `docs/RESEARCH_PROTOCOL_v2.sha256`.

## Clock gate

`CLOCK_GATE = PASSED_BY_EXTERNAL_ADMIN_VERIFICATION`. The same host was verified in an elevated administrator PowerShell: W32Time Running; Leap Indicator 0; Stratum 5; source `time.windows.com,0x9` (reference IP `52.148.114.188`); last successful synchronization `2026-09-12 05:58:47` local time; poll interval 10. The non-elevated agent process received `Access is denied (0x80070005)` from `w32tm /query /status`; that is an agent-permission limitation, not evidence of an unsynchronized clock. No Windows Time configuration was changed.

## Source provenance

| Item | Frozen value |
| --- | --- |
| Git `HEAD` | `1b617928d2df66f14a0f62b48ef119472c3dbdce` |
| Index | No staged files |
| Working tree | Dirty: tracked production/test/documentation changes and untracked Kalama/Nuclei/research files are present. |
| Commit-only reproducibility | `SOURCE_PROVENANCE_NOT_FROZEN` — the current implementation is not fully represented by `HEAD`; no commit was made. |
| Deterministic current source snapshot | `docs/RESEARCH_PROTOCOL_v2.source-manifest.sha256`, SHA-256 `1c34a05afe909daf87cced6796a44e088926f129c2248670e38221011dc892df` |

The source snapshot hashes the current priority/dynamic-probe implementation, its configuration boundary, relevant tests, the dynamic design note, and v1. It deliberately excludes `diagnostics/`, `review-bundles/`, `lab-fixtures/`, `out.txt`, `err.txt`, and other experiment/output material. It is a snapshot of a dirty tree, not a substitute for a committed source revision.

Relevant untracked implementation/research inputs include `src/kalama/dynamic_probe.py`, `src/kalama/dynamic_probe_runtime.py`, `src/kalama/dynamic_research.py`, `src/kalama/dynamic_shadow.py`, `src/kalama/metasploit_fixtures.py`, dynamic-probe tests, `docs/DYNAMIC_PROBE_WAVE1.md`, and v1. Untracked `diagnostics/`, `review-bundles/`, and `lab-fixtures/` are retained but classified as pilot/diagnostic or fixture material, not source snapshot inputs.

## Frozen actual priority-v1 semantics

**Identifier:** `kalama-priority-v1`.

**Source locations:** `src/kalama/prioritizer/scoring.py`, `score_cve()` and `rank_cves()`; `src/kalama/prioritizer/pipeline.py`, `prioritize()` artifact fields `score_model`, `exposure_context`, and `top_n_requested`/`top_n_returned`.

For CVSS `c`, EPSS `e`, and KEV-listed indicator `k` (`1` when listed, otherwise `0`), the exact raw score is:

`S_raw = c + (3 × e) + (3 × k)`.

`score_cve()` requires finite `c ∈ [0,10]` and finite `e ∈ [0,1]`; it computes `epss_contribution = e × 3`, `kev_contribution = 3` only when `kev_listed`, and `total_raw = S_raw`. `total_display` is `S_raw` quantized to two decimal places using `ROUND_HALF_UP`. Ranking uses unrounded `total_raw`, then KEV-listed before non-listed, descending EPSS, descending CVSS, and lexicographic CVE ID. `rank_cves()` rejects incomplete CVSS, EPSS, or KEV evidence and returns at most `top_n` (default `30`).

CVSS is selected by `enrichment.select_cvss()` / `enrich_cvss()` from source/version/authority precedence; EPSS is an available score in `[0,1]`; KEV is `LISTED` or `NOT_LISTED`. Exposure is collected by `exposure_from_facts()` and serialized as `exposure_context`, but `pipeline.prioritize()` records `exposure_in_score: false`: exposure is not a score term. No other normalization or clamping occurs after the input-range validation; display rounding does not drive rank.

## Frozen experiment parameters

| Parameter | Current implementation value / semantics |
| --- | --- |
| Priority identifier | `kalama-priority-v1` |
| Top-N | default `30` (`prioritize(..., top_n=30)` and `rank_cves(..., top_n=30)`) |
| Dynamic provider/profile | `nuclei` / `safe-cve-http` (`src/kalama/dynamic_shadow.py`: `DYNAMIC_PROVIDER`, `DYNAMIC_PROFILE`) |
| Dynamic invocation | CLI `--dynamic-scan nuclei`, profile only `safe-cve-http`; dynamic scan is opt-in and default off (`src/kalama/cli.py`, `src/kalama/runtime.py`) |
| Dynamic signal taxonomy | `CORROBORATED`, `NOT_OBSERVED`, `NOT_APPLICABLE`, `NOT_RUN`, `INCONCLUSIVE` (`DynamicSignal`, `derive_dynamic_signal()`) |
| Signal derivation | any matched applicable binding → `CORROBORATED`; all applicable bindings clean → `NOT_OBSERVED`; no applicable templates → `NOT_APPLICABLE`; disabled → `NOT_RUN`; unresolved/incomplete coverage → `INCONCLUSIVE` |
| Application-path policy | root `/` is always first; optional comma-separated `KALAMA_NUCLEI_APP_PATHS` values are explicit operator input only, deduplicated, normalized as directory paths, maximum 8. No crawling, fuzzing, or CVE-derived path inference. Queries, fragments, backslashes, hosts/schemes, traversal, encoded traversal, and `//host` are rejected. Each binding is scoped to its normalized base path. |
| Template safety profile | HTTP only; redirects, OAST, remote templates, and runtime updates forbidden; excludes `intrusive`, `dos`, `fuzz`, `bruteforce`, `local` and non-HTTP protocols. A run-bound endpoint is required (`NucleiTemplatePolicy`). |
| BEFORE eligibility-policy reference | Existing `src/kalama/execution/oracle.py:classify_oracle()` → `MetricEligibility`; retain its `eligible`, conditions, and `exclusion_reason` unchanged. |

## Nuclei and template provenance: independently verified local state

No `KALAMA_NUCLEI_*` environment variables were configured in the agent process. The code reads the approved-manifest and template-root only from `KALAMA_NUCLEI_MANIFEST` and `KALAMA_NUCLEI_TEMPLATE_ROOT`; it defaults the binary name to `nuclei` and the runner-image tag to `kalama/nuclei-probe:pinned` when unset. Docker image/API inspection was denied to this process, so a tag is not evidence of an image identity.

| Required identity | Verified value |
| --- | --- |
| Approved manifest absolute / relative path | **UNAVAILABLE — `KALAMA_NUCLEI_MANIFEST` unset** |
| Approved manifest SHA-256 | **UNAVAILABLE** |
| `nuclei-templates` git revision | **UNAVAILABLE** |
| Template-tree SHA-256 | **UNAVAILABLE** |
| Approved template ID / relative path / SHA-256 / mapped CVEs | **UNAVAILABLE — no approved manifest configured** |
| Nuclei version | **UNAVAILABLE — configured binary not recoverable** |
| Nuclei binary SHA-256 | **UNAVAILABLE** |
| Runner image tag | Default code fallback only: `kalama/nuclei-probe:pinned`; no configured override verified |
| Runner image digest | **UNAVAILABLE — Docker API denied** |

These values were not copied from pilot reports or v1. The runtime itself persists manifest path/hash/revision/tree and per-template expected hashes only after a configured manifest has been loaded and validated; none is available for a confirmatory freeze in this environment.

## Research questions and hypotheses (unchanged from v1)

**RQ1:** Does locally observed dynamic validation evidence from Nuclei provide additional information about empirical exploitability among vulnerabilities selected by Kalama priority-v1?

Thai meaning: หลักฐานจากการตรวจสอบแบบ dynamic ด้วย Nuclei สามารถให้ข้อมูลเพิ่มเติมเกี่ยวกับความสามารถในการ exploit จริงของช่องโหว่ที่ถูกเลือกโดย Kalama priority-v1 ได้หรือไม่

**H0:** Among eligible Top-N candidates, the empirical BEFORE-exploit success rate for candidates with `CORROBORATED` dynamic evidence is not higher than for candidates without `CORROBORATED` evidence.

**H1:** Among eligible Top-N candidates, candidates with `CORROBORATED` dynamic evidence have a higher empirical BEFORE-exploit success rate than candidates without `CORROBORATED` evidence.

Statistical significance testing is deferred until the confirmatory sample is adequate. These hypotheses define a future comparison and do not imply support for H1.

**RQ2:** What proportion of priority-v1 Top-N candidates can be dynamically evaluated using the approved Nuclei `safe-cve-http` profile?

Report `CORROBORATED`, `NOT_OBSERVED`, `NOT_APPLICABLE`, `INCONCLUSIVE`, and `NOT_RUN`, plus dynamic coverage rate. `NOT_APPLICABLE` is not a failure.

**RQ3:** How do application/deployment path conditions affect dynamic validation results?

Preserve `base_path`, `base_path_source`, `scope_version`, each template × path result, and matched path. This is descriptive. Paths must be declared before exploit outcomes are known; no post-outcome path additions are permitted.

**RQ4:** How repeatable are dynamic validation and BEFORE exploit outcomes when the same target/configuration is executed repeatedly?

Report unique target/configuration observations separately from repeatability runs. Repeated executions must not increase the independent sample size.

## Variables, unit, and interpretation (unchanged from v1)

| Role | Frozen definition |
| --- | --- |
| Primary explanatory variable | `dynamic_positive = (dynamic_signal == CORROBORATED)` |
| Primary outcome | `exploit_positive`, using the existing BEFORE exploit evaluation policy unchanged |
| Eligibility | Existing BEFORE `metric_eligibility` policy; do not redefine it |
| Raw outcome | Preserve the raw BEFORE disposition separately |
| Primary unit of analysis | One Top-N candidate CVE in one run |
| Generalization unit | Distinguish independent target/configuration cases from repeatability runs |

`NOT_OBSERVED` does **not** mean “not vulnerable.” It means only that all approved template × declared application-path bindings completed successfully and produced no match within the declared dynamic-validation scope. Its relationship with exploit outcomes is descriptive unless a later protocol explicitly defines another analysis.

## Pilot treatment

`YUihQ` = pilot / preliminary unique target-configuration observation.

`5IULR` = pilot / preliminary repeatability run of the same target-configuration.

Neither is part of the future confirmatory dataset. Neither changes the independent confirmatory sample size.

## Protocol v1 correction and omissions

v1's displayed formula (`cvss + epss*3 + kev*3`) agrees with the actual raw formula; it is not inaccurate. v2 records material omitted semantics: validated input ranges, raw-score ranking, two-decimal `ROUND_HALF_UP` display-only rounding, deterministic tie-breakers, and explicit `exposure_in_score: false`.

v1 correctly marked manifest/revision/tree/manifest-hash fields absent, but did not include a deterministic dirty-tree source snapshot, approved-template entries and hashes, a verified binary identity, or a verified runner image digest. Those Nuclei fields remain unavailable rather than being invented.

## Confirmatory preconditions

No confirmatory measurement is authorized until all of the following are frozen and independently verified: (1) a committed source revision, or an explicitly accepted source snapshot together with the dirty-tree status; (2) the actual priority-v1 formula and Top-N above; (3) configured Nuclei binary path, version, and SHA-256; (4) runner image tag and immutable digest; (5) approved-manifest path and SHA-256; (6) template repository revision and tree SHA-256; (7) every approved template ID, relative path, SHA-256, and mapped CVE; (8) the dynamic profile and declared application paths; (9) this exact v2 SHA-256; and (10) raw dynamic records, raw BEFORE disposition, and existing eligibility-policy output for each future run.

Future confirmatory runs must record the exact v2 hash in `docs/RESEARCH_PROTOCOL_v2.sha256`. A later correction must create v3; this v2 file and checksum must not be edited.
