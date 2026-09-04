# Automatic Remediation Discovery v1 — Implementation Audit

**Repository:** `/home/distorion/kalama-labs-area/new-idea-kalama`
**Date:** 2026-09-01
**Type:** READ-ONLY IMPLEMENTATION AUDIT (no files modified)

**Method note (§2).** `git diff`/`git status` were **not possible**: the directory is **not a
git repository** (no `.git`). This audit therefore inspects the complete working tree as the
implementation. No file was modified. `python3 -m compileall -q src` → exit 0.
`.venv/bin/python -m unittest -v` → **227 passed / 0 failed / 0 skipped**.

---

## §1 Credentials

No credentials, tokens, or secrets encountered. No `POTENTIAL_SECRET_EXPOSURE`.
No API keys, registry auth, or shell history were inspected.

---

## §3 Experimental evidence vs implementation

The `remediation_experiment/README.md` findings (A=PASS, B=FAIL, C=PARTIAL; the rule that
`FixedVersion` is **not** an executable candidate; the mandate to distinguish `PROPOSED` from
`EXECUTABLE`; no LLM; no archive migration) are faithfully encoded in `discovery/models.py` and
the provider logic.

The implementation claims **no more** capability than the experiment justifies; it claims *less*:

- SOURCE_BUILD is **proposal-only**.
- PREBUILT stops at `KNOWLEDGE_REQUIRED`.
- OS package requires a live, non-mutating availability probe before becoming executable.

---

## §4 Reconstructed architecture (from executable production code)

```
ProductionRuntime._patch_plan_provider            (runtime.py:120)
  → RemediationDiscoveryService(runner=SubprocessCommandRunner,
                                container_name=<facts.container_name>,
                                source_root=$KALAMA_SOURCE_ROOT)          (runtime.py:127)
  → AutomaticRemediationProvider(service, output_root, container_name, source_root)  (runtime.py:129)
  → PatchPlanningOrchestrator(store, provider=AutomaticRemediationProvider)         (runtime.py:132)
      Orchestrator.run → build_patch_plan(..., provider, target_facts)              (orchestrator.py:172)
        planner.py groups occurrences → provider.candidate(...)                     (planner.py:71)
          AutomaticRemediationProvider.candidate → service.discover_occurrences     (service.py:168)
            _provider_for: os-pkgs → OsPackageProvider ; lang-pkgs → SourceBuildProvider (service.py:42)
          → _bridge(DiscoveredCandidate) → RemediationCandidate(trusted=False,
                                                  source_type=auto_discovered)       (service.py:52)
        → PatchAction + PlanningStatus.WAITING_FOR_USER_INPUT (trusted=False ⇒ reasons) (planner.py:96)
      → write_patch_plan ; provider.write_discovery_artifact (REMEDIATION_DISCOVERY) (orchestrator.py:196,208)
      → Patch Form (approval boundary)                                              (orchestrator.py:227)
      → PatchConfirmationOrchestrator → PatchExecutionOrchestrator → DockerPatchBackend (runtime.py:106)
```

Constructor wiring, runtime injection (`_patch_plan_provider`), provider routing
(`_provider_for`), artifact flow (`REMEDIATION_DISCOVERY` ArtifactKind), and state transitions
(plan → form → execution) are all confirmed from executable code. `ManualRemediationProvider`
(runtime.py:37) is now **dead code** — it is no longer passed to the orchestrator.

---

## §5 DISCOVERY_CONNECTED_TO_PRODUCTION: **YES**

`ProductionRuntime._patch_plan_provider` (runtime.py:120–132) is the single production
Patch-Planning boundary (`continue_once` → stage `"patch_plan"` → `self._patch_plan_provider(state).run(run_id)`
at runtime.py:105). It exclusively wires `AutomaticRemediationProvider`. The old
`ManualRemediationProvider` is retained but unused. Every remediation target in a production run
flows through discovery.

---

## §6 Separation of concepts

`discovery/models.py` defines independent enums:

- `DiscoveryClassification` (OS_PACKAGE / SOURCE_BUILD / PREBUILT_IMAGE / UNSUPPORTED / UNCLASSIFIED)
- `ClassificationStatus`, `VersionStatus`, `CandidateStatus` (RESOLVED/PARTIAL/UNRESOLVED/KNOWLEDGE_REQUIRED/…)
- `ExecutionReadiness` (READY / NOT_READY / HUMAN_CONFIRMATION_REQUIRED / NOT_EXECUTABLE)
- `AvailabilityStatus` (AVAILABLE / UNAVAILABLE / EOL_REPOSITORY / PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES / QUERY_TIMEOUT / …)

CVE‑2017‑9805 is represented exactly as the experiment expects:
`PREBUILT_IMAGE`, fixed `2.5.13`, `candidate_status=KNOWLEDGE_REQUIRED`, `availability=None`,
`execution_readiness=NOT_READY` (source_build.py:162). Nothing collapses to `resolved=true`.

---

## §7 OsPackageProvider audit

`os_package.py` uses `result_class=="os-pkgs"` or `result_type` in `_OS_TYPES`; consumes
`package_name`, `installed_version`, `fixed_versions`, `result_type` (SCANNER_EVIDENCE) plus
`container_name` (LOCAL_IMAGE_METADATA) for the probe. Families:

- `debian/ubuntu/deb → apt`
- `alpine/apk → apk`
- `rpm/rhel/centos/fedora → dnf`

The provider can obtain sufficient facts (distro/manager from `result_type`, availability from a
live probe).

**Caveats:**
- (a) `_distro_label` reads `target_facts["distro"]`/`["image_distro"]`/`["os"]`, but production
  `TargetFacts.to_dict()` (target/models.py:171–185) has **no such key** → the `runtime_distro`
  evidence and candidate `target` are never populated in production (distro is still derivable
  from `result_type`).
- (b) Unknown manager types (e.g. `suse`) → `UNSUPPORTED`/`NOT_EXECUTABLE`, no query (correct).

---

## §8 PACKAGE_AVAILABILITY_VALIDATION: **PASS** (minor caveat)

`OsPackageProvider._probe_availability` (os_package.py:216) runs a **non-mutating**
package-manager query inside the target container: `apt-cache policy <pkg>`, `apk policy <pkg>`,
dnf `repoquery`/`yum --showduplicates`. `apt-cache policy` only reads local package indexes — no
mutation, no network install.

- **Exact-version validated?** Yes — `parse_availability` requires the exact fixed-version token
  with exit 0 to mark `AVAILABLE`.
- **Non-mutating?** Yes.
- **Timeout bounded?** Yes — `runner.run(argv, timeout=query_timeout)`; timeouts (subprocess →
  exit 124) and raised exceptions map to non-executable `QUERY_TIMEOUT`/`UNAVAILABLE`.
- **Failures captured?** Yes — exit code, truncated stdout/stderr captured into
  `AvailabilityResult.evidence_or_error`.
- **Repository failure non-fatal?** Yes — becomes a WAITING action + Patch Form, not FAILED_FATAL.

`FixedVersion` alone never implies installability: executable `PACKAGE_AVAILABLE`/`DISCOVERED` is
set **only** when the probe confirms the exact version.

**Caveat:** the probe validates against the container's cached apt index (`apt-cache policy` does
not hit the network). For the EOL case it correctly reports the fixed u10 absent → UNAVAILABLE. It
cannot detect a repo that has the version in a *stale* local index but would 404 on install — a
conservative false-positive edge, not a safety break.

---

## §9 EOL_SAFETY: **PASS**

For CVE-2019-5481, `os_package.py` correctly produces `OS_PACKAGE`, `version_status=RESOLVED`
(fixed `7.52.1-5+deb9u10`), `candidate_status=UNAVAILABLE`,
`availability=PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES`/`UNAVAILABLE`, `eol=True`,
`execution_readiness=NOT_READY`.

There is **no** code that rewrites `apt sources.list`, switches to `archive.debian.org`, disables
signatures, allows unauthenticated packages, or invents mirrors. The executor's package command
(`apt-get update && apt-get install -y -- <pkg>=<ver>`, docker_backend.py `_package_command`) is
pre-existing and does not touch sources. An EOL/unavailable package can never become an executable
candidate.

---

## §10 SourceBuildProvider audit

`source_build.py` consumes `lang-pkgs`, `package_purl` (parsed to groupId:artifactId),
`installed_version`, `fixed_versions`, plus `local_manifests` (`pom.xml`/`Dockerfile`) from
`collect_local_manifests` (service.py:26).

It can derive Case A coordinates: `org.apache.struts:struts2-core` `2.3.30 → 2.3.32` (same-branch)
from scanner evidence, and — only when a local manifest is present — classify
`SOURCE_BUILD`/`A`/`REBUILD` proposal. Without a manifest it degrades to `PREBUILT_IMAGE`
KNOWLEDGE_REQUIRED (correct for CVE-2017-9805).

---

## §11 SOURCE_BUILD_AUTO_EXECUTION: **NO** ✓

No `mvn`, no `pom.xml` modification, no build shell generation, no subprocess build, no automatic
conversion to HUMAN_COMMAND in discovery. `SourceBuildProvider` emits only a proposal with
`execution_readiness=HUMAN_CONFIRMATION_REQUIRED`/`NOT_READY` and `trusted=False`. Tests `test_G`
and `test_J` assert no `mvn`/`apt-get`/`docker build` string and NOT_READY. Even at the codec layer,
a REBUILD is never READY unless a human supplies a command (codec.py:58). In default production
without `$KALAMA_SOURCE_ROOT`, no manifest is collected, so Case A would present as
PREBUILT_IMAGE/KNOWLEDGE_REQUIRED, not SOURCE_BUILD — conservative and safe.

---

## §12 Version-selection safety

`select_same_branch_fixed` (os_package.py:54) and `_select_target` (source_build.py:42) match on
**major**, then prefer **same minor**, and **never jump major** (no same-major match →
`None, False, "no fixed version on the installed major branch"` → PARTIAL). Ambiguity remains
unresolved (not silently chosen). For `2.3.32, 2.5.10.1` with installed `2.3.30`, both select
`2.3.32`. Ambiguous branches stay `PARTIAL`/`UNRESOLVED`.

**Caveat (MEDIUM, consistency, not safety):** within a same-minor match it picks the *highest*
(`pool[-1]`), but with only a major match it picks the *lowest* (`min`). The README states
`SAME_BRANCH_MINIMUM_FIXED`, so the same-minor branch selecting the maximum is inconsistent with
that stated policy (though it never crosses majors and never fabricates a version absent from
scanner evidence).

---

## §13 GUESSED_PREBUILT_TAGS: **NO** ✓

No `docker pull`, no registry probes, no `<repo>:<version>` concatenation, no Vulhub naming.
`SourceBuildProvider` returns `PREBUILT_IMAGE` + `KNOWLEDGE_REQUIRED` + `source_identifier=None` +
no availability. `test_L` asserts no `vulhub/struts2:2.5.13` / `rest-showcase` in output. The only
prebuilt resolution path reads a Human-supplied local image identity
(`docker_backend.resolve_prebuilt_image` reads `candidate.source_identifier`, set only by a Human
through the Patch Form).

---

## §14 MANUAL_PREBUILT_BACKWARD_COMPATIBILITY: **PASS**

`DockerPatchBackend.resolve_prebuilt_image` (docker_backend.py:153) is intact; the
`PatchExecutionOrchestrator` routes all-PREBUILT actions to it (execution_orchestrator.py:75,82).
A Human supplies a trusted local image → Patch Form → backend tags it. The manual flow is not
disabled.

---

## §15 HUMAN_CONFIRMATION_BYPASSED: **NO**

Discovery sets only `source_type="auto_discovered"`, `trusted=False`,
`CandidateStatus.DISCOVERED`, `ExecutionReadiness.HUMAN_CONFIRMATION_REQUIRED` (available OS pkg).
It never sets `HUMAN_CONFIRMED`, `AUTO_CONFIRMED`, `VERIFIED`, `PATCH_SUCCEEDED`,
`READY_TO_EXECUTE`. `trusted=False` forces `ARTIFACT_SOURCE_UNRESOLVED` in the planner →
`WAITING_FOR_USER_INPUT` → Patch Form. `confirmation.py` sets `trusted=True`/`human_confirmed_fields`
only on explicit Human confirmation, with tamper checks (`PATCH_FORM_TAMPERED`), revision checks
(`STALE_PATCH_FORM`), base-SHA lineage, run identity, and an editable-field allowlist — all
preserved. Executable OS candidates require `HUMAN_CONFIRMATION_REQUIRED`.

---

## §16 EMPIRICAL_VERIFICATION_SEMANTICS_CHANGED: **NO**

Discovery never writes `CVE_REMOVED`/`PATCH_SUCCESS`/`EXPLOIT_FIXED`/`OracleVerdict`/
`MetricEligibility`/`REMEDIATION_RESULT`. `test_N` asserts no success verdict nor `CVE_REMOVED` in
discovery evidence. `PatchExecutionOrchestrator` publishes `remediation_verified=False` until
downstream stages produce empirical facts; the Trivy After / reachability / re-exploit / oracle
chain is unchanged.

---

## §17 DISCOVERY_FAILURE_FALLBACK: **PASS**

Every failure mode leads to a non-executable candidate and a `WAITING_FOR_USER_INPUT` Patch Form
(Human can continue), not FAILED_FATAL:

| Failure mode | Result |
|---|---|
| repository unavailable | `UNAVAILABLE`/`PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES` → NOT_READY |
| provider timeout | `QUERY_TIMEOUT` → NOT_READY |
| unsupported distro | `UNSUPPORTED`/`NOT_EXECUTABLE` → WAITING action |
| missing FixedVersion | `VersionStatus.UNRESOLVED` → NOT_READY |
| missing manifest | PREBUILT KNOWLEDGE_REQUIRED → NOT_READY |
| knowledge required / unexpected provider exception | captured inside `_probe_availability` → non-executable |
| discovery-artifact write failure | swallowed non-fatally (orchestrator.py:221) |

Even `runner=None` degrades to `QUERY_TIMEOUT`, not a crash. `FAILED_FATAL` is reserved for genuine
canonical-state corruption (missing plan/form, tampering, `PATCH_PLAN_INTEGRITY_ERROR`).

---

## §18 PROVENANCE_AUDITABILITY: **PARTIAL**

`DiscoveryEvidence.fact + provenance` (`SCANNER_EVIDENCE`, `LOCAL_IMAGE_METADATA`,
`LOCAL_SOURCE_METADATA`, `PACKAGE_MANAGER_METADATA`) records per finding: classification, package,
installed/fixed version, branch policy, and the availability query result
(`availability_query_attempted` + `AvailabilityResult`). A reviewer can answer *which FixType,
where the version came from, and whether availability was probed and why execution is
allowed/denied*.

**Gap:** because production `TargetFacts` has no `distro` field, the `runtime_distro` evidence
(`LOCAL_IMAGE_METADATA`) and the candidate `target` field are never populated at runtime (§7a) —
distro authority is only implied via `result_type` (tagged `SCANNER_EVIDENCE`, not
`LOCAL_IMAGE_METADATA`). Source-build per-occurrence facts are emitted from a shared list, so some
facts are duplicated verbatim (noisy, not incorrect).

---

## §19 Artifact/state compatibility: **no migration risk**

Changes are additive: a new `ArtifactKind.REMEDIATION_DISCOVERY` enum member, and
`RemediationCandidate` gained optional fields (`classification`, `candidate_status`,
`execution_readiness`, `availability`, `discovery_issue`, `evidence`, …) all with defaults.
`PATCH_PLAN_SCHEMA`, `PATCH_FORM_SCHEMA`, `RunState`, and serialization/deserialization
(`codec.py`) remain backward compatible. Existing saved runs/artifacts remain readable.

---

## §20 Executor regression / scope expansion: **none**

`DockerPatchBackend` preserves `PACKAGE_MANAGER`, `HUMAN_COMMAND`, `PREBUILT_IMAGE_REPLACEMENT`.
Deferred executors return `*_EXECUTOR_NOT_CONFIGURED`: `REBUILD`, `ARTIFACT_REPLACEMENT`,
`COPACETIC`, `MUTATION`, `DOCKER_COMMIT`. No generic rebuild/artifact executor, no Copacetic
integration, no automatic EOL migration introduced. The executor was not rewritten.

---

## §21 Forbidden features: all **NO**

| Check | Result |
|---|---|
| LLM_REMEDIATION_INTRODUCED | NO (only pre-existing exploit-guidance LLM; unrelated) |
| RAG_INTRODUCED | NO |
| COPACETIC_INTRODUCED | NO (only an existing enum value/strategy-token; executor refuses it) |
| REGISTRY_CRAWLING_INTRODUCED | NO |
| GENERIC_REBUILD_EXECUTOR_INTRODUCED | NO |

---

## §22 Unit-test audit

The discovery suite genuinely covers (assertions verified): available OS pkg (A), unavailable (B),
repository timeout (C), missing FixedVersion (D), multiple packages same CVE (E, per-package
probes), unsupported distro (F), Maven candidate (G), missing manifest → PREBUILT
KNOWLEDGE_REQUIRED (H), ambiguous/no-majorjump branch (I), no build shell command (J), prebuilt
no-fixed-image-candidate (K), no guessed tag (L), discovery never human-confirms (M), never
success-verdict (N), discovery artifact write (O). Orchestrator-level discovery+plan+form
integration test present. Human confirmation preserved; manual Patch Form preserved;
`remediation_verified=False` preserved.

**Coverage gaps:**
1. **No** end-to-end test drives a `PREBUILT_IMAGE_REPLACEMENT` action through
   `PatchExecutionOrchestrator`/`DockerPatchBackend` — the `resolve_prebuilt_image` fake is never
   invoked.
2. No test for multiple-package **mixed** availability (one available, one not) asserting overall
   non-executability.
3. No test of the dnf/repoquery RPM path.
4. No test of the `_distro_label` production gap.
5. No test wires `ProductionRuntime._patch_plan_provider` itself (env `KALAMA_SOURCE_ROOT`,
   container_name extraction untested).

---

## §23 Regression run

```
python3 -m compileall -q src        → exit 0
.venv/bin/python -m unittest -v     → Ran 227 tests; OK (0 failed, 0 skipped)
```

Run with the repo's existing `.venv`. No new dependencies installed.

---

## §24 Static production smoke

`RemediationDiscoveryService`, `AutomaticRemediationProvider`, `PatchPlanningOrchestrator`,
`DockerPatchBackend`, `PatchExecutionOrchestrator`, `PatchConfirmationOrchestrator` all
import/instantiate cleanly under the repo venv. No production run was started (no mutation),
consistent with the audit constraints.

---

## §25 Three-case prediction vs production capability

**Case A — CVE-2017-5638.** Requires `$KALAMA_SOURCE_ROOT` set to a dir containing `pom.xml`.
Then: `SOURCE_BUILD`, build_system `maven`, current `org.apache.struts:struts2-core 2.3.30`,
target `2.3.32`, candidate DISCOVERED but `execution_readiness=NOT_READY`/proposal-only,
`trusted=False` ⇒ Human confirmation required, automatic build `NO`. **Capable.**
*Note:* without `KALAMA_SOURCE_ROOT`, it classifies as `PREBUILT_IMAGE`/KNOWLEDGE_REQUIRED —
conservative, not wrong.

**Case B — CVE-2017-9805.** `PREBUILT_IMAGE`, fixed `2.5.13` (same-branch),
`source_identifier=None`, `candidate_status=KNOWLEDGE_REQUIRED`, `availability=None`,
`execution_readiness=NOT_READY`, no Docker tag. **Exactly matches.**

**Case C — CVE-2019-5481.** `OS_PACKAGE`, packages `curl`/`libcurl3`/`libcurl3-gnutls`, installed
`7.52.1-5+deb9u9`, fixed `7.52.1-5+deb9u10`, availability
`UNAVAILABLE`/`PACKAGE_NOT_IN_CONFIGURED_REPOSITORIES` (EOL repos), `eol=True`,
`execution_readiness=NOT_READY`. **Exactly matches.**

---

## §26 EXPERIMENT_CASE_HARDCODING: **NO**

`CVE-2017-5638`/`CVE-2017-9805`/`2.3.32`/`7.52.1`/`struts2-core`/`vulhub/struts2` appear **only in
comments and READMEs**, never in executable routing/selection logic. No fixed-version maps, no
special-cased CVEs, no package-repo overrides. Logic is generic over scanner evidence.

---

## §27 Code-quality review

**LOW**
- `service.py:192` imports the private helper `_atomic_write` from `resolution.artifacts`
  (private cross-module coupling).
- Command strings for `sh -lc` (`apt-cache policy {package}`, dnf/yum paths) are not
  `shlex.quote`d, unlike `docker_backend._package_command`. Package names originate from scanner
  evidence (trusted-ish) — low risk, but an injection surface.
- `_combine_availability`/`_combine_status` have partially redundant/dead branches; cosmetic, and
  the higher-level execution_readiness combine still forces NOT_READY on any mismatch.

**No CRITICAL, no HIGH, no MEDIUM correctness/safety defect found.** No `shell=True`, no unbounded
retries, no temp-file leakage, no hidden mutable global state; host commands use `shell=False`.

---

## §28 Final implementation matrix

| Requirement | Status | Evidence |
|---|---|---|
| Production discovery wiring | **PASS** | runtime.py:120–132 |
| OS package classification | PASS | os_package.py `_is_os_package`+`_OS_TYPES` |
| FixedVersion handling | PASS | §6 separation; `VersionStatus` |
| Package availability validation | PASS | non-mutating probe; timeout; captured |
| EOL safe refusal | PASS | §9; no sources rewrite/archive/unauthenticated |
| Source/Maven discovery | PASS | source_build.py PURL+manifest |
| Source proposal-only safety | PASS | §11; NO auto-execution |
| Branch-safe version selection | PARTIAL | §12 (no major jump ✓; same-minor selects max) |
| Prebuilt KNOWLEDGE_REQUIRED behavior | PASS | §6, §13, §25B |
| No guessed image tags | PASS | §13 (GUESSED_PREBUILT_TAGS: NO) |
| Human confirmation preserved | PASS | §15 (trusted=False → Patch Form) |
| Provider failure fallback | PASS | §17 (non-fatal → WAITING) |
| Provenance | PARTIAL | §18 (distro evidence not populated in production) |
| Existing Patch Executor preserved | PASS | §20 (3 strategies intact; deferred executors refuse) |
| Trivy/re-exploit/oracle semantics preserved | PASS | §16 (`remediation_verified=False`) |
| Backward compatibility | PASS | §19 additive-only |
| Unit/regression tests | PARTIAL | §22/§23 (227 pass; PREBUILT-end-to-end + mixed + wiring gaps) |

---

## §29 Findings list (no fixes applied)

**ID: F1 — Severity: MEDIUM — File: `src/kalama/remediation/discovery/os_package.py` — Function: `select_same_branch_fixed`**
Problem: With a same-minor match it returns `pool[-1]` (highest fixed on that minor), but with only
a same-major match it returns `min(...)` (lowest). The two branches use opposite selection
directions and both diverge from the README's stated `SAME_BRANCH_MINIMUM_FIXED` policy (pick the
minimum fixed ≥ installed). Why it matters: may choose a higher fixed version than necessary on the
branch; internally inconsistent. Evidence: lines 71–75. Recommended fix: pick the minimum fixed ≥
installed consistently across both branches (or align the documented policy with the algorithm).
Not a safety violation (never crosses major, never fabricates a version absent from scanner
evidence).

**ID: F2 — Severity: MEDIUM — File: `src/kalama/remediation/discovery/os_package.py` — Function: `_distro_label` / `_discover_one`**
Problem: `_distro_label` reads `target_facts["distro"]/["image_distro"]/["os"]`, but production
`TargetFacts.to_dict()` (target/models.py:171–185) has no such key, so the `runtime_distro`
evidence and candidate `target` are never populated; distro authority is only implied by
`result_type` (tagged SCANNER_EVIDENCE). Why it matters: muddies provenance (§18) and drops a
planned LOCAL_IMAGE_METADATA fact. Evidence: os_package.py:42–46,262–267. Recommended fix: derive
OS/distro from a genuinely present runtime fact (e.g. read `/etc/os-release` via `docker exec`, or
add a `distro` field to `TargetFacts`), or drop the misleading evidence.

**ID: F3 — Severity: LOW — File: `src/kalama/remediation/discovery/os_package.py` — Function: `build_availability_query`/`_query_argv`**
Problem: Package names are interpolated unquoted into `sh -lc` command strings (apt/dnf/yum paths),
unlike the executor which `shlex.quote`s. Why it matters: a hostile/malformed `package_name` from
scanner evidence could inject shell metacharacters into a container-scoped command. Evidence:
os_package.py:82–86,213. Recommended fix: `shlex.quote` package (and version) before interpolation.

**ID: F4 — Severity: LOW — File: `src/kalama/remediation/discovery/service.py` — Function: `AutomaticRemediationProvider.write_discovery_artifact`**
Problem: Imports and reuses the private `_atomic_write` from `resolution.artifacts` (artifacts.py:145).
Why it matters: private cross-module coupling increases breakage risk. Recommended fix: expose a
public writer in `resolution.artifacts`.

**ID: F5 — Severity: LOW — File: `src/kalama/remediation/discovery/os_package.py` — Function: `_combine_availability`/`_combine_status`**
Problem: Redundant/dead branches; combined `availability` after a mixed-multi-package case reflects
only the first package. Why it matters: review/maintainability. Safety preserved because
execution_readiness combine forces NOT_READY on any mismatch. Recommended fix: "AVAILABLE only if
all probed packages available; else NOT_READY" and fix status-token comparisons.

**Coverage gaps (not code fixes):**
- (a) no end-to-end test drives `PREBUILT_IMAGE_REPLACEMENT` through the executor;
- (b) no mixed-availability (one pkg available, one not) multi-package test;
- (c) no dnf/RPM path test;
- (d) no test of `ProductionRuntime._patch_plan_provider` wiring.

**Process note:** the repository is not under git, so the §2 diff-based scope analysis (files
added/modified/deleted by the implementing agent) could not be performed; the audit was conducted on
the complete working tree.

---

## §30 Final verdict

```
AUTOMATIC_REMEDIATION_DISCOVERY_CODE_AUDIT:
PARTIAL

SAFE_TO_RUN_LIVE_PRODUCTION_E2E:
YES

SAFE_TO_MERGE:
YES

MINIMUM_FIXES_BEFORE_E2E:
1. Verification that the target `TargetFacts` carrier includes a real distro field (or derive OS
   from runtime) so the `runtime_distro` evidence/provenance is populated; otherwise confirm
   `result_type` alone is acceptable as the distro authority for E2E.
2. Confirm/align the same-branch version-selection direction (F1) with the documented
   `SAME_BRANCH_MINIMUM_FIXED` policy before relying on chosen target versions.
3. (Recommended, not blocking) add an end-to-end `PREBUILT_IMAGE_REPLACEMENT` execution test and a
   mixed-multi-package availability test.
```

**Rationale for PARTIAL (not PASS):** all hard safety boundaries are respected (no unsafe guessing,
availability validation works, EOL packages cannot become executable candidates, SourceBuild
proposal-only, Prebuilt stays KNOWLEDGE_REQUIRED, human confirmation mandatory, oracle/verification
semantics unchanged, regression tests pass). PASS was withheld for two MEDIUM, non-safety findings
(F1 branch-selection inconsistency; F2 distro provenance not populated in production) plus the
test-coverage gaps in §28/§29. `SAFE_TO_MERGE=YES` is granted because **no CRITICAL or HIGH
correctness/safety issue** exists, and the MEDIUM items are correctness/provenance refinements, not
blockers.
