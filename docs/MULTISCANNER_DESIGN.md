# Multi-Scanner Design (Revised)

This document audits the current Kalama / EVVP production code and proposes an
implementation-ready design for adding Grype alongside Trivy without changing
the exploitation, resolver, patch execution, retry, LLM guidance, or frontend
surfaces in this round.

Revision status: this is the corrected design addressing the seven review
corrections (finding/candidate identity, availability vs. completeness,
metric preservation, fixed-version provenance, approved configuration, run
isolation, implementation sequence). No production code is modified in this
round. Do not begin implementation until explicitly authorized.

## Scope and Method

This is an architecture audit and design revision only. It does not run
exploit, patch, scanner, Docker cleanup, or external target operations. It
does not modify orchestrator, prioritizer, patch planning, verification,
evaluation, CLI, or setup scripts.

Scanner findings remain predictions and metadata. Exploit and re-exploit
evidence remain the empirical validation layer and must not be derived from
scanner agreement.

## Current Architecture

### BEFORE scan execution

Step 2 is Trivy-first and has no scanner abstraction boundary yet.

- `src/kalama/target/coordinator.py:8` imports `scan_image` from
  `trivy_scanner.py` directly.
- `src/kalama/target/coordinator.py:16` exposes `execute_step2(...,
  trivy_timeout=None)`.
- `src/kalama/target/coordinator.py:26` calls `scan_image(image,
  Path(request.output_path), runner, timeout=trivy_timeout)`.
- `src/kalama/target/trivy_scanner.py:17` validates Trivy JSON only.
- `src/kalama/target/trivy_scanner.py:43` builds this command:
  `trivy image --scanners vuln --list-all-pkgs --format json --output <path>
  <subject>`.
- `src/kalama/target/trivy_scanner.py:48` writes to a temporary file, runs the
  scanner, validates JSON, fsyncs it, atomically publishes it, and returns a
  `TrivyArtifact`.
- `src/kalama/target/models.py:27` defines scanner failures as Trivy-specific
  `TRIVY_NOT_AVAILABLE`, `TRIVY_EXECUTION_FAILED`, `TRIVY_INVALID_JSON`, and
  `TRIVY_SCHEMA_UNSUPPORTED`.
- `src/kalama/target/models.py:191` defines `TrivyArtifact`, including
  `trivy_version`, `scan_subject`, image identity, artifact path, sha256, schema
  version, and created timestamp.
- `src/kalama/target/models.py:212` defines `Step2Result.trivy_artifact`.

### Workbench scanner routing

The scanner is executed through the managed workbench container.

- `src/kalama/target/workbench.py:13` defines `WorkbenchToolRunner`.
- `src/kalama/target/workbench.py:21` routes only commands whose first argv item
  is `trivy` into `docker exec <workbench>`.
- `src/kalama/target/workbench.py:24` removes `--output` before entering the
  workbench and writes stdout bytes back to the host output path.
- `setup-workbench.sh:7` pins `KALAMA_TRIVY_VERSION`, default `0.74.0`.
- `setup-workbench.sh:78` installs Trivy from GitHub release tarball with
  checksum verification inside `kalama-workbench-modern`.
- `src/kalama/doctor.py:124` checks `docker exec <workbench> trivy --version`.

There is no Grype installation, version check, or routing branch.

### State and artifact persistence

Current state contracts are public and persisted.

- `src/kalama/state/models.py:48` defines `ArtifactKind.TRIVY_BEFORE`.
- `src/kalama/state/models.py:63` defines `ArtifactKind.TRIVY_AFTER`.
- `src/kalama/state/models.py:64` defines `ArtifactKind.REMEDIATION_SCAN_RESULT`.
- `src/kalama/state/models.py:230` defines `RunState`.
- `src/kalama/state/models.py:269` replaces artifacts by `ArtifactKind`; prior
  hashes move to `artifact_history`.
- `src/kalama/state/store.py:71` deserializes `RunState`.
- `src/kalama/state/store.py:114` rejects unknown artifact kinds, so new artifact
  kinds are a compatibility decision.
- `src/kalama/orchestrator.py:110` writes the BEFORE scan to
  `trivy/before/scan_<date>_<run_id>.json`.
- `src/kalama/orchestrator.py:144` persists that scan as `TRIVY_BEFORE`.
- `src/kalama/orchestrator.py:182` requires committed `TRIVY_BEFORE` before
  prioritization.

Historical runs depend on `TRIVY_BEFORE`, `TRIVY_AFTER`, schema `2`, and the
directory shape `trivy/<phase>/...`.

### Prioritization

The prioritizer has useful scanner-agnostic pieces, but its entry point and
artifact inputs are Trivy-specific.

- `src/kalama/prioritizer/trivy_parser.py:1` is the only scan parser.
- `src/kalama/prioritizer/trivy_parser.py:91` parses Trivy schema 2.
- `src/kalama/prioritizer/trivy_parser.py:136` emits
  `VulnerabilityOccurrence` values.
- `src/kalama/prioritizer/trivy_parser.py:193` aggregates occurrences by
  canonical CVE.
- `src/kalama/prioritizer/models.py:45` names parse failures
  `INVALID_TRIVY_ARTIFACT`, `UNSUPPORTED_TRIVY_SCHEMA`, and
  `TRIVY_FINDING_INVALID`.
- `src/kalama/prioritizer/models.py:77` defines `VulnerabilityOccurrence`, which
  already carries package identity, versions, result type/class, scanner
  severity, CVSS candidates, URLs, references, and timestamps.
- `src/kalama/prioritizer/models.py:97` deduplicates one occurrence by
  `canonical_cve_id`, `target`, `result_class`, `result_type`, package identity,
  installed version, and fixed versions.
- `src/kalama/prioritizer/pipeline.py:22` imports `parse_trivy_report`.
- `src/kalama/prioritizer/pipeline.py:29` exposes `prioritize_trivy`.
- `src/kalama/prioritizer/pipeline.py:55` records `inputs.trivy`.
- `src/kalama/prioritizer/pipeline.py:114` reads a single input file and calls
  `prioritize_trivy`.
- `src/kalama/orchestrator.py:32` defines `Step3Invocation.trivy_sha256`.
- `src/kalama/orchestrator.py:48` passes only the committed Trivy path to
  `prioritize_file`.

The scoring formula is already separate enough to keep unchanged:
`cvss + epss*3 + kev*3` (`kalama-priority-v1`, see
`src/kalama/prioritizer/models.py:232` `ScoreBreakdown` and
`src/kalama/prioritizer/scoring.py`). It must stay unchanged in this round.

### Resolver, Attack Form, and exploitation

These stages consume the prioritization artifact, not raw scanner output.

- `src/kalama/resolution/resolver_stage.py:52` parses ranked CVE input from
  `TOP30_BEFORE`.
- `src/kalama/resolution/orchestrator.py:81` verifies `TOP30_BEFORE`.
- `src/kalama/resolution/orchestrator.py:121` writes `RESOLVER_BEFORE` and
  Attack Form artifacts.
- `src/kalama/execution/orchestrator.py` consumes confirmed exploit config and
  target facts. It should not be changed for multi-scanner.

The multi-scanner change should preserve the shape of `ranked_cves` enough that
resolver and Attack Form behavior remain unchanged.

### Patch planning and discovery

Patch planning consumes successful exploit outcomes plus `ranked_cves`
occurrences.

- `src/kalama/remediation/orchestrator.py:143` still requires
  `ArtifactKind.TRIVY_BEFORE` lineage in addition to `ATTACK_BEFORE` and
  `TOP30_BEFORE`.
- `src/kalama/remediation/orchestrator.py:182` records `inputs.trivy_before` in
  the patch plan.
- `src/kalama/remediation/planner.py:34` builds patch actions from successful
  CVEs and the `occurrences` embedded in `TOP30_BEFORE`.
- `src/kalama/remediation/planner.py:41` indexes occurrences by `cve_id`.
- `src/kalama/remediation/planner.py:69` unions `fixed_versions` across
  occurrences into one flat `fixed` tuple passed as `scanner_fixed_versions`.
- `src/kalama/remediation/discovery/service.py:98` routes occurrence sets to OS
  package or source build discovery.
- `src/kalama/remediation/discovery/service.py:133` accepts
  `scanner_fixed_versions` as a flat version list without scanner provenance.
- `src/kalama/remediation/discovery/os_package.py` treats occurrence fields as
  scanner evidence and only marks a candidate executable after an independent
  non-mutating package-manager availability probe. Approved discovery policy
  (see `src/kalama/remediation/discovery/README.md`): same-branch-only target
  selection, `FIX_VERSION_KNOWN` is distinct from `PACKAGE_AVAILABLE`, source
  rebuilds are proposal-only, prebuilt-image replacement without a trusted
  mapping is `KNOWLEDGE_REQUIRED`.

The planner assumes a single merged occurrence list per CVE. Section 4 below
corrects the earlier proposal: the flat union must not become an unqualified
single source of truth once two scanners are present.

### AFTER scan and scanner remediation comparison

Step 6 is also Trivy-specific.

- `src/kalama/verification/orchestrator.py:15` imports `parse_trivy_report`.
- `src/kalama/verification/orchestrator.py:22` imports `scan_image`.
- `src/kalama/verification/orchestrator.py:31` defines `AfterScanner` returning
  `TrivyArtifact`.
- `src/kalama/verification/orchestrator.py:49` implements
  `production_after_scanner` by reusing Step 2 `scan_image`.
- `src/kalama/verification/orchestrator.py:134` loads
  `ArtifactKind.TRIVY_BEFORE`.
- `src/kalama/verification/orchestrator.py:172` writes AFTER scan to
  `trivy/after/scan_<date>_<run_id>.json`.
- `src/kalama/verification/orchestrator.py:188` persists it as `TRIVY_AFTER`.
- `src/kalama/verification/orchestrator.py:197` parses before and after with
  `parse_trivy_report`.
- `src/kalama/verification/orchestrator.py:216` writes
  `REMEDIATION_SCAN_RESULT` with `inputs.trivy_before` and `inputs.trivy_after`.
- `src/kalama/verification/comparison.py:21` groups occurrences by canonical CVE
  only for scanner remediation status.
- `src/kalama/verification/comparison.py:47` returns `FOUND`, `NOT_FOUND`, or
  `UNKNOWN` and marks `scanner_remediation_verified` when the CVE is absent.

With multiple scanners, absence from one scanner must become per-scanner
absence, not global remediation success. Section 2 below replaces the earlier
union rule, which was unsound when one scanner failed.

### Evaluation and run summary

Evaluation correctly treats exploit evidence as empirical ground truth, but its
scanner fields are single-after-scan.

- `src/kalama/evaluation/orchestrator.py:75` requires `TOP30_BEFORE`,
  `ATTACK_BEFORE`, and `REMEDIATION_RESULT`.
- `src/kalama/evaluation/metrics.py:23` builds records from selected Top N,
  attack result, and remediation result.
- `src/kalama/evaluation/metrics.py:57` records one `after_scan_status`.
- `src/kalama/evaluation/metrics.py:125` cross-tabs one scanner status against
  final remediation status.
- `src/kalama/evaluation/orchestrator.py:101` explicitly scopes metrics to
  `TOP_N_ONLY`; predicted negatives are not empirically evaluated.
- `src/kalama/evaluation/orchestrator.py:153` writes Run Summary
  `after_scan` from the `REMEDIATION_SCAN_RESULT` artifact summary.
- `src/kalama/evaluation/metrics.py:89` computes Precision, Recall, F1, and
  accuracy with explicit unavailability reasons
  (`PREDICTED_NEGATIVES_NOT_EMPIRICALLY_EVALUATED`, `RECALL_UNAVAILABLE`,
  `INCOMPLETE_CONFUSION_MATRIX`). These semantics must remain intact.

This layer must add scanner provenance and union/individual datasets without
changing Precision@N semantics. Section 3 below corrects the earlier proposal,
which risked relabeling a union-selected subset as a scanner's independent
Precision@N.

## Dependency Map

Current flow:

```text
Step2 target/coordinator.execute_step2
  -> target/trivy_scanner.scan_image
  -> TRIVY_BEFORE artifact
  -> prioritizer/pipeline.prioritize_file
  -> prioritizer/trivy_parser.parse_trivy_report
  -> TOP30_BEFORE ranked_cves
  -> resolver / Attack Form / BEFORE exploit
  -> patch planning reads TOP30_BEFORE occurrences and TRIVY_BEFORE lineage
  -> patch execution creates patched image and after target
  -> verification/orchestrator.production_after_scanner
  -> TRIVY_AFTER artifact
  -> verification/comparison.compare_remediation_targets
  -> REMEDIATION_SCAN_RESULT
  -> re-exploit / remediation result / evaluation / run summary
```

Scanner-sensitive contracts:

- `ArtifactKind.TRIVY_BEFORE`, `ArtifactKind.TRIVY_AFTER`
- `TrivyArtifact`, `Step2Result.trivy_artifact`
- Step 2 output path `trivy/before/...`
- Step 6 output path `trivy/after/...`
- `inputs.trivy`, `inputs.trivy_before`, `inputs.trivy_after`
- `trivy_version`
- Trivy schema `SchemaVersion == 2`
- `VulnerabilityOccurrence` fields extracted from Trivy names
- `VulnerabilityOccurrence.identity` (occurrence-dedup key, not a
  cross-phase match key; see correction in Section 1)
- patch plan lineage to `trivy_before`
- remediation scan result summary as one scanner verdict
- tests that import `scan_image`, `parse_trivy_report`, `TrivyArtifact`, and
  `ArtifactKind.TRIVY_*`

## Existing Fixtures

The repository has a Trivy fixture at
`tests/unit/fixtures/trivy_realistic.json`. It includes:

- top-level `SchemaVersion`, `Trivy.Version`, `ReportID`, `CreatedAt`,
  `ArtifactID`, `ArtifactName`
- per-result `Target`, `Class`, `Type`
- per-vulnerability `VulnerabilityID`, `PkgName`, `InstalledVersion`,
  `FixedVersion`, `PkgIdentifier.PURL`, `PkgIdentifier.UID`, `Severity`,
  `SeveritySource`, `CVSS`

No committed Grype fixture was found in the production/test tree during this
audit. A Grype fixture must be added from actual Grype JSON before implementing
the parser. Do not invent Grype field names from memory.

## Proposed Architecture

Add a scanner-agnostic layer, but keep legacy Trivy artifacts readable.

```text
ScannerAdapter protocol
  -> TrivyAdapter
  -> GrypeAdapter
  -> raw scanner artifacts per scanner/per phase
  -> ScanSet artifact per phase
  -> NormalizedFinding list with provenance
  -> canonical union candidates
  -> existing ranking formula
  -> existing resolver/exploit/patch stages
  -> per-scanner AFTER comparisons + union comparison
```

New concepts (corrected; see Sections 1-2 for normative definitions):

- `ScannerAdapter`: executes one scanner and returns a structured scan record.
- `RawScannerArtifact`: immutable raw output plus status, command, version,
  timestamps, target identity, path, sha256, and parser status.
- `ScanSet`: phase-level artifact that references all raw scanner outputs and
  contains normalized findings.
- `NormalizedFinding`: one scanner observation within one run/phase/image/raw
  report (finding identity). Never matched across phases by finding identity.
- `UnionCandidate`: the vulnerability/component under evaluation across stages
  (candidate identity), carrying `detected_by`, `not_detected_by`,
  `not_selected`, `unknown`, and per-scanner `scanner_findings` with full
  provenance.
- `ComponentMapping`: the BEFORE-to-AFTER linkage for one candidate in one
  scanner, resolving version upgrades, renames, relocations, and image changes
  explicitly, or returning `UNKNOWN`.
- `ScannerPresence`: per-candidate scanner detection map, preserving scanner
  disagreements. `NOT_SELECTED` is distinct from `NOT_FOUND`.
- `ComparisonCompleteness`: whether the union comparison is complete, kept
  independent from scanner execution continuation and from empirical
  remediation validation.

Recommended initial scanners:

- `trivy`
- `grype`

Do not add Nuclei yet. Design `ScannerAdapter` so Nuclei can be added later
without changing the pipeline again.

## Proposed Normalized Schema

Add a new artifact schema, for example `kalama.scan-set/v1`.

```json
{
  "schema": "kalama.scan-set/v1",
  "run_id": "AoFTs",
  "phase": "before",
  "attempt": 1,
  "created_at": "2026-09-09T00:00:00Z",
  "target": {
    "requested_image": "vulhub/elasticsearch:1.4.2",
    "scan_subject": "sha256:...",
    "image_id": "sha256:...",
    "image_digest": null,
    "container_name": "victim-AoFTs",
    "container_id": "...",
    "network": "kalama-net",
    "ip_address": "172.18.0.10"
  },
  "selection": {
    "selected_scanners": ["trivy", "grype"],
    "candidate_policy": "union",
    "comparison_complete": true,
    "incomplete_reasons": []
  },
  "scanners": [
    {
      "scanner": "trivy",
      "status": "SUCCEEDED",
      "version": "0.74.0",
      "started_at": "2026-09-09T00:00:00Z",
      "completed_at": "2026-09-09T00:00:01Z",
      "raw_artifact": {
        "kind": "SCANNER_RAW",
        "path": ".../scanners/before/trivy/scan_2026-09-09_AoFTs.json",
        "sha256": "...",
        "schema": 2
      },
      "command": ["trivy", "image", "--scanners", "vuln", "--list-all-pkgs",
        "--format", "json", "--output", "...", "sha256:..."],
      "error": null
    },
    {
      "scanner": "grype",
      "status": "FAILED",
      "version": null,
      "started_at": "2026-09-09T00:00:00Z",
      "completed_at": "2026-09-09T00:00:01Z",
      "raw_artifact": null,
      "command": ["grype", "sha256:...", "-o", "json"],
      "error": {
        "code": "SCANNER_EXECUTION_FAILED",
        "message": "non-zero scanner exit"
      }
    }
  ],
  "findings": [
    {
      "finding_id": "AoFTs:before:trivy:<artifact_sha_short>:0:0",
      "scanner": "trivy",
      "scanner_status": "DETECTED",
      "raw_vulnerability_id": "CVE-2019-3462",
      "canonical_cve_id": "CVE-2019-3462",
      "alias_group_id": "CVE-2019-3462",
      "aliases": [],
      "candidate_key": "CVE-2019-3462|pkg:deb/debian/apt|os-pkgs:debian",
      "package": {
        "name": "apt",
        "purl": "pkg:deb/debian/apt@1.4.8",
        "purl_without_version": "pkg:deb/debian/apt",
        "uid": "apt-fixture",
        "ecosystem": "debian",
        "installed_version": "1.4.8",
        "fixed_versions": ["1.4.9"]
      },
      "package_instance": {
        "installed_version": "1.4.8",
        "fixed_versions": ["1.4.9"],
        "purl": "pkg:deb/debian/apt@1.4.8",
        "uid": "apt-fixture"
      },
      "location": {
        "target": "vulhub/elasticsearch:1.4.2 (debian 9.5)",
        "result_class": "os-pkgs",
        "result_type": "debian"
      },
      "severity": {
        "scanner_value": "HIGH",
        "scanner_source": "debian",
        "cvss": [
          {
            "authority": "nvd",
            "version": "3.1",
            "score": "8.1",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        ]
      },
      "advisory": {
        "primary_url": null,
        "references": [],
        "published_at": null,
        "modified_at": null,
        "data_source": null
      },
      "fixed_version_provenance": [
        {
          "scanner": "trivy",
          "fixed_version": "1.4.9",
          "package_purl": "pkg:deb/debian/apt@1.4.8",
          "package_name": "apt",
          "installed_version": "1.4.8",
          "advisory_source": null,
          "raw_ref": {
            "scanner": "trivy",
            "artifact_sha256": "...",
            "result_index": 0,
            "finding_index": 0
          }
        }
      ],
      "raw_ref": {
        "scanner": "trivy",
        "artifact_sha256": "...",
        "result_index": 0,
        "finding_index": 0
      }
    }
  ],
  "excluded_findings": [],
  "warnings": []
}
```

Unknown values must stay `null` or explicit empty arrays. Do not fabricate CVEs,
fixed versions, CVSS scores, ecosystems, or aliases.

Legacy note: the existing `trivy:0:0`-style IDs in the previous draft are
occurrence indexes only. They are not finding identities and must be wrapped
into the fully-qualified `finding_id` above by the adapter. The legacy
`VulnerabilityOccurrence.identity` tuple (which includes `target`,
`installed_version`, and `fixed_versions`) remains an occurrence-dedup key for
backward compatibility; it must not be reused as the candidate key or the
BEFORE/AFTER match key.

## 1. Identity, Deduplication, Aliases, and Component Mapping (Corrected)

This section supersedes the earlier "Candidate identity should include image
identity, phase, and installed version" proposal. That formulation conflated
observation identity with evaluation identity and would have broken BEFORE/AFTER
matching on every version upgrade.

### 1.1 Three separate concepts

- **Finding identity.** Identifies exactly one scanner observation within one
  specific run, phase, image, and raw report. Components: `run_id`, `phase`
  (`before`/`after`), `scanner` name, scanner version (when known), target
  image ID/digest and container ID (when applicable), raw artifact path and
  sha256, `result_index`, `finding_index`, and `raw_vulnerability_id`.
  Finding identities are never compared across phases. A version upgrade always
  produces a different finding identity; that is expected and must not block
  matching.
- **Candidate identity (`candidate_key`).** Identifies the
  vulnerability/component under evaluation across pipeline stages (prioritizer,
  resolver, exploit, patch planning, verification, evaluation). Components
  only: canonical vulnerability identity (CVE or verified alias-group ID) plus
  normalized component identity (package identity without version plus
  location family). Explicitly excluded from mandatory equality: image
  identity/ID/digest, phase, installed version, fixed versions, exact target
  display string, scanner name, scanner version, artifact hash. Those are
  evidence bound to findings, not to the candidate.
- **Package-instance identity.** The fully-qualified observed instance:
  package name, full purl with version, UID when provided, installed version,
  per-scanner fixed versions, exact target string, result class/type. This is
  preserved on every finding and occurrence and is never collapsed before
  patch planning.
- **Component mapping.** The explicit BEFORE-to-AFTER linkage for one
  candidate within one scanner. It answers: "which AFTER package instance, if
  any, corresponds to this BEFORE package instance for the purpose of this
  comparison?" Mapping is per scanner, per candidate, evidence-bound, and may
  return `UNKNOWN`.

### 1.2 Candidate key construction (normative)

- `canonical_vuln` = `canonical_cve_id` when the raw ID normalizes to a CVE;
  otherwise the verified `alias_group_id`. Alias groups are formed only from
  scanner-native alias/related-vulnerability fields or a separately verified
  mapping source. Never equate GHSA and CVE on string similarity alone.
- `normalized_package` = purl without version when a purl is present
  (lowercased name, ecosystem preserved; e.g. `pkg:deb/debian/apt`), else
  `name|ecosystem` lowercased. Version, UID, and distro qualifier revisions
  are stripped for the key but retained in package-instance identity.
- `location_family` = `result_class|result_type-ecosystem-family` (e.g.
  `os-pkgs|debian`). The exact Trivy `Target` display string (which embeds the
  image tag and distro release) is evidence, not key material.
- `candidate_key = canonical_vuln + "|" + normalized_package + "|" +
  location_family`.
- Two findings with the same CVE but different normalized packages are
  different candidates and must not be merged. Two findings with the same CVE
  and same normalized package but different installed versions are the same
  candidate with two package instances.
- Scanner provenance (`detected_by`, `not_detected_by`, `not_selected`,
  `unknown`, `scanner_findings`) is attached to the candidate, never part of
  the key (otherwise union deduplication could never fire).

### 1.3 Component mapping rules (normative)

Mapping runs independently per scanner. BEFORE findings from scanner S are
compared only against AFTER findings from scanner S.

- **Version upgrade (same package, new installed version):** map by
  `candidate_key` equality. Installed-version change is the expected path and
  must not prevent recognition. Example: BEFORE `apt@1.4.8` and AFTER
  `apt@1.4.9` with the same `candidate_key` are mapped; absence of the CVE on
  the mapped AFTER instance yields per-scanner `NOT_FOUND`.
- **Package rename / split / merge:** if the package name or ecosystem
  changes with no scanner-provided rename relation, return `UNKNOWN`
  (`COMPONENT_MAPPING_AMBIGUOUS`). Never guess renames.
- **Relocation (different target/result location):** map by `candidate_key`
  (which uses location family, not the exact target string). A pure image-tag
  or distro-release display change does not break mapping. A genuine class
  change (e.g. `os-pkgs` to `lang-pkgs`) with the same package name is
  ambiguous unless scanner evidence links them; return `UNKNOWN`.
- **Image identity change:** expected between BEFORE and AFTER (patched image
  gets a new image ID). Mapping must never require image-ID equality. Each
  side keeps its own bound image identity (Section 6); the link is via
  `candidate_key` plus the per-scanner package-instance match.
- **Multiplicity:** if one BEFORE instance maps to zero AFTER instances of
  the same `candidate_key` and the AFTER scan for that scanner SUCCEEDED with
  no ambiguity, that scanner reports `NOT_FOUND`. If it maps to one instance,
  compare presence directly. If it maps to several AFTER instances (duplicate
  installs, multi-target reports) with mixed presence, return `UNKNOWN`
  rather than picking the favorable instance.
- **Preservation:** every mapping decision records BEFORE package-instance
  identity, AFTER package-instance identity (or null), scanner, raw refs on
  both sides, and the mapping reason. Ambiguity is surfaced, never silently
  resolved.

### 1.4 Deduplication and alias corrections

- Within one scanner report, deduplicate observations into occurrences using
  the existing `VulnerabilityOccurrence.identity`-style key (occurrence-dedup
  key). This key is explicitly not the candidate key and not the match key.
- Across scanners, group occurrences into union candidates by `candidate_key`.
  Each candidate carries `detected_by`, `not_detected_by` (selected, succeeded,
  absent), `not_selected`, `unknown`, and the full per-scanner
  `scanner_findings` list with severities, fixed versions, CVSS candidates,
  aliases, and raw refs preserved side by side.
- Aliases: preserve `raw_vulnerability_id`, scanner-native `aliases`, and the
  computed `alias_group_id` separately. Merge into one `alias_group_id` only
  when the scanner output provides the relation. GHSA/CVE merging without
  scanner evidence is forbidden.
- Disagreement preservation (unchanged): never overwrite one scanner's
  severity, fixed versions, CVSS, or aliases with another's; never label a
  scanner false positive/negative solely because another scanner missed it.

## Scoring and Prioritization Policy

Keep `kalama-priority-v1` unchanged in this implementation slice
(`cvss + epss*3 + kev*3`; CVSS selected by the current
`nvd-source-first-v1` policy, not by scanner consensus).

Default candidate policy: **union** (approved).

- The union policy retains any candidate reported by at least one successful
  scanner, keyed by the corrected `candidate_key` in Section 1.2.
- The prioritizer receives one canonical candidate per `candidate_key`.
- The selected CVSS input uses the current CVSS provider policy, not scanner
  consensus.
- The artifact records `detected_by`, `not_detected_by`, `not_selected`,
  `unknown`, and per-scanner findings. `NOT_SELECTED` and `NOT_FOUND` are
  distinct states.
- Consensus-only (retain only candidates found by every successful selected
  scanner) is an optional experimental policy. It is not required for the
  initial implementation, must not be the default, and if added later must
  record the exclusion reason per candidate. Filtering disagreements before
  empirical validation would hide potentially relevant candidates.

## 2. Scanner Availability vs. Comparison Completeness (Corrected)

A scan phase may continue when at least one selected scanner succeeds, but the
multi-scanner comparison may still be incomplete. These are independent flags.

- **Phase continuation** answers: "do we have enough evidence to proceed to
  the next stage?" Rule: BEFORE fails only if zero selected scanners
  SUCCEEDED; AFTER never fails the whole pipeline while at least one selected
  scanner SUCCEEDED (per-scanner failures become `UNKNOWN` downstream).
- **Comparison completeness** answers: "can the union BEFORE/AFTER verdict be
  stated without losing provenance?" This is recorded as
  `comparison_complete: bool` plus `incomplete_reasons`, independent from
  phase continuation and from empirical remediation validation.
- **Empirical validation** answers: "did re-exploitation succeed or fail?"
  Re-exploitation may proceed whenever the environment is valid (patched image
  exists, after-target bound, image identities consistent), even if scanner
  comparison is incomplete. Scanner `UNKNOWN` never blocks re-exploit and
  never counts as remediation success or failure.

### 2.1 Statuses (normative)

Scanner execution status (per scanner, per phase): `SUCCEEDED`, `FAILED`
(non-zero exit or timeout, with code preserved, e.g.
`SCANNER_EXECUTION_FAILED`), `INVALID_JSON`, `UNSUPPORTED_SCHEMA`,
`SKIPPED` (not selected), `INCOMPLETE` (selected but produced no terminal
status record).

Per-scanner per-candidate comparison status: `FOUND` (mapped instance present
in AFTER), `NOT_FOUND` (scanner SUCCEEDED on both sides, mapping unambiguous,
mapped instance absent), `UNKNOWN` (any blocking condition below, with
reason), `NOT_APPLICABLE` (scanner was `SKIPPED`; excluded from the union
denominator, never counted as `NOT_FOUND`).

Union comparison status: `FOUND`, `NOT_FOUND`, or `UNKNOWN` with
`INCOMPLETE` reason. The worked example is normative:

```text
BEFORE: Trivy = FOUND, Grype = FOUND
AFTER:  Trivy = NOT_FOUND, Grype = SCAN_ERROR (FAILED/INVALID_JSON/INCOMPLETE)
Union comparison = UNKNOWN / INCOMPLETE (not NOT_FOUND)
```

### 2.2 Explicit rules

- **Scanner succeeded and finding present.** AFTER SUCCEEDED and the component
  mapping resolves to an AFTER instance carrying the candidate vuln:
  per-scanner `FOUND`.
- **Scanner succeeded and finding absent.** AFTER SUCCEEDED, BEFORE for the
  same scanner had the candidate, mapping unambiguous, target identities valid
  on both sides, no material parser ambiguity: per-scanner `NOT_FOUND`.
- **Scanner failed, timed out, or produced invalid JSON.**
  `FAILED`/`INVALID_JSON`/`UNSUPPORTED_SCHEMA` on either side for that scanner:
  per-scanner `UNKNOWN` with reason `SCANNER_UNAVAILABLE_BEFORE` or
  `SCANNER_UNAVAILABLE_AFTER`. This scanner contributes `UNKNOWN` to the union
  and can never contribute `NOT_FOUND`.
- **Scanner was not selected.** Status `SKIPPED`, comparison
  `NOT_APPLICABLE`. Excluded from union logic entirely. Displayed as
  `not_selected`, never as `missing_from`.
- **Scanner was selected but did not complete.** Status `INCOMPLETE`:
  per-scanner `UNKNOWN` with reason `SCANNER_INCOMPLETE`. Treated as failure
  for union purposes but with a distinct diagnostic code.
- **Target identity mismatch.** AFTER scan subject differs from the committed
  patched-image identity, or BEFORE subject differs from the victim image
  (existing `PATCHED_IMAGE_IDENTITY_MISMATCH` /
  `AFTER_TARGET_IMAGE_MISMATCH` conditions): per-scanner `UNKNOWN` with reason
  `TARGET_IDENTITY_MISMATCH` for every scanner in that phase, plus the
  existing phase-level fatal for comparison validity. No `NOT_FOUND` may be
  emitted from a mismatched phase.
- **Component mapping ambiguity.** Mapping returns ambiguous (rename without
  evidence, multiplicity with mixed presence, class change without linkage,
  material parser warnings for the relevant CVE): per-scanner `UNKNOWN` with
  reason `COMPONENT_MAPPING_AMBIGUOUS`.
- **BEFORE scanner unavailable but AFTER scanner succeeds.** No BEFORE
  baseline for scanner S (`FAILED`/`INVALID_JSON`/`INCOMPLETE` in BEFORE) but
  AFTER SUCCEEDED: per-scanner `UNKNOWN` with reason
  `NO_BEFORE_BASELINE`. AFTER absence alone is not `NOT_FOUND`.
- **BEFORE scanner succeeds but AFTER scanner unavailable.** BEFORE `FOUND`
  but AFTER `FAILED`/`INVALID_JSON`/`INCOMPLETE`: per-scanner `UNKNOWN` with
  reason `NO_AFTER_EVIDENCE`. This is the normative example above; it taints
  the union to `UNKNOWN`.

### 2.3 Union rule (normative)

Let evaluable scanners be selected scanners with SUCCEEDED on both sides and
an unambiguous mapping for the candidate.

- Union `FOUND` if any evaluable scanner reports `FOUND`.
- Else union `NOT_FOUND` only if: at least one evaluable scanner reports
  `NOT_FOUND`, zero evaluable scanners report `FOUND`, and zero scanners
  report `UNKNOWN` where that scanner's BEFORE was `FOUND` or BEFORE was
  itself unknown (no baseline). Scanners whose BEFORE never contained the
  candidate (`NOT_APPLICABLE` at BEFORE) do not taint the union.
- Otherwise union `UNKNOWN` with `incomplete_reasons` listing each tainting
  scanner and reason. In particular, any BEFORE-`FOUND` scanner that is
  AFTER-`UNKNOWN` forces union `UNKNOWN`, even if another scanner is
  `NOT_FOUND`. Surviving-scanner absence is scanner evidence only.
- `new_after_findings` (candidates in AFTER with no BEFORE mapping) are
  recorded separately per scanner and never folded into the intended-target
  verdict.
- `scanner_remediation_verified` for one scanner means that scanner reported
  `NOT_FOUND`. There is no global `scanner_remediation_verified` unless the
  union is `NOT_FOUND`. Empirical `VERIFIED`/`FAILED` comes only from the
  re-exploit oracle.

## 3. Evaluation Metric Preservation (Corrected)

Do not silently redefine Precision@N, Recall, F1, or remediation success rate.
The current `src/kalama/evaluation/metrics.py` semantics (`TOP_N_ONLY`,
unavailable-Recall/F1 reasons, TP+FP consistency checks) remain intact.

### 3.1 What must be preserved per record

Every evaluation record in the union-selected cohort must carry, additively
and without renaming existing fields:

- `union_selected_top_n`: rank and score under the union candidate policy
  (the only Top N that was empirically attempted in a union run).
- `trivy_detected_within_selected`: whether Trivy detected this
  union-selected candidate (`DETECTED` / `NOT_DETECTED` / `NOT_SELECTED` /
  `UNKNOWN`), with scanner version and raw ref.
- `grype_detected_within_selected`: same for Grype.
- `empirical_eligible`: the existing `binary_evaluation.eligible` flag.
- `empirical_label`: the existing binary disposition-derived label
  (`TP`/`FP`/ineligible), derived only from BEFORE exploit oracle evidence.
- Scanner-specific prediction provenance: per-scanner detection status,
  scanner versions, `candidate_policy`, and raw artifact hashes.
- Candidate selection policy: `union` (plus versioned policy identifier).
- Evaluation universe and denominator: `evaluation_universe.scope`
  (`TOP_N_ONLY` unless a full universe is introduced), `top_n_requested`,
  `top_n_returned`, eligible counts, and the exact denominator used for every
  rate.

### 3.2 Three analyses that must not be conflated

1. **Metrics over the union-selected empirical cohort.** Precision@N,
   remediation success rate, and coverage are computed over the union-selected
   Top N exactly as today. The prediction is "union-selected"; the denominator
   is eligible union-selected records. This is the only Precision@N reported
   for a union run.
2. **Conditional scanner detection/agreement analysis within that cohort.**
   Within the union-selected set, report agreement tables (e.g. Trivy-only,
   Grype-only, both; detection-conditioned exploit-success rates). These are
   descriptive breakdowns, not independent Precision@N values.
3. **Independently selected per-scanner Top N metrics.** A claim of the form
   "Trivy Precision@N" or "Grype Precision@N" requires its own defined
   selection protocol (top N selected by that scanner alone), its own ranked
   list, and its own empirical evaluation of that list. A subset of a
   union-selected list is not an independently selected Top N and must never
   be labeled as such.

### 3.3 Prohibited claims

- Do not claim Recall, F1, or a full confusion matrix unless the required
  predicted-negative population has been empirically evaluated under
  `FULL_EMPIRICAL_UNIVERSE`. Under `TOP_N_ONLY`, `recall` stays unavailable
  with reason `PREDICTED_NEGATIVES_NOT_EMPIRICALLY_EVALUATED` and `accuracy`
  stays unavailable with reason `INCOMPLETE_CONFUSION_MATRIX`.
- Do not compute a scanner's Precision@N by filtering the union-selected Top
  N to that scanner's detections. That quantity is a conditional agreement
  rate, not Precision@N.
- Remediation success rate denominator is `VERIFIED + FAILED` evaluable
  remediation targets (oracle-derived), not scanner-`NOT_FOUND` counts. The
  existing `scanner_empirical_cross_tab` may gain per-scanner and union keys,
  but the cross-tab never feeds the success-rate denominator.

## 4. Fixed-Version Provenance in Patch Planning (Corrected)

The current planner (`src/kalama/remediation/planner.py:69`) unions
`fixed_versions` across occurrences into one flat tuple. With one scanner this
was already lossy; with two scanners it would turn conflicting recommendations
into one unqualified list. Example (normative):

```text
Trivy: fixed_versions [2.3.32, 2.5.10.1]
Grype: fixed_versions [2.3.32]
Forbidden: fixed_versions [2.3.32, 2.5.10.1] with no provenance
Required:  two provenance records, one per scanner finding
```

Minimal compatibility changes (no remediation-discovery redesign in this
round):

- Preserve per-occurrence provenance alongside the legacy flat list. Each
  `fixed_version_provenance` entry carries: scanner name, `raw_ref`
  (scanner, artifact sha256, result/finding indexes), package identity
  (name, full purl, installed version), the single `fixed_version` value,
  advisory source / `data_source`, and version context (result class/type).
- Keep the existing flat `fixed_versions` / `scanner_fixed_versions` fields
  for backward compatibility, but mark them as display/legacy aggregates. All
  new logic must read the provenance list when present.
- Remediation discovery (`service.py`, `os_package.py`, `source_build.py`)
  continues to use the existing approved version-selection policy and
  independent availability/compatibility checks: same-branch-only selection,
  `FIX_VERSION_KNOWN` vs `PACKAGE_AVAILABLE` distinction via non-mutating
  package-manager probes, proposal-only source rebuilds, `KNOWLEDGE_REQUIRED`
  for unmapped prebuilt images. Scanner agreement must not automatically
  determine the patch version; agreement metadata is informational and must
  not bypass the availability probe.
- The discovery `candidate()` adapter may accept an additive
  `fixed_version_provenance` parameter; the existing
  `scanner_fixed_versions: Sequence[str]` signature stays. No change to
  `FixType`/`PatchStrategy` inference, `trusted=False` default for
  auto-discovered candidates, or human-confirmation boundaries.

## 5. Approved Configuration Decisions

These decisions are adopted unless the current code reveals a concrete
incompatibility, in which case the incompatibility must be documented with
file and line references. No such incompatibility was found in this audit.

- **Default scanner set: `trivy`.** Backward compatibility: a run with no
  scanner option behaves exactly as today (Trivy-only, `TRIVY_BEFORE` /
  `TRIVY_AFTER` written, legacy readers work).
- **Multi-scanner selection via the existing configuration pattern.**
  Environment `KALAMA_SCANNERS` (e.g. `trivy,grype`) mirrors the existing
  `KALAMA_*` env pattern (`KALAMA_TRIVY_VERSION`, `KALAMA_SOURCE_ROOT`,
  `KALAMA_GUIDANCE_*` in `setup-workbench.sh` and `src/kalama/runtime.py`).
  A CLI `--scanners` option on the `run` subparser may be added in a later
  slice: this is consistent with current CLI architecture because `run`
  already takes run-scoped input (`--image`, `src/kalama/cli.py:20`) and
  global input (`--output-root`) separately. Precedence when both exist:
  CLI flag > `KALAMA_SCANNERS` > default (`trivy`). Values are validated
  against the known adapter registry; unknown names fail fast with a usage
  error. No Slice 1 change (Slice 1 adds no config surface).
- **Default candidate policy: `union`.** Recorded in every scan-set and
  prioritization artifact.
- **Consensus-only: optional experimental policy, not required for the
  initial implementation.** Do not implement it in Slice 1.
- **New artifact kinds: `SCAN_SET_BEFORE` and `SCAN_SET_AFTER`.** The more
  generic `SCANNER_EVIDENCE_*` naming is rejected: scan sets are the decided
  kind. Adding kinds requires a coordinated `state/models.py` +
  `state/store.py` + test update (store currently rejects unknown kinds at
  `state/store.py:114`); that update is deferred past Slice 1.
- **Preserve legacy `TRIVY_BEFORE` and `TRIVY_AFTER` compatibility.** New
  runs with Trivy enabled write both `SCAN_SET_*` and compatibility `TRIVY_*`
  references; downstream readers prefer `SCAN_SET_*` when present and
  otherwise adapt legacy `TRIVY_*` through the compatibility reader.
- **Do not rewrite or migrate historical runs in place.** Old state files use
  only known kinds and remain loadable; `artifact_history` semantics
  (`state/models.py:269`) are unchanged.
- **Do not implement Nuclei yet.** Keep the `ScannerAdapter` protocol
  extensible (scanner name, version, command, raw artifact, normalized
  findings) so Nuclei can be added without a second pipeline change.
- **Keep the existing prioritization scoring formula unchanged**
  (`kalama-priority-v1`: `cvss + epss*3 + kev*3`).
- **Keep exploit evidence as the independent empirical ground truth.**
  Scanner agreement never sets `VERIFIED`, `PATCH_SUCCESS`, or `CVE_REMOVED`.

## 6. Run Isolation Requirements (New)

Every scanner execution and every artifact derived from it must be bound to
the exact execution context. Shared or inferred bindings are forbidden.

Bound identity per scanner execution (recorded in `RawScannerArtifact` and the
scan-set `scanners[]` entry): `run_id`, pipeline phase (`before`/`after`),
target image ID and digest (resolved at scan time, not just the requested
tag), container ID/name when applicable (`victim-<run_id>` /
`victim-after-<run_id>`), scanner name and version (when the scanner reports
one; null with reason when it cannot be determined, never fabricated), raw
artifact path and sha256, command argv, start/end timestamps, and
attempt/revision identity.

Artifact binding and publication rules, consistent with the repository's
existing conventions (temp file + JSON validation + fsync + atomic publish in
`target/trivy_scanner.py:48`; atomic writes via `_atomic_write` in
`resolution/artifacts.py`; replace-by-kind with `artifact_history` in
`state/models.py:269`):

- Raw paths are namespaced by run, phase, scanner, and attempt, e.g.
  `scanners/<phase>/<scanner>/scan_<date>_<run_id>[_attempt<N>].json` alongside
  the legacy `trivy/<phase>/...` paths (legacy paths are preserved for
  compatibility, never removed). The scan-set artifact references raw paths
  plus sha256 hashes; consumers verify the hash before parsing.
- Never discover or reuse scan artifacts by broad filename matching
  (`glob("*.json")`), latest timestamp, containing directory, or CVE alone.
  The only valid inputs to prioritization, patch planning, verification, and
  evaluation are artifact paths resolved through the committed `RunState`
  artifact references (`SCAN_SET_BEFORE/AFTER`, with legacy `TRIVY_*`
  fallback) with sha256 verification. Artifacts from another `run_id` must
  never overwrite or satisfy the current run's requirements; a path or hash
  mismatch is a hard integrity error, not a fallback to search.
- Publication is immutable/create-once per (run, phase, scanner, attempt).
  Never overwrite a published raw artifact or scan set in place. Retries or
  repeated scans mint a new attempt/revision identity (incremented `attempt`
  in the filename and scan-set payload); superseded references move to
  `artifact_history` via the existing `with_artifact` path. Two writers
  publishing the same identity is a collision error.
- Target binding is verified at both ends: BEFORE scan subject must match the
  committed victim image identity; AFTER scan subject must match the committed
  patched-image / after-target identity. Mismatch triggers the existing
  `PATCHED_IMAGE_IDENTITY_MISMATCH` / `AFTER_TARGET_IMAGE_MISMATCH` handling
  and forces comparison `UNKNOWN` (Section 2.2).

## Compatibility and Migration

Use additive versioned schemas. Do not rewrite old runs.

Compatibility plan (approved):

- Keep reading existing `TRIVY_BEFORE` and `TRIVY_AFTER`.
- Add `SCAN_SET_BEFORE` and `SCAN_SET_AFTER` (decided; see Section 5).
- New runs with Trivy enabled write both `SCAN_SET_*` and compatibility
  `TRIVY_*` references.
- Existing Trivy-only runs remain readable without migration.
- Downstream readers prefer `SCAN_SET_*` when present, else adapt legacy
  `TRIVY_*` through a compatibility reader into normalized findings.

Because `run_state_from_dict()` rejects unknown artifact kinds, adding new
kinds requires a coordinated model/store/test update. This is still additive
for data because old state files use only known existing kinds. That update is
explicitly deferred past Slice 1 (Slice 1 introduces no new `ArtifactKind`).

## Runtime and Installation

Least disruptive path (deferred past Slice 1; documented here so Slice 1
contracts anticipate it):

- Keep using the managed workbench container.
- Install Grype into the same workbench with checksum verification, analogous
  to Trivy (`setup-workbench.sh` pattern: pinned `KALAMA_GRYPE_VERSION`,
  release-tarball download, checksum verification).
- Selection via `KALAMA_SCANNERS` (default `trivy`), with optional future
  `run --scanners trivy,grype` overriding it (see Section 5 for precedence).
- Extend doctor to check selected scanners only (`trivy --version` and
  `grype --version` branches), not every possible scanner, so Trivy-only
  users are unaffected.
- Extend `WorkbenchToolRunner` with a `grype` argv branch mirroring the
  existing `trivy` branch (strip output flag, `docker exec`, capture stdout
  back to the host path). No host fallback for either scanner.

Linux:

- Download Grype release artifact inside the workbench container.
- Verify checksums.
- Execute as `docker exec <workbench> grype <image-id-or-digest> -o json`.

Windows + WSL2:

- Keep host requirements unchanged: Docker Desktop/Engine reachable from the
  workbench through `/var/run/docker.sock`.
- Do not require host-native Grype.
- Continue using host-side atomic artifact publication from captured stdout, as
  `WorkbenchToolRunner` already does for Trivy.

Do not install Grype in this audit or in Slice 1.

## Scanner Execution and Failure Policy

Each scanner must produce a separate status record (see Section 2.1 for the
full status set, including `SKIPPED` vs `INCOMPLETE` vs `FAILED`).

A failed scanner must not be represented as an empty successful result. If
Trivy succeeds and Grype fails, the run may continue using Trivy-derived
candidates under the union policy, but the scan set and prioritization
artifact must record that Grype was unavailable, and the union comparison for
any candidate Grype saw in BEFORE (or might have seen, when BEFORE itself is
missing) stays `UNKNOWN` per Section 2.3.

Fatal policy (phase continuation; distinct from comparison completeness):

- BEFORE phase: fail only if no selected scanner succeeds.
- AFTER phase: do not fail the whole pipeline if at least one scanner
  succeeds; mark per-scanner failures as `UNKNOWN` in the remediation scan
  result.
- Target/image identity mismatch is fatal for comparison validity for that
  phase because comparison would be invalid (existing mismatch errors apply).

## 7. Revised Implementation Sequence

### Slice 1 (authorized first slice; only slice proposed for approval now)

Limited to scanner-agnostic normalized models, legacy compatibility, one real
Grype fixture/parser, adapter contracts, and unit tests. No pipeline behavior
changes.

New files (proposed, under `src/kalama/scan/`):

- `src/kalama/scan/models.py` — `NormalizedFinding`, `UnionCandidate`
  (with `candidate_key` per Section 1.2), `ComponentMapping`,
  `ScannerExecutionRecord` (`SUCCEEDED`/`FAILED`/`INVALID_JSON`/
  `UNSUPPORTED_SCHEMA`/`SKIPPED`/`INCOMPLETE`), `ScanSet` envelope
  (`kalama.scan-set/v1`), `ComparisonStatus` (`FOUND`/`NOT_FOUND`/`UNKNOWN`/
  `NOT_APPLICABLE` + reasons), `FixedVersionProvenance`, `RawRef`. Pure
  dataclasses/enums with `to_dict`/`from_dict`; no I/O, no orchestration.
- `src/kalama/scan/adapters.py` — `ScannerAdapter` protocol
  (`scanner_name`, `supported_versions`, `build_command`, `parse_raw`,
  `normalize`) plus shared alias/canonicalization and `candidate_key`
  helpers. No workbench, orchestrator, or state imports.
- `src/kalama/scan/trivy.py` — thin wrap (not a rewrite) of the current
  Trivy validation/parser (`target/trivy_scanner.py`,
  `prioritizer/trivy_parser.py`) emitting `NormalizedFinding` values with
  fully-qualified finding identity and `fixed_version_provenance`. Existing
  modules stay untouched; this file only adapts them.
- `src/kalama/scan/grype.py` — real Grype JSON parser emitting the same
  normalized types. Field mapping is derived strictly from the committed
  fixture; unknown Grype shapes yield `UNSUPPORTED_SCHEMA`, never fabricated
  values.
- `src/kalama/scan/legacy.py` — convert an existing Trivy schema-2 artifact
  (as loaded from a `TRIVY_BEFORE`/`TRIVY_AFTER` path) into a single-scanner
  `ScanSet` for testing and future fallback. Read-only helper; not wired
  into any orchestrator in Slice 1.
- `tests/unit/fixtures/grype_realistic.json` — actual Grype `-o json`
  output captured from a lab image (same image family as
  `trivy_realistic.json` where possible), committed verbatim with a
  provenance note (image ref, Grype version, capture date). No hand-edited
  fields.
- `tests/unit/test_scan_models.py`, `tests/unit/test_scan_adapters.py`,
  `tests/unit/test_trivy_normalization.py`,
  `tests/unit/test_grype_parser.py` — unit tests per the acceptance list
  below.

Explicitly out of Slice 1 (no changes unless an absolutely necessary
dependency is identified and explicitly justified with file/line references):

- orchestrator (`src/kalama/orchestrator.py`, `target/coordinator.py`,
  `target/models.py`, `runtime.py`), prioritizer pipeline/models
  (`prioritizer/pipeline.py`, `prioritizer/models.py`,
  `prioritizer/trivy_parser.py`), patch planning and discovery
  (`remediation/planner.py`, `remediation/orchestrator.py`,
  `remediation/discovery/*`), verification (`verification/orchestrator.py`,
  `verification/comparison.py`), evaluation (`evaluation/metrics.py`,
  `evaluation/orchestrator.py`), CLI (`cli.py`), setup scripts
  (`setup-workbench.sh`), doctor (`doctor.py`), state models/store
  (`state/models.py`, `state/store.py`), workbench routing
  (`target/workbench.py`).

No full pipeline, exploit, patch, AFTER scan, or evaluation runs in this
round or in Slice 1.

### Later slices (proposed order; not authorized; summarized so Slice 1 stays compatible)

- Slice 2: scanner execution adapters + workbench `grype` routing +
  `SCAN_SET_BEFORE` persistence with `TRIVY_BEFORE` compatibility.
- Slice 3: prioritization over normalized union candidates (additive
  provenance fields; scoring formula unchanged).
- Slice 4: patch-plan lineage prefers scan set, accepts legacy Trivy;
  provenance-aware `fixed_versions` (flat list retained).
- Slice 5: `SCAN_SET_AFTER` + per-scanner and union comparison per
  Section 2 + `REMEDIATION_SCAN_RESULT` enrichment.
- Slice 6: evaluation scanner context per Section 3 + CLI (`--scanners`) /
  doctor / setup support + regression suite.

## Test Plan (Slice 1 acceptance)

Slice 1 passes only if all of the following hold. No exploit/patch/scan
execution tests are in scope for Slice 1.

Normalization, aliases, identity, provenance:

- Trivy legacy fixture still parses; wrapped adapter output preserves every
  legacy occurrence field and adds fully-qualified finding identity,
  `candidate_key` (without image/phase/version), and per-value
  `fixed_version_provenance`.
- Grype real fixture normalizes package identity (name, purl with and without
  version, UID when present), aliases (scanner-native only), severities,
  fixed versions (provenance-preserving), advisory references, and raw refs
  (`artifact_sha256`, `result_index`, `finding_index`). Unknown values are
  null/empty, never fabricated.
- Finding identity includes run/phase/scanner/artifact-hash/indexes and
  differs across phases/images for the same CVE+package; candidate identity
  is stable across installed-version changes and excludes image, phase,
  installed/fixed versions, and scanner.
- Candidates built from Trivy+Grype fixtures group by `candidate_key`:
  same CVE with different normalized packages stays split; same CVE+package
  with different versions stays one candidate with two instances;
  `detected_by`/`not_detected_by`/`unknown` provenance is preserved and
  `NOT_SELECTED` is representable.
- GHSA/CVE aliases merge only when scanner evidence provides the alias
  relation; otherwise they remain distinct candidates.
- Fixed-version provenance: the Trivy `[2.3.32, 2.5.10.1]` + Grype `[2.3.32]`
  case yields three provenance records (not one merged list) and the legacy
  flat union remains available as a marked legacy aggregate.

Failure and comparison-logic states (pure-function tests on Slice 1 types;
no orchestrator changes):

- All execution statuses constructible and distinguishable: `SUCCEEDED`,
  `FAILED`, `INVALID_JSON`, `UNSUPPORTED_SCHEMA`, `SKIPPED`, `INCOMPLETE`.
- Union-rule truth table passes, including the normative example (BEFORE
  Trivy FOUND + Grype FOUND; AFTER Trivy NOT_FOUND + Grype error implies
  union UNKNOWN/INCOMPLETE, not NOT_FOUND), plus: not-selected exclusion,
  target-mismatch UNKNOWN, mapping-ambiguity UNKNOWN, no-before-baseline
  UNKNOWN, no-after-evidence UNKNOWN.
- Comparison-completeness flag is independent from phase-continuation logic
  in the tested pure functions (incomplete comparison does not imply phase
  failure and does not imply empirical failure).

Regression guards in Slice 1 (read-only, no behavior change):

- Existing Trivy-only parser, `VulnerabilityOccurrence.identity` semantics,
  and historical `TRIVY_*` state fixtures remain loadable and byte-identical
  through the wrapped path (adapter output is additive; legacy output is not
  rewritten).

Existing relevant tests (must keep passing unmodified in Slice 1):

- `tests/unit/test_workbench_scanner.py`
- `tests/unit/test_bootstrap.py`
- `tests/unit/test_doctor.py`
- `tests/unit/test_prioritizer.py`
- `tests/integration/test_after_scan.py`
- `tests/integration/test_orchestrator.py`
- `tests/integration/test_evaluation.py`
- `tests/integration/test_patch_planning.py`
- `tests/integration/test_cli.py`

## Acceptance Criteria (design round + Slice 1)

Design-round acceptance:

- This revised `MULTISCANNER_DESIGN.md` is the only modified file; no
  production code is modified.
- Sections 1-7 above address every correction: separate finding/candidate
  identity with component mapping; availability vs. completeness with all
  nine explicit rules; metric preservation with required fields and the
  three-analysis distinction; fixed-version provenance with the minimal
  compatibility path; approved configuration; run isolation; and the
  Slice-1-only sequence.

Slice-1 implementation acceptance (for the future authorized round):

- Default run with no scanner option remains Trivy-only and historical
  behavior remains readable (no new `ArtifactKind` required in Slice 1).
- New normalized types round-trip through `to_dict`/`from_dict` with stable
  keys; no orchestrator, CLI, or state-schema change is needed to import
  them.
- Every scanner record carries status, version when available, timestamps,
  command, target identity, and raw artifact reference or structured error.
- Prioritization input shape, scoring formula, resolver/exploit interfaces,
  discovery version-selection policy, and `TOP_N_ONLY` metric semantics are
  untouched by Slice 1.
- No old run artifacts are rewritten or migrated in place.

## Risks to Existing Behavior

- Adding artifact kinds requires updating strict state deserialization
  (deferred past Slice 1 for this reason).
- If `ranked_cves` changes too much, resolver, Attack Form, patch planning,
  and evaluation tests will break (Slice 1 therefore adds no `ranked_cves`
  change).
- Merging Trivy and Grype fixed versions too early can mislead patch planning
  (mitigated by provenance preservation in Section 4).
- Treating scanner disagreement as false positive/false negative would corrupt
  the empirical method (mitigated by Sections 2-3).
- Doctor/setup changes can accidentally require Grype for users who expect
  the current Trivy-only default (mitigated by selected-scanners-only checks
  and the `trivy` default).
- AFTER scan summaries currently store one status per CVE; multi-scanner needs
  richer detail without breaking CLI status output (additive fields only, in
  a later slice).

## Open Decisions Requiring Approval (remaining only)

All Section 5 decisions are approved and removed from this list. The following
remain; Slice 1 is unaffected by their outcome.

- Minimum supported Grype version and checksum source for the future
  `setup-workbench.sh` installation step.
- Whether scanner DB/version drift between BEFORE and AFTER should warn only
  or block comparisons (recommendation: record versions in both scan sets and
  warn; block only on target-identity mismatch; to be confirmed).
- Exact raw-path layout for the future `scanners/<phase>/<scanner>/` tree
  (recommendation in Section 6 adopted unless objected).
- Whether the future consensus-only experimental policy flag should exist at
  all, and under what name (no implementation proposed in Slice 1).

## Concise Design Summary

Kalama should not make Trivy and Grype compete for one value. Each scanner
runs independently, publishes its own raw evidence and status bound to the
exact run/phase/image/container/artifact, then feeds a versioned scan-set
artifact containing normalized findings with fully-qualified finding identity.
Findings group into union candidates by a version/image/phase/scanner-free
candidate key; BEFORE/AFTER linkage uses an explicit per-scanner component
mapping that returns `UNKNOWN` when ambiguous. Phase continuation, comparison
completeness, and empirical validation are independent flags: surviving-scanner
absence never becomes global `NOT_FOUND` while a relevant scanner is
`UNKNOWN`, and scanner `UNKNOWN` never blocks re-exploitation. Metrics keep
their existing `TOP_N_ONLY` meanings over the union-selected cohort with
additive scanner-detection fields; fixed versions keep per-scanner provenance
while discovery keeps its approved availability-checked policy. The first
implementation slice adds only normalized models, the legacy Trivy adapter,
the real Grype fixture and parser, adapter contracts, and unit tests.
