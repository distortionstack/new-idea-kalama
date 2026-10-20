# Phase 1 Report — EXP-PROC-7X9D-01 (Evidence Preparation Only)

No ROLE A reasoning, no proposal, no ROLE B review, no commands drafted or
executed, no submission, no AFTER scan, no re-exploit, no evaluation, no
Knowledge writes, no production modification was performed in this phase.

## 1. Chosen case and why

`apache2` 2.4.10-10+deb8u12 (deb, debian-8.10 amd64) on
`kalama-lab:type-c-shellshock` (RepoDigest `sha256:1ee787c9…`). Primary
CVE-2019-10092 (MEDIUM, mod_proxy error-page XSS) + incidental
CVE-2019-10098 (MEDIUM, mod_rewrite open redirect), both scanner-fixed in
2.4.10-10+deb8u15 (DLA-1900-1). Single action patch-001. Full rationale in
case_selection.md; the decisive properties are: (a) the runtime CMD is
`apache2ctl` — the control interface of the candidate package itself —
giving a provenance-linked vendor procedure root (the gap the bash
experiment could not fill); (b) L4 does not merely confirm the
scanner-fixed revision but refines it (deb8u15 deficient → deb8u16
correct); (c) the live registry resolves scanner-vs-index skew
deterministically (deb8u15 stanza absent/superseded, deb8u16 present with
byte-verified artifact).

## 2. Rejected candidates and why

Struts2 family and CVE-2015-1427/elasticsearch: REJECTED_CONTAMINATED
(full prior patch records). bash/CVE-2019-9924: excluded by design (prior
Agent/Reviewer answer exists; L5 unobtainable). apache2
CVE-2019-0217/0220 pair: uncontaminated but two revisions from latest;
deprioritized in favor of the tighter single-step deficient-fix narrative.
Other same-image packages (perl/tar/apt/…): no service identity, weak L5.

## 3. Contamination status

PARTIALLY_CONTAMINATED (shared-image seed/lab-doc exposure only):
prior material contains no exact patched version, artifact coordinate,
strategy, patch/install command, validation command, runtime procedure, or
completed patch result for this candidate. See contamination_audit.md.

## 4. Frozen candidate identity

frozen_seed.json
(sha256:80afbdafd624df658a7bfe906cc7a3ea4878a064127842a625347396028e9910):
two apache2 records extracted read-only from frozen in-repo Trivy bytes
(trivy 0.74.0, 2026-09-17, 258 findings, debian 8.10 EOSL) + frozen
image-config/history facts. No rescan (docker daemon unavailable); reuse
declared in seed provenance. No container executed.

## 5. Scope hazards

apache2-bin/-data/-utils carry the same CVEs — in scope ONLY as
Depends-driven closure of the apache2 meta-package upgrade (stanzas
recorded), not as independent actions. mod_proxy/mod_rewrite live config
state unobservable from image history (verification bounded to
version + config-syntax + service-state). /usr/local/bash-4.3.0 prefix out
of scope. 250 non-apache2 findings out of scope. deb8u15 bytes
deliberately unretrieved (superseded + deficient; bounded gap, not
oversight).

## 6. Deterministic source roots

SEED-01 scanner finding, SEED-02 scanner DataSource, SEED-03 runtime
image config/history. Derivation rules: SCANNER_REFERENCE_TRAVERSAL (×3),
ADVISORY_QUERY (×3), ADVISORY_TRACKER_CVE_PATH, ADVISORY_TYPED_REFERENCE_
TRAVERSAL (S014 via OSV ADVISORY typing), TRACKER_CHILD_LINK (×3 chained
S006→S012→S021→S013), PACKAGE/DISTRO-derived registry paths,
INDEX_DERIVED_ARTIFACT_PATH, RUNTIME_IDENTITY_VENDOR_DOC (×2, stanza
Homepage corroboration), DISTRO/RUNTIME_TOOL-derived manpages, DOC_CHILD_
LINK (S020 from S015). One derivation-pattern guess (S019) 404'd and is
retained as a failed record. No search engines, blogs, mirrors, or
unparented sources. See source_roots.md.

## 7. Retrieval results

24 graph records (3 roots + 21 fetch records): 19 RETRIEVED, 2
FETCH_FAILED (S019 404; no other failure — incl. both DLA announces, which
were PoW-walled in the prior experiment), 0 unanchored, 0 missing
parents, valid:true. Manifest sha256:555d0ccc886ea… (pre-pack; packs carry
their own hashes). Notable: jessie main index byte-identical to prior
S010, jessie-security index byte-identical to prior S011 (independent
determinism corroboration).

## 8. Source graph counts

Refs per arm: A 13 (12 retrieved + 1 failed), B 17 (16 + 1), C 22
(21 + 1); monotonic A ⊂ B ⊂ C by ref-ID set inclusion
(machine-checked). Failed refs (S003 never cited; S019 never cited) are
present for transparency with empty used_for_fields.

## 9. Evidence available at each L-level

- L0: scanner pair + runtime CMD/history facts (seed).
- L1: reference-graph traversal records (S001/S002/S003; content
  uninterpreted in ARM_A).
- L2: NVD (S004), OSV incl. ADVISORY typings (S005), Debian tracker CVE
  page (S006), KEV double-negative (S007).
- L3: snapshot existence (S008), installed stanza + hashes (S009), live
  security stanza + sibling stanzas (S010), byte-verified deb8u16 .deb
  (S011: 209216 bytes, SHA-256 match).
- L4: DLA-1900-1 announce + tracker (S001/S012), upstream httpd 2.4
  security mapping (S002: affected incl. 2.4.10, fixed upstream 2.4.41),
  DLA-1900-2 announce + tracker + series index (S014/S013/S021).
- L5: httpd invoking (S015), httpd stopping (S016), Debian apache2ctl(8)
  (S017), Debian apt-get(8) (S018), httpd program reference (S020).

## 10. Per-field sufficiency by arm (future-Agent fields)

| field | ARM_A_L3 | ARM_B_L3_L4 | ARM_C_L3_L4_L5 |
|---|---|---|---|
| fix_type | evidence present (C-basis); needs semantic contract (separate input) | same | same |
| strategy | SUPPORTED | SUPPORTED (L4-refined) | SUPPORTED |
| target_version | SUPPORTED (deb8u16 latest-secure; rationale uninterpretable here) | SUPPORTED (L4: deb8u16 correct, deb8u15 deficient) | SUPPORTED |
| artifact_source | SUPPORTED | SUPPORTED | SUPPORTED |
| source_identifier | SUPPORTED | SUPPORTED | SUPPORTED |
| build_system | N/A (OS package) | N/A | N/A |
| command | INSUFFICIENT | INSUFFICIENT | SUPPORTED |
| validation_command | INSUFFICIENT | INSUFFICIENT | SUPPORTED |
| notes | SUPPORTED | SUPPORTED | SUPPORTED |

Pack gates: A/B command+validation INSUFFICIENT; C command+validation
SUPPORTED (all 8 sub-requirements mapped: artifact/version L3, integrity
L3 byte-match, closure L3, compatibility L4, install mechanism S018,
service/reload S016+S017, verification S017+S020, scope seed+S010).

## 11. Exact L5 sources and procedural capability each supports

- S015 invoking.html: P-INV-1/2 — apachectl recommended invocation;
  start/restart/stop signal translation. Supports: invocation mechanism.
- S016 stopping.html: P-STOP-1/2/3 — stop/graceful/restart procedures +
  pre-restart syntax check. Supports: service reload/restart requirement.
- S017 apache2ctl(8): P-CTL-1/2 — Debian command set
  (restart/graceful auto-configtest) + envvars requirement. Supports:
  runtime binary invocation + pre-restart verification.
- S018 apt-get(8): P-APT-1/2 — install pkg=version single-package
  semantics + update-before-upgrade. Supports: package-manager invocation.
- S020 httpd.html: P-HTTPD-1/2 — -v version check, -t syntax test.
  Supports: post-update verification mechanism.
- Debian mapping note: vendor 'apachectl' ≡ Debian 'apache2ctl' (S017);
  case command must use apache2ctl. No case-specific command precomputed;
  quotes bounded with provenance (P-STOP-3, P-APT-1/2).

## 12. ARM_C gate verdicts

- arm_c_command_sufficiency= SUPPORTED
- arm_c_validation_command_sufficiency= SUPPORTED
- Basis: L3+L4+L5 jointly present for the apache2 upgrade action
  (command), L3+L5 (+L4 compat context) for config/version/service
  verification (validation_command). No correctness claimed — no Agent has
  proposed anything yet.

## 13. Suitability for Phase 2 Agent trial

SUITABLE. Expected shape holds: A (version/artifact/provenance supported,
command insufficient) → B (compatibility/version-rationale improved via
deficient-fix narrative, command still insufficient) → C (procedure
evidence present, command + validation_command deterministically
SUPPORTED). Reviewer must watch: deb8u15-vs-deb8u16 version choice under
identical C evidence (both grounded; L4 favors deb8u16), and the
apachectl→apache2ctl mapping.

## 14. Pack hashes

- ARM_A_L3: 0c5e127b1eba7997a181de6035cdbb3cfa237752db4a29cfc4d4723ccbe55101
- ARM_B_L3_L4: 768320fa82966535d51c944717c71665d342cf752179a64f9e8b87cf12aff1e6
- ARM_C_L3_L4_L5: 403dce7897cd0d209f0f409c30fe5d272cc1d109eb0df1694dbf8b91c62caeae

## 15. Validation results

All packs parse; schema keys present; pack hashes recompute-verified;
binding correct; refs resolve (pack ∪ graph roots); ref hashes match
graph bytes; no failed source used as authority; provenance complete;
monotonicity holds; no L4 leakage into A (S001/S002 CANDIDATE_ONLY +
unused, S006 regression pointer redacted from A summary, content sections
null); no L5 leakage into A/B (refs absent); semantic contract reused
byte-for-byte with no case strings; no proposal/reviewer content; no
execution artifact; no Knowledge write; no production modification.
ARM_C L5 5-point check: all five procedure sources authoritative for the
runtime/vendor/component, provenance-linked, retrieved, action-relevant,
and procedure-level. See pack_validation.json per arm (all PASS).

## 16. Production files modified

NONE by this experiment. Pre-existing dirty tree preserved untouched
(no reset/clean/stash/checkout/revert). New files only under
research/llm_reasoning/patch_assist_prototype/runs/EXP-PROC-7X9D-01/.
Lab-side effects: none (no docker, no container, no image build).
Network: evidence retrieval only (19 documents + 1 artifact + 2 index
files, all hashed).

## 17. Unresolved issues before ROLE A

- Target-version choice (deb8u15 scanner-fixed vs deb8u16 L4-supported)
  is intentionally left to the Phase-2 Agent; both are evidence-grounded,
  L4 favors deb8u16. Not a defect — a designed interpretation test.
- S003 (stretch DSA) is graph transparency only, never cited.
- KEV double-negative and snapshot corroboration are reviewer context.
- Next task opens ROLE A with these frozen packs; any further retrieval
  requires a new pack revision.
