# Phase 1 Report — EXP-BASH-7X9B-01 (Evidence Preparation Only)

No ROLE A reasoning, no proposal, no ROLE B review, no commands, no
execution, no submission, no AFTER scan, no re-exploit, no evaluation, no
Knowledge writes, no production modification was performed in this phase.

## 1. Selected case

bash 4.3-11+deb8u1 (deb, debian-8.10 amd64) on `kalama-lab:type-c-shellshock`
(RepoDigest `sha256:1ee787c9…`). Primary CVE-2019-9924 (HIGH, rbash
BASH_CMDS) + incidental CVE-2016-9401 (MEDIUM), both fixed in 4.3-11+deb8u2
(Debian LTS DLA-1726-1). Single action patch-001. See case_selection.md.

## 2. Why suitable

Scanner-visible with fixed-version path; EOL/LTS repo-availability
uncertainty; backport-vs-upstream version question; container service
procedure question; bounded to one package/one fixed revision. The lab's
original Shellshock CVE is not scanner-visible (installed bash postdates
that fix) and the source-built /usr/local/bash-4.3.0 is recorded as an
out-of-scope boundary, not a target.

## 3. Contamination audit

PARTIALLY_CONTAMINATED (lab-doc reference only — `docs/LAB_CASES.md` build
instructions and FixType C note; no scans, forms, commands, closures, or
procedures on record). Struts2 family and CVE-2015-1427/elasticsearch cases
examined and rejected (the latter CONTAMINATED: full pipeline patch record
in `output/live-cve-2015-1427-fixture-validation-3/`). See
contamination_audit.md.

## 4. Frozen seed identity

`seed/frozen_seed.json` (sha256:abe066fb…), raw Trivy scan
`seed/trivy_before_scan.json` (sha256:e0ebf0d0…; 258 findings, trivy 0.74.0,
Debian 8.10 EOSL), `seed/image_config.json` (sha256:e9af0ebf…).
Acquisition: docker pull + tag per LAB_CASES.md, tar scan, read-only
inspect. No container executed, no Kalama pipeline run.

## 5. Source-root derivation summary

SEED-01 scanner finding (references/package/datasource derivation),
SEED-02 scanner DataSource (tracker navigation), SEED-03 runtime image
config (procedure facts only). No LLM/root invention; no search-engine,
blog, mirror, or unparented sources. Homepage metadata link observed but
never traversed.

## 6. Source graph statistics

19 records (3 seed roots + 16 fetch records): 11 RETRIEVED, 5 FETCH_FAILED
(S001/S014 PoW walls, S002 JS shell, S015/S016 404s), 0 unanchored, 0
missing parents, valid:true. Manifest sha256:684bcb59… (pre-pack; packs
carry their own hashes).

## 7–9. Arms and sufficiency

- ARM A (L0+L1; pack c7d22143…): version SUPPORTED; provenance/integrity/
  closure INSUFFICIENT; strategy PARTIAL; command/validation INSUFFICIENT.
- ARM B (+L2/L3; pack 35ee4458…): version/provenance/integrity/closure/
  strategy SUPPORTED (.deb hash matches index exactly); command/validation
  INSUFFICIENT (L4/L5 missing).
- ARM C (+L4; pack a780084f…): as ARM B plus promoted DLA record S013 and
  upstream fix entry S004 with version-family note; command/validation
  INSUFFICIENT (PROCEDURE_UNKNOWN).

## 10. Missing evidence by arm

ARM A: artifact/closure/procedure + DLA prose. ARM B: compat docs +
procedure. ARM C: Debian changelog prose + DLA prose + procedure docs.
Full details: acquisition/missing_evidence.json.

## 11. Runtime-doc vs runtime-evidence status

(B) frozen runtime deployment evidence only (apache2ctl foreground CMD,
PATH, cgi build history); vendor documentation (D) neither — no URLs in
runtime evidence, invention forbidden. Whether (B) alone could suffice is
open analysis, not a Phase 1 finding.

## 12. Isolation/leakage validation

Monotonic refs: A(5) ⊂ B(13) ⊂ C(15); S004 CANDIDATE_ONLY in A/B,
PROMOTED_UPSTREAM only in C; S013/S014 only in C; no L4/L5 content in A/B.
Machine-checked: required keys present, no dangling parents, all retrieved
sources hashed, no proposal/reviewer content in any pack, pack hashes
recompute-verified (see pack_validation.json per arm).

## 13. Pack hashes

- ARM_A_L1: c7d22143166595953bc28f757903945855eff1e040a18cfaa888d1f8f79e25f2
- ARM_B_L3: 35ee44588ee913590b71e241695e299ebfdece631c8cc23b939511b64479fa5a
- ARM_C_L3_L4_L5: a780084f1983f6b2136a90617d359353df034546cd6f4c021e64ababcfc24707

## 14. Schema validation results

All packs parse; schema required keys present; per-field contract shapes
conform to evidence_pack/source_reference schemas (verified against
`schemas/*.schema.json` required lists and ref/hashes/parent checks above).

## 15. Production files modified

NONE. Lab-only side effects outside the experiment dir: docker pull + tag
of the public lab image (no repo file impact). Dirty tree otherwise
preserved; no reset/clean/stash/checkout/revert/delete.

## 16. Dirty-tree preservation statement

All pre-existing modified/untracked files left untouched; new files only
under `research/llm_reasoning/patch_assist_prototype/runs/EXP-BASH-7X9B-01/`.

## 17. Unresolved issues before ROLE A

- Command/validation gates are INSUFFICIENT in all three arms (L5 vendor
  docs unobtainable under policy); ROLE A must abstain on both fields in
  every arm — a designed abstention-correctness test, not a defect.
- ARM C folder name implies L5; evidence_level honestly records L5 missing.
- KEV negative, PoW/404 failures, and the /usr/local-bash scope boundary
  are documented for reviewer context but change no gate.
- Next task opens ROLE A with these frozen packs; no further retrieval
  during reasoning/review except via a new pack revision.
