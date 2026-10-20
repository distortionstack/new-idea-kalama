# Contamination Audit — EXP-BASH-7X9B-01

Method: filename/index/metadata search plus minimum-content inspection to
determine whether a remediation answer exists. No historical remediation
answer, command, closure, or procedure was read for the accepted case.

## Rejected candidate 1: Struts2 / CVE-2017-5638 / CVE-2017-9805 family

- Overlap with UZBL5, HdiiR, lkW2d, Tasks 7.5.5–7.5.8 (full patch reasoning,
  proposals, commands, closures on record). Classification: CONTAMINATED.
  Rejected without further inspection.

## Rejected candidate 2: Elasticsearch / CVE-2015-1427 (vulhub/elasticsearch:1.4.2)

- Prior exposure found: `diagnostics/diag-cve-2015-1427-*` (exploit probes),
  `output/live-cve-2015-1427*` (trivy scans, attack forms, resolver state).
- Decisive: `output/live-cve-2015-1427-fixture-validation-3/` contains a
  complete pipeline record — `patch/forms` (incl. submissions),
  `patch/plan`, `patch/results`, `verification/remediation*`,
  `evaluation/`, and `trivy/after`. A solved remediation record exists.
- Classification: CONTAMINATED. Rejected. No remediation content was opened
  beyond directory/file listing.

## Accepted case: bash / CVE-2019-9924 on kalama-lab:type-c-shellshock

- Searched `output/`, `research/`, `docs/`, `diagnostics/`, `attack/`,
  `review-bundles/` for: `CVE-2014-6271`, `CVE-2019-9924`, `CVE-2016-9401`,
  `shellshock`, `type-c-shellshock`, `kalama-lab:type`.
- Result: exactly one reference — `docs/LAB_CASES.md` ("FixType C — OS
  package" lab entry: image name, vulhub source path, `kalama run` command,
  FixType C classification note, and the observation that an old repository
  can yield a PACKAGE_AVAILABLE negative result).
- What LAB_CASES.md does NOT contain: any scanner output for this image, any
  patch form/plan, any command or validation command, any dependency
  closure, any checksum, any successful patch procedure, any evaluation.
- Trivy scan in this phase (fresh, 2026-09-17) shows the lab's original
  CVE-2014-6271 is NOT scanner-visible (installed bash reports
  4.3-11+deb8u1, already past the Shellshock fix); the scanner-visible
  action is CVE-2019-9924 → 4.3-11+deb8u2, which no prior artifact discusses.
- Classification: PARTIALLY_CONTAMINATED (lab-doc reference exposure only).
  Prior material contains no exact remediation answer, command, dependency
  closure, or successful patch procedure. Case remains usable.
- Post-acceptance rule applied: no historical remediation answers consulted;
  all pack content derives from the frozen seed plus deterministic retrieval
  in this phase.
