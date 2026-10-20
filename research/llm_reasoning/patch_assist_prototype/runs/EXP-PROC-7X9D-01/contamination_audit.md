# Contamination Audit — EXP-PROC-7X9D-01

Method: repository-wide filename/content search plus minimum-content
inspection to determine whether a remediation answer exists for the
candidate. No historical remediation answer, command, closure, or procedure
was read for the accepted case. Scanner L0 facts (the frozen Trivy scan
bytes reused as seed) and runtime identity facts (image CMD) are seed
material, not remediation answers, and do not contaminate.

## Rejected candidate 1: Struts2 / CVE-2017-5638 / CVE-2017-9805 family

- Overlap with UZBL5, HdiiR, lkW2d, Tasks 7.5.5–7.5.8: `output/2d8ru-*`
  holds full patch reasoning, proposals, patch forms, submissions,
  commands, closures, results, and evaluations.
  Classification: REJECTED_CONTAMINATED. Rejected without further
  inspection.

## Rejected candidate 2: Elasticsearch / CVE-2015-1427 (vulhub/elasticsearch:1.4.2)

- Prior exposure: `diagnostics/diag-cve-2015-1427-*`, `output/live-*`.
- Decisive: `output/live-cve-2015-1427-fixture-validation-3/` contains a
  complete pipeline record — `patch/forms` (incl. submissions),
  `patch/plan`, `patch/results`, `verification/`, `evaluation/`, and
  `trivy/after`. A solved remediation record exists.
  Classification: REJECTED_CONTAMINATED. Rejected. No remediation content
  was opened beyond directory/file listing.

## Excluded candidate 3: bash / CVE-2019-9924 (EXP-BASH-7X9B-01)

- Prior Agent/Reviewer experiment used the exact remediation answer
  (target 4.3-11+deb8u2, artifact, closure) across three arms plus a
  semantic ablation. Reuse would violate case-selection requirements 2–3.
  Excluded by design, not inspected for procedure content.

## Accepted case: apache2 / CVE-2019-10092 (+CVE-2019-10098) on kalama-lab:type-c-shellshock

Searches performed (2026-10-11, read-only):

1. `CVE-2019-10092|CVE-2019-10098|CVE-2019-0217|CVE-2019-0220` across the
   repo: matches ONLY in
   `research/llm_reasoning/patch_assist_prototype/runs/EXP-BASH-7X9B-01/seed/trivy_before_scan.json`
   (raw L0 scanner bytes reused as this experiment's seed — seed material,
   not a remediation answer) and in Ubuntu-14.04 screening scans under
   `output/screening-*` (different image/OS; apache2 string present but
   none of these CVEs; no patch content).
2. `apache2.*2\.4\.10-10\+deb8u1[3456]|deb8u1[3456].*apache` (exact patched
   versions / artifact coordinates): NO matches anywhere in the repo. No
   prior artifact contains the target version or .deb coordinate.
3. `apache2ctl|apachectl` (exact runtime procedure): matches ONLY in prior
   run seeds/packs as frozen runtime identity facts
   (`Cmd: [apache2ctl, -DFOREGROUND]`), in `image_config.json`, in the raw
   scan image history, and in prior missing_evidence/phase_1 text noting
   procedure docs were ABSENT. No procedure documentation, no
   patch/install command, no validation command exists anywhere.
4. `output/` patch/plan/proposal/command files mentioning apache: all
   matches are `output/2d8ru-struts2-*` files whose apache string is the
   "Apache Struts" project name, not the httpd package. No apache2 package
   patch form, plan, submission, or result exists.
5. Prior Agent/Reviewer experiments (EXP-BASH-7X9B-01 arms, EXP-BASH-7X9C-SEM-01
   arm): bash-only packs/proposals/reviews. No apache2 remediation answer
   was ever proposed or reviewed.

What prior material DOES contain (incidental exposure only):

- `docs/LAB_CASES.md`: build instructions for the shared image
  (`docker tag vulhub/bash:4.3.0-with-httpd kalama-lab:type-c-shellshock`)
  and FixType C classification note. No CVE, no scan, no apache2 mention,
  no command, no procedure.
- EXP-BASH-7X9B-01 seed/packs: the shared image's Trivy bytes (which
  include the apache2 findings as uninterpreted L0 rows) and the
  `apache2ctl -DFOREGROUND` CMD fact. No apache2 target version, strategy,
  artifact, command, validation, closure, or procedure was ever recorded.

Classification: PARTIALLY_CONTAMINATED (shared-image seed/lab-doc exposure
only). Prior material contains no exact patched version, no artifact
coordinate, no remediation strategy, no patch/install command, no
validation command, no runtime procedure, and no completed patch result
for this candidate. Case remains usable.

Post-acceptance rule applied: no historical remediation answers consulted;
all pack content derives from the frozen seed plus deterministic retrieval
in this phase. The seed reuses in-repo scan bytes read-only; the reuse is
declared in seed provenance and is the experiment's L0 basis, not a
secondary source of answers.
