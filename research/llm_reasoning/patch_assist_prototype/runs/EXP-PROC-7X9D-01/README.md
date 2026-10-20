# EXP-PROC-7X9D-01 — Prospective Procedure-Evidence / Command-Capability Experiment (Phase 1)

Research-only prospective experiment. No production behavior modified. No
remediation executed. No Patch Form submitted. No Agent/Reviewer run. No
Knowledge write. No external LLM API used.

Research question: does adding genuine L5 runtime/vendor procedure
evidence — holding lower-level evidence and system semantics controlled —
enable evidence-grounded `command` / `validation_command` proposals without
increasing unsupported claims or human refinement? This phase prepares and
freezes the inputs only.

- Case: `apache2` 2.4.10-10+deb8u12 → L4-supported fix 2.4.10-10+deb8u16
  (CVE-2019-10092 primary + CVE-2019-10098 incidental) on
  `kalama-lab:type-c-shellshock`. See case_selection.md.
- Contamination: PARTIALLY_CONTAMINATED (shared-image seed/lab-doc
  exposure only; no prior remediation answer). See contamination_audit.md.
- Run: 6WUM1. Action: patch-001.
- Semantic contract: byte-for-byte reuse of frozen
  `kalama_patch_semantics_v1.json`
  (sha256:51c96cafd129d09e429ebe392189781e8a5c0caff97915ba9ee76ebd0ab672f8).
- Arms (monotonic refs 13 ⊂ 17 ⊂ 22):
  ARM_A_L3 (0c5e127b…) — L0–L3; command/validation INSUFFICIENT.
  ARM_B_L3_L4 (768320fa…) — +L4 (DLA-1900-2 deficient-fix narrative);
  command/validation still INSUFFICIENT.
  ARM_C_L3_L4_L5 (403dce78…) — +L5 (Apache + Debian procedure docs);
  command/validation SUPPORTED.

Layout: README.md, case_selection.md, contamination_audit.md,
experiment_manifest.json, source_roots.md, source_graph.json,
source_manifest.json, acquisition/retrieval_log.jsonl,
acquisition/raw/*, authority_decisions.json, missing_evidence.json,
frozen_seed.json, semantic_contracts/, arms/*/evidence_pack.json +
pack_validation.json, phase_1_report.md.

STOP: packs frozen and validated. No ROLE A/B, no evaluation, no patch.
