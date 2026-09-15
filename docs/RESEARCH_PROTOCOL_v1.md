# Kalama / EVVP Research Protocol v1

**Status:** immutable after publication  
**Protocol version:** `v1`  
**Created at:** `2026-09-11T21:55:56Z`  
**Protocol hash:** recorded in `docs/RESEARCH_PROTOCOL_v1.sha256`

## Immutability and applicability

This document freezes the questions, hypotheses, variables, and interpretation rules before any additional paired measurement is collected. It must not be edited in place. A change to any research question, hypothesis, variable, eligibility policy, dynamic scope, template input, or analysis rule requires a new protocol version and a new document hash.

Every future confirmatory paired run must record this exact protocol version and SHA-256 hash. Existing runs `YUihQ` and `5IULR` remain immutable and are labelled **pilot / preliminary observations**. They are repeatability evidence, not confirmatory observations under this protocol.

## Provenance

| Item | Frozen value |
| --- | --- |
| Git `HEAD` | `1b617928d2df66f14a0f62b48ef119472c3dbdce` |
| Working tree at protocol creation | Dirty; this protocol does not assert a clean source checkout. |
| Priority identifier | `kalama-priority-v1` |
| Priority formula | `cvss + epss*3 + kev*3` |
| Top-N | `30` |
| Dynamic provider/profile | Nuclei / `safe-cve-http` |
| Nuclei runner image | `kalama/nuclei-probe:3.11.1` |
| Nuclei version | `v3.11.1` |
| Nuclei image digest | `sha256:2c7fe35eaf345c3600c0126d0361ea065a6c536fbe225ccfc4c49e07fd32f808` |
| Template revision / tree hash / manifest hash | **Not configured at protocol creation** |

### Confirmatory-run precondition

No confirmatory measurement is authorized under this protocol until the approved manifest path, manifest SHA-256, template revision, and template-tree SHA-256 are recorded in a new protocol version. These values are absent from the current environment; they must not be inferred from pilot outputs or invented. The successor protocol must retain the questions and rules below unchanged if it is to be treated as the same study design.

## Primary research question

**RQ1:** Does locally observed dynamic validation evidence from Nuclei provide additional information about empirical exploitability among vulnerabilities selected by Kalama priority-v1?

Thai meaning: หลักฐานจากการตรวจสอบแบบ dynamic ด้วย Nuclei สามารถให้ข้อมูลเพิ่มเติมเกี่ยวกับความสามารถในการ exploit จริงของช่องโหว่ที่ถูกเลือกโดย Kalama priority-v1 ได้หรือไม่

## Primary hypotheses

**H0:** Among eligible Top-N candidates, the empirical BEFORE-exploit success rate for candidates with `CORROBORATED` dynamic evidence is not higher than for candidates without `CORROBORATED` evidence.

**H1:** Among eligible Top-N candidates, candidates with `CORROBORATED` dynamic evidence have a higher empirical BEFORE-exploit success rate than candidates without `CORROBORATED` evidence.

Statistical significance testing is deferred until the confirmatory sample is adequate. These hypotheses define a future comparison and do not imply support for H1.

## Secondary descriptive research questions

**RQ2:** What proportion of priority-v1 Top-N candidates can be dynamically evaluated using the approved Nuclei `safe-cve-http` profile?

Report `CORROBORATED`, `NOT_OBSERVED`, `NOT_APPLICABLE`, `INCONCLUSIVE`, and `NOT_RUN`, plus dynamic coverage rate. `NOT_APPLICABLE` is not a failure.

**RQ3:** How do application/deployment path conditions affect dynamic validation results?

Preserve `base_path`, `base_path_source`, `scope_version`, each template × path result, and matched path. This is descriptive. Paths must be declared before exploit outcomes are known; no post-outcome path additions are permitted.

**RQ4:** How repeatable are dynamic validation and BEFORE exploit outcomes when the same target/configuration is executed repeatedly?

Report unique target/configuration observations separately from repeatability runs. Repeated executions must not increase the independent sample size.

## Variables, unit, and interpretation

| Role | Frozen definition |
| --- | --- |
| Primary explanatory variable | `dynamic_positive = (dynamic_signal == CORROBORATED)` |
| Primary outcome | `exploit_positive`, using the existing BEFORE exploit evaluation policy unchanged |
| Eligibility | Existing BEFORE `metric_eligibility` policy; do not redefine it |
| Raw outcome | Preserve the raw BEFORE disposition separately |
| Primary unit of analysis | One Top-N candidate CVE in one run |
| Generalization unit | Distinguish independent target/configuration cases from repeatability runs |

`NOT_OBSERVED` does **not** mean “not vulnerable.” It means only that all approved template × declared application-path bindings completed successfully and produced no match within the declared dynamic-validation scope. Its relationship with exploit outcomes is descriptive unless a later protocol explicitly defines another analysis.

## Required provenance for each future confirmatory run

Each run must reference this protocol hash and preserve: protocol version, priority-v1 identifier, Top-N, Nuclei version and image/binary hash, template revision/tree hash, approved manifest hash, declared application paths and their sources, raw dynamic records, raw BEFORE disposition, and existing eligibility-policy output.
