# Kalama LLM reasoning benchmark

## Purpose

Extraction is not evidence that an LLM can safely help a Resolver gap: a
deterministic parser can copy a value faster and with a narrower failure mode.
Task 7.5.2 therefore freezes a benchmark only after real evidence passes
provenance, non-copy, necessity, ground-truth, ablation, and counterfactual
checks. No model is run by this task.

## Classification

`COPY` carries the answer in one item. `SELECTION` chooses among explicit
values. `DETERMINISTIC_RULE` is an exact lookup, normalization, version check,
or set intersection and belongs in ordinary code. `SEMANTIC_INTERPRETATION`
requires contextual meaning across evidence and has no safe small rule.
`INSUFFICIENT` lacks a unique safe answer; `INVALID` has bad provenance,
identity, phase, or ground truth.

## Discovery result

The Task 7.4/7.5 fixtures were inspected together with resolver/evidence unit
fixtures, dynamic-probe code/tests, session log, lab metadata, review bundles,
and patch fixture sources. No natural benchmark qualifies.

| Candidate | Category | Result |
| --- | --- | --- |
| Case B target/payload/targeturi | COPY | Expected value is in a single MSF item. |
| Case F target_version | COPY | Validated-Knowledge item carries the version. |
| Struts runtime base path -> TARGETURI | DETERMINISTIC_RULE | Base-path normalization is already explicit deterministic code; a base path is semantically the answer. |
| MSF payload + platform facts | DETERMINISTIC_RULE/SELECTION | Compatibility intersection is code, not semantic judgment. |
| Patch fix/strategy/build system fixtures | COPY or DETERMINISTIC_RULE | Existing fixture evidence either says the enum or maps it directly. |

## Controlled-lab plan for Task 7.5.3 preparation

Task 7.5.2 concludes `CONTROLLED_LAB_FIXTURE_REQUIRED`, but does not execute
the lab. Reuse the accepted local Struts target only. Create a research-only,
non-execution patch-planning scenario for `strategy`: record the real local
Dockerfile/build context, a truthful local build manifest, and an unchanged
upstream remediation passage whose prose describes conditions rather than a
strategy enum. The lab must establish independently that the selected artifact
cannot be safely replaced in place and that rebuilding the existing image is
the accepted configuration. The evaluator-only lab configuration records gold
`REBUILD`; the prompt receives neither this assertion nor a text saying
"strategy = REBUILD".

At least two contributions must be necessary: the build/deployment context and
the remediation-condition evidence. Removing either leaves relevant evidence
but requires abstention. The counterfactual changes only the controlled build
context to a truthful in-place artifact configuration and independently sets
gold to the corresponding allowed strategy; vulnerability/CVE/module facts and
the semantic relation stay fixed. The lab must be read-only until the separate
authorized task, must not execute a patch, must clean temporary research files,
and must emit signed/hashed observation artifacts, provenance, candidate and
phase bindings, prompt digest, and evaluator-only truth.

## Future Task 7.5.3 matrix

Run three frozen repetitions each for: full evidence -> gold; one-evidence
ablation -> `{\"value\":null,\"evidence_refs\":[]}`; counterfactual full ->
changed gold; and counterfactual ablation -> abstention. Report structured and
typed correctness, required-reference sufficiency, validator conformance,
latency/tokens, fabricated/forbidden output, unsupported inference, and
counterfactual consistency. The latter requires both full conditions correct,
different values, and outputs following the changed evidence.

Counterfactuals are the primary pretrained-memory control. Record whether CVE,
module, and product facts are necessary; omit optional identifiers only when
that does not alter task semantics. The evaluator truth never enters prompt
serialization (enforced by research tests).

## Limitations

No natural semantic fixture was found. The controlled plan still needs a real,
authorized lab run and semantic review before it can be labeled ready. It must
not be used to change production Resolver behavior or justify Task 7.6.
