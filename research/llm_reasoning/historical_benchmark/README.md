# Task 7.5.3 — Historical Reasoning Benchmark

This research-only benchmark enforces a temporal cutoff between frozen
model-visible evidence and evaluator-only historical revisions. It is derived
from `human_gap_audit/REPORT.md` and independently checked against `lkW2d`
state/forms/results.

## Result

No case is admitted. The four runtime-to-dependency candidates and the full
r1→r2 closure candidate lack a preserved, dated pre-r2 runtime observation.
The only repository-local record containing the needed exception strings is
`docs/session-log-2026-09-09.md`, a retrospective note created after the r2
decision. Making that note model-visible would leak post-decision knowledge.

The structure and tests remain intentionally useful: a later benchmark can add
an admissible case only by providing frozen pre-decision evidence, not by
reusing the r2 form or retrospective note. No Ollama call is permitted when
there are zero admitted cases.
