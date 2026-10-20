# Stage 02 — BEFORE scan and prioritization

`TRIVY_BEFORE` produced the normalized scan artifact. `TOP30_BEFORE` used
`kalama-priority-v1`, returned 30 records, and ranked CVE-2015-1427 first.
Inputs and outputs are the original JSON artifacts under `trivy/before/` and
`scoring/before/`.
