# Pipeline overview and data flow

`TRIVY_BEFORE` supplies vulnerability records to `TOP30_BEFORE`, which feeds
the resolver. The resolver produces a human-reviewable Attack Form and a
confirmed exploit configuration. BEFORE exploit evidence is then joined with
remediation discovery and the reviewed Patch Form to create a Patch Plan.
Patch execution creates a patched image identity. AFTER scanning compares the
intended CVE against that patched target; re-exploitation consumes the AFTER
exploit configuration and target. Evaluation joins the stage records into a
TOP_N_ONLY dataset and metrics.

The run demonstrates three ownership classes:

- deterministic system artifacts: scan, ranking, state, patch result, and
  evaluation files;
- external/runtime evidence: Metasploit results and Docker image/container
  identities;
- human-confirmed inputs: Attack Form and Patch Form submissions.

Optional dynamic scan, knowledge-store, and LLM-assist paths are not claimed as
participants in this run. The run's state and artifact index are authoritative
for what was produced.
