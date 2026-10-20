# Provenance audit

The state files provide run IDs, source and patched image identities, stage
timestamps, artifact paths, schemas, and SHA-256 hashes. The selected
near-candidate `lkW2d` consistently uses the `2d8ru/struts2` source identity
and records patched image `kalama/struts2:patched-lkw2d`.

The artifact index links BEFORE and AFTER results to the same run ID and CVE
set. Attack Form and Patch Form revisions are recorded, including the patch
retry (`revision: 2`, `retry_mode: EDIT_PLAN`).

This establishes artifact lineage, but not successful remediation. The
authoritative state remains `INCONCLUSIVE`; the AFTER scan still reports both
CVEs as found. The legacy `STEP_5_PATCH` umbrella status is also
`NOT_STARTED` even though patch-plan and patch-execution sub-stages succeeded.
This contradiction is preserved and not normalized into a success claim.
