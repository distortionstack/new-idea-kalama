# Run recovery plan

1. Allow the active MSF subprocess to reach the existing 240-second bound.
2. Confirm whether `X40Ks` transitions to a persisted failure or remains
   `RUNNING` after the child exits.
3. If it fails with a resolver timeout, preserve that state and artifact as the
   root-cause evidence; do not retry the same run blindly.
4. Add an overall resolver deadline and per-CVE progress diagnostics, then run
   a bounded diagnostic test with a single selected CVE.
5. Resume `X40Ks` only if the persisted state is a valid continuation boundary
   and no process for that run remains alive.
6. Otherwise document the non-resumable state before creating any new Run ID.

Attack Form, Patch Form, exploit, and patch gates remain mandatory.
