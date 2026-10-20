# Readiness action plan

1. Start Docker Desktop with the Linux engine and rerun `kalama doctor`.
2. Run `setup-workbench.sh` only after Docker is available; verify
   `kalama-net`, `kalama-workbench-modern`, `msf-resolver-host`, and Trivy from
   Doctor output.
3. Resolve the focused test failures, beginning with sandbox temporary-folder
   permissions and the attribution assertion failures.
4. Re-run the focused tests and then the relevant integration tests without
   launching exploits or patching targets as part of readiness-only work.
5. Before any new case, confirm target identity capture, patched-image identity,
   AFTER target attribution, and a positive remediation-validation state are
   produced by the current implementation.

Until steps 1 and 2 pass and the integration concerns are addressed, a new
full end-to-end run should not be started.
