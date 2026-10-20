# Patch coverage audit

The historical `lkW2d` defect is generic: `PatchAction` contains occurrences,
but execution success was defined by command exit status. Human commands that
printed `SCOPE_EXCLUDED_NOOP` and `*_UNCHANGED_OK` became `result: SUCCEEDED`.

This task adds a generic `remediation_effect` to execution records:

- `COMMAND_SUCCEEDED` means the command completed successfully;
- `NO_OP` means the command explicitly reported excluded/unchanged scope;
- `COMMAND_FAILED` means execution failed.

After-scan evidence now preserves per-CVE action effects and `no_op_cves` in
`patch_coverage`, and maps an all-NO_OP CVE to action status `NO_OP` rather than
`SUCCEEDED`. Scanner and exploit evidence remain authoritative for final
remediation; command success alone cannot produce `VERIFIED`.

The historical artifacts were not rewritten.
