# End-to-end execution plan — approval required

This is a plan only. No exploit or patch has been executed.

1. Start Docker Desktop Linux engine; run `kalama doctor` and require
   `Overall READY`.
2. Confirm `kalama-net`, workbench/Trivy, Metasploit resolver, and the
   immutable digest for `kalama-lab:type-c-shellshock`.
3. Run the target scan and Top-N prioritization; confirm CVE-2014-6271 is in
   scope and record the package/version/fixed-version evidence.
4. Review and submit the Attack Form; execute and attribute the BEFORE
   Shellshock exploit to the managed target.
5. Generate and review the Package Manager Patch Form. Require complete
   occurrence coverage and reject any NO_OP/excluded intended occurrence.
6. Execute the patch, record package version and health checks, then scan the
   patched image.
7. Re-exploit the verified AFTER container using the same invariant
   configuration and require a complete negative observation.
8. Accept success only if scanner scope is `NOT_FOUND`, AFTER target identity
   matches the patched image, the exploit oracle is valid negative, health
   checks pass, and final remediation status is authoritative `VERIFIED`.

Approval is required before any live exploit or patch operation.
