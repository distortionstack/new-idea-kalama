# Resolver root cause — Run X40Ks

## Finding

The original resolver process is still alive. At the time of inspection the
process chain was:

`viper.exe continue X40Ks` → Python → `docker exec -i msf-resolver-host`
`/usr/src/metasploit-framework/msfconsole -q -n -r /tmp/kalama_resolver_script.rc`

The run state has remained unchanged since `2026-10-14T07:58:59Z`:

- `status`: `RUNNING`
- `current_stage`: `STEP_4_RESOLVER`
- resolver stage: `RUNNING`
- errors: empty
- no resolver artifact exists

## Exact operation

The active `/tmp/kalama_resolver_script.rc` contains one module:
`exploit/multi/http/struts_dmi_exec`. The resolver is in the batched MSF module
introspection path, inside `framework.modules.create(fullname)`, before the
structured sentinel output is emitted. This is not an Attack Form or patch
operation.

The top-N artifact contains 30 distinct CVEs. `analyze_cves()` processes them
serially and calls `discover_cve()` for each. The current design can therefore
perform many sequential MSF calls, each with `MSF_TIMEOUT_SECONDS = 240`.

## Classification

At inspection time this was a slow/blocking external MSF operation, not a
Python process failure or deadlock proven by the available evidence. The child
process was alive and consuming MSF/Ruby time. The subprocess call has a 240
second timeout, but there is no overall Step 4 deadline, progress checkpoint,
or persisted operation diagnostic. Consequently the user-visible state can
remain `RUNNING` for a long time with no explanation.

## Recovery decision

Do not resume concurrently while the original process is alive. The run is
safe to resume only after the process exits and the state is reconciled. No
state, artifact, or historical evidence was modified during diagnosis.
