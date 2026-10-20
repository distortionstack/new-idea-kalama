# Resolver fix and tests

## Current confirmed change

No resolver logic was changed while `X40Ks` was active. The existing code does
bound individual Docker and MSF subprocesses (`20s` Docker transport and
`240s` MSF calls), but it lacks a total Step 4 deadline and persisted progress
diagnostics. This is the smallest confirmed design gap; changing it while the
run is active could interfere with the original process.

## Tests performed

- `python -m py_compile tools/viper_evidence_viewer.py`: passed.
- Read-only process inspection: original resolver process confirmed alive.
- Read-only Docker inspection: `msf-resolver-host` is running and attached to
  `kalama-net`.
- Read-only script inspection: active MSF resource file identified.

A resolver regression test and bounded-total-timeout fix should be added only
after the active run exits, so the test can reproduce the one-module timeout
without touching live run state.
