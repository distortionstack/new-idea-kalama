# Test results

`pip check`: passed.

`compileall src`: passed.

Focused non-Docker/unit coverage, rerun with `TEMP`/`TMP` redirected to a
writable workspace directory: **24 passed, 4 failed**, with 10 subtests
passed. The original Windows sandbox `PermissionError` is therefore an
environment-only issue and is no longer the explanation for the four failures.
The remaining failures are in `tests/integration/test_reexploit.py`; setup
raises `AttributeError` because the expected `PATCH_RESULT` artifact is absent
before the re-exploit assertions run. They require a separate fixture/orchestrator
investigation and are not a clean end-to-end verification.

The failures do not establish that the underlying integration logic is broken;
they do establish that this host cannot provide a clean test verification.
Docker-dependent checks were not run because the daemon is unavailable.
