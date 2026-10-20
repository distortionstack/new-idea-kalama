# Task 7.5.5 pre-run blocker report

## Scope reached

- Repository: `C:\Users\distortion\Documents\new-idea-kalama`
- Date/time zone: 2026-09-16, Asia/Bangkok
- Intended subject image, read only from the permitted HdiiR target binding:
  `2d8ru/struts2@sha256:7aa386b4b606bec5f6a7f015bab6bd1cc84169beadb2a632b6939e6e703e47db`
- No remediation conclusions, Patch Form values, target versions, dependency closure,
  patch commands, or validation commands were read from HdiiR or historical runs.
- No external remediation URL was opened.

## Preflight result

Kalama Doctor reported `Overall NOT_READY` because the Docker Desktop Linux
engine pipe `npipe:////./pipe/dockerDesktopLinuxEngine` was unavailable. This
also left `kalama-net`, `msf-resolver-host`, the workbench, and Trivy unchecked.

Starting Docker Desktop caused its backend to crash before the engine became
available. The first observed crash was caused by inaccessible stale Unix-domain
socket entries under:

`C:\Users\distortion\AppData\Local\Docker\run`

After stopping Docker/WSL, that runtime directory was moved recoverably to:

`C:\Users\distortion\AppData\Local\Docker\run.backup-task755`

and a new empty runtime directory was created. The next startup exposed the same
failure under:

`C:\Users\distortion\AppData\Local\docker-secrets-engine`

That runtime directory was likewise moved recoverably to:

`C:\Users\distortion\AppData\Local\docker-secrets-engine.backup-task755`

and recreated empty. A subsequent startup created fresh socket entries but still
crashed with `The file cannot be accessed by the system` while initializing the
Ingest server. The Windows UI automation fallback could not initialize because
its helper was denied by the sandbox (`apply deny-read ACLs`). No Docker factory
reset, Docker data deletion, image deletion, container deletion, or repository
cleanup was performed.

Docker Desktop processes and WSL were stopped after the failed recovery attempts.
Both backup directories remain present.

## Experiment state

- New run_id: not created
- New victim/container: not created
- BEFORE scan: not run
- Resolver/Attack Form: not run
- BEFORE exploit: not run
- STEP_5_PATCH_PLAN: not reached
- PATCH_REASONING_SEED: not created
- External source graph: not started
- Patch proposal: not created
- Patch execution / AFTER scan / re-exploit / evaluation: not run

No canonical run was partially created, so there is no run-scoped artifact
directory for Task 7.5.5 yet.

## Required recovery

A Windows restart is the remaining bounded recovery for the inaccessible
AF_UNIX socket state. After restart, start Docker Desktop and require `kalama
doctor` to report `Overall READY` before creating the fresh run. The experiment
must then begin from the production `kalama run` command and preserve the source
discovery restrictions in the Task 7.5.5 protocol.

TASK_7_5_5_STATUS: BLOCKED
