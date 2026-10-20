# VIPER / Kalama

**VIPER — Vulnerability Inspection, Patching, and Exploit Retesting for Container Images**

VIPER is the user-facing name of the authorized container vulnerability
inspection and remediation pipeline. The historical `kalama` Python package,
`python -m kalama` compatibility path, Docker resources, network names, and
artifact schemas remain unchanged to preserve existing evidence provenance.

The preferred CLI is `viper`; `kalama` remains supported as a compatibility
entry point.

Kalama is a state-driven vulnerability-validation pipeline for **authorized, isolated lab containers**. It scans a Docker image, ranks findings, gathers Metasploit module information, and pauses for human review before any exploit-validation stage.

## Core pipeline

```text
Docker image
   |
Scan -> Prioritize Top-N -> Resolver / Attack Form (human review)
   |
BEFORE exploit validation -> Remediation / Patch Form
   |
AFTER scan -> Re-exploit -> Evaluation
```

Kalama intentionally runs one stage at a time after a pause. A successful `kalama run` does not mean every later stage ran.

## Important: authorized lab use only

Run Kalama only against containers or systems you own or are explicitly authorized to test. Use isolated Docker lab targets. The normal managed-target flow attaches containers to `kalama-net` without publishing host ports.

## Tested environment

This path was validated from a clean clone on Windows using Git for Windows 2.55.0, Python 3.12.10, Docker Desktop 29.7.2 with the Linux/WSL2 backend, Docker Compose 5.5.0, and Git Bash only for the setup script. The project requires Python 3.10 or newer.

You do not install Trivy or Metasploit on the host. Setup installs Trivy in Kalama's workbench and starts a Metasploit container.

## 1. Install prerequisites

Install Git for Windows, Python 3.10+, and Docker Desktop. Configure Docker Desktop for Linux containers, then use PowerShell to check them:

```powershell
git --version
py --version
docker version
docker compose version
docker info
```

`docker info` must show a Server section. If it reports a daemon pipe/access error, start Docker Desktop, wait for it to be ready, and make sure your account can use Docker. Do not use prune commands as routine troubleshooting.

If `py` is unavailable, re-run the Python installer with the launcher/PATH option enabled, then open a new PowerShell window.

## 2. Clone Kalama

```powershell
git clone https://github.com/distortionstack/new-idea-kalama.git
cd new-idea-kalama
git status --short
```

An empty `git status --short` result means the clone is clean.

## 3. Create a Python environment

From the repository root, create and activate an isolated environment. Replace `3.12` with another installed supported version if necessary.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
```

If activation is blocked, run `.\.venv\Scripts\python.exe` directly for the commands below. Do not weaken a system-wide PowerShell execution policy just for Kalama.

## 4. Install Kalama

```powershell
python -m pip install -e .
kalama --help
kalama run --help
```

`-e` installs this checkout in editable mode. The run help confirms that `--dynamic-scan` defaults to `off`.

## 5. Prepare Docker infrastructure

`setup-workbench.sh` is a Bash script. From **Git Bash** in the repository root, run:

```bash
./setup-workbench.sh
```

It creates or reuses:

- Docker network `kalama-net`
- scanner workbench `kalama-workbench-modern` (Docker socket plus Trivy)
- Metasploit resolver `msf-resolver-host`
- `output/state/`

Setup verifies ownership/configuration and does not replace incompatible containers. Its final Doctor report should say `Overall READY`.

Back in PowerShell, confirm the resources if needed:

```powershell
docker ps
docker network ls
```

## 6. Run Doctor

```powershell
kalama doctor
```

Doctor is read-only. It checks Python/PyYAML, Docker and its daemon, `kalama-net`, the resolver container, workbench socket/Trivy, provider setup, and writable output. `Overall READY` means the core environment is ready.

## Windows (Docker Desktop + Git Bash)

Use Git Bash to run the shell setup script. Docker Desktop must be running and
configured for Linux containers before beginning. The first setup downloads the
workbench, Trivy, and Metasploit images, so it can take a few minutes.

Install these prerequisites:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with its engine running
- [Git for Windows](https://git-scm.com/download/win), including Git Bash
- Python 3.10 or newer, with `python` available in Git Bash

From Git Bash, clone and prepare the project:

```bash
git clone <repo>
cd <repo>

python -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Start Docker Desktop and wait until it reports that the engine is running. Then
run the setup and check its result:

```bash
./setup-workbench.sh
./.venv/Scripts/python.exe -m kalama doctor
```

The expected final line is `Overall READY`. If the script reports
`DOCKER_DAEMON_UNREACHABLE`, Docker Desktop has not finished starting yet; wait
for the engine to run and execute the script again.

Setup creates or reuses `kalama-net`, `kalama-workbench-modern`, and `msf-resolver-host`, then prepares `output/state`. Trivy is checksum-verified and installed inside `kalama-workbench-modern`; it is intentionally not a host dependency. Existing incompatible containers cause a conflict error and are never replaced automatically.

## 7. Your first lab run

**LAB USE ONLY.** This verified example stays on the isolated Kalama network:

```powershell
kalama run --image 2d8ru/struts2:latest
```

Do not add a dynamic-scan option for the normal workflow. The default is `off`.

The command creates a `RUN_ID`, a target named `victim-RUN_ID`, a Trivy scan, and a priority-v1 Top-N result. The initial command normally pauses at:

```text
Status: PAUSED
Current stage: STEP_4_RESOLVER
```

Inspect it with:

```powershell
kalama status RUN_ID
```

The state is `output/state/run_RUN_ID.json`; initial scan and ranking artifacts are under `output/trivy/before/` and `output/scoring/before/`.

## 8. RUN_ID, statuses, and continuing

- `RUN_ID` identifies one durable run.
- `PAUSED` means the next stage is ready; run `kalama continue RUN_ID` once.
- `WAITING_FOR_USER_INPUT` means a generated form needs review. Continuing alone intentionally does nothing.
- `FAILED_FATAL` means the run stopped with errors; inspect status before retrying.
- `COMPLETED` means all implemented stages finished.

After the first pause, run the resolver:

```powershell
kalama continue RUN_ID
```

Resolver processing can take several minutes because it reads live module metadata from `msf-resolver-host`. Do not run a second `continue` while status is `RUNNING`.

## 9. Review and submit the Attack Form

When status shows `Waiting reason: ATTACK_FORM`, it prints the form path, for example:

```text
output/resolver/forms/attack_form_RUN_ID_r1.yaml
```

Open the YAML in an editor and review every editable CVE entry. Kalama may auto-fill the isolated target in `RHOSTS`, but a suggestion is not approval.

- `module`: proposed Metasploit module.
- `RHOSTS` / `RPORT`: target address and service port.
- `TARGETURI`: application path used by the module.
- `target`: module target/profile.
- `payload`, `LHOST`, `LPORT`: callback settings when applicable.
- `preconditions`: a bounded required command before validation.
- `execution_protocol`: whether the action is check-only or includes an exploit attempt.

Confirm safe values or explicitly skip the CVE with a reason. Never submit guessed values. Then submit the reviewed form and inspect state:

```powershell
kalama submit-attack-form RUN_ID .\path\to\attack_form_RUN_ID_rN.yaml
kalama status RUN_ID
```

Submitting an unchanged form is valid but normally creates the next revision (such as `r2`) and remains `WAITING_FOR_USER_INPUT`. Kalama does not silently accept unresolved fields. Once entries are confirmed or skipped, continue with `kalama continue RUN_ID`.

## 10. Patch Form and retry

The fresh-user validation documented above exercised setup through the Attack Form boundary only. The following later-stage commands are supported by the current CLI and implementation, but were **not** live-tested in that documentation run.

Later stages can pause for `PATCH_FORM`. Submit the exact form printed by status, then continue:

```powershell
kalama submit-patch-form RUN_ID .\path\to\patch_form_RUN_ID_rN.yaml
kalama continue RUN_ID
```

Supported remediation strategies are `PACKAGE_MANAGER`, `HUMAN_COMMAND`, and `PREBUILT_IMAGE_REPLACEMENT`. `COPACETIC`, `ARTIFACT_REPLACEMENT`, and `REBUILD` are unsupported.

For a failed patch-execution stage, supported retry commands are:

```powershell
kalama retry RUN_ID --edit-plan
kalama retry RUN_ID --same-plan
```

Use `--force-smoke-failed` only with `--edit-plan` when the review record justifies it.

## 11. Results

Use `kalama status RUN_ID` first. It reports the current stage, errors, next command, and summaries for completed artifacts.

- `output/state/`: run state
- `output/trivy/before/`: initial scan
- `output/scoring/before/`: priority-v1 Top-N
- `output/resolver/`: resolver record, Attack Forms, submissions, confirmed configurations
- later completed stages add BEFORE-exploit evidence, patch results, AFTER-scan output, re-exploit evidence, and evaluation summaries

Do not interpret an artifact from an unfinished stage as proof that the pipeline completed.

## 12. Troubleshooting

| What you see | What to do |
| --- | --- |
| `py` or `python` is not recognized | Install Python 3.10+ with launcher/PATH enabled and open a new PowerShell window. |
| `DOCKER_DAEMON_UNREACHABLE` or a Docker pipe error | Start Docker Desktop, wait for Linux containers, and verify with `docker info`. |
| `Overall NOT_READY` | Read the named Doctor failure, fix that prerequisite, then rerun setup from Git Bash. |
| Workbench/resolver conflict | Do not delete it automatically; setup refuses to replace incompatible containers. |
| `PAUSED` | Run the exact `kalama continue RUN_ID` command once. |
| `WAITING_FOR_USER_INPUT` | Review and submit the exact Attack or Patch Form printed by `kalama status RUN_ID`. |
| Resolver takes time | It performs live read-only Metasploit introspection. Check status; do not start another continuation. |

## Optional features

Nuclei dynamic validation is **optional and disabled by default**. It was not installed, configured, or executed for this basic workflow. A normal user does not need a Nuclei binary, templates, manifests, runner image, or `KALAMA_NUCLEI_*` variables to use the core pipeline.

## Developer and research documentation

Research protocols and experiments are separate from beginner setup. See `docs/` only for deeper developer/research material.
