# Kalama MVP

Kalama is a state-driven vulnerability research pipeline for authorized lab environments. The canonical state for each run is stored under `output/state/`.

## Fresh-clone setup

Python requirements:

- Python 3.10 or newer
- PyYAML (installed by the package declaration)

System/runtime requirements:

- Docker CLI and a reachable Docker daemon
- Network access for Docker images, Trivy DB, FIRST EPSS, and CISA KEV
- Scanner and Metasploit infrastructure prepared by `setup-workbench.sh`

Install the Python package:

```bash
git clone <repo>
cd <repo>

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

Prepare the lab infrastructure and validate it:

```bash
./setup-workbench.sh
kalama doctor
```

Setup creates or reuses `kalama-net`, `kalama-workbench-modern`, and `msf-resolver-host`, then prepares `output/state`. Trivy is checksum-verified and installed inside `kalama-workbench-modern`; it is intentionally not a host dependency. Existing incompatible containers cause a conflict error and are never replaced automatically.

`kalama-workbench` is the legacy workbench name and is not inspected, adopted, started, renamed, or deleted by the current setup. The modern architecture exclusively owns `kalama-workbench-modern`.

```text
Host
├── Python / Kalama
├── Docker CLI and daemon
├── kalama-workbench-modern
│   ├── Docker socket mount
│   └── Trivy
└── msf-resolver-host
    └── Metasploit Framework
```

Doctor is read-only: it does not install packages, create networks, start containers, pull images, or mutate pipeline state.

When Doctor reports `READY`:

```bash
kalama run --image vulhub/bash:4.3.0-with-httpd
```

Both CLI forms are equivalent:

```bash
kalama --help
python3 -m kalama --help
```

For a detailed Thai walkthrough, including Attack Form and Patch Form examples, see [MANUAL_TH.md](MANUAL_TH.md).

## Current remediation boundary

Implemented execution strategies are `PACKAGE_MANAGER`, `HUMAN_COMMAND`, and `PREBUILT_IMAGE_REPLACEMENT`. `COPACETIC`, `ARTIFACT_REPLACEMENT`, and `REBUILD` remain explicitly unsupported.
