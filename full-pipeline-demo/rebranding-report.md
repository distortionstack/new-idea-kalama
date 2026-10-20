# VIPER rebranding report

## Changes

- Added the user-facing name: **VIPER — Vulnerability Inspection, Patching, and Exploit Retesting for Container Images**.
- Added the `viper` console entry point while retaining `kalama`.
- Updated CLI help and the Doctor module description to use VIPER branding.
- Updated the README introduction and compatibility statement.

## Compatibility measures

- `python -m kalama` and the `kalama` console command remain available.
- The implementation package remains `kalama`.
- Existing Docker images, containers, `kalama-net`, environment variables, artifact schemas, paths, run IDs, and hashes were not renamed.
- No historical evidence was rewritten.

## Validation

- Editable package installation passed.
- `viper --help` passed.
- `python -m kalama --help` passed.
- `viper doctor --json` returned `ready: true` when run with host Docker access.

## Remaining migration work

Internal identifiers intentionally remain legacy-compatible. A future migration may
add a dedicated `viper` package namespace, but that is out of scope because it
would require import, artifact, and deployment migration testing.
