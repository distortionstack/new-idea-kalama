# Unified Resource Discovery dependency preflight

Scope: the dependency needed before Task 3 only.  The full provider inventory for
`registries`, its Go dependency graph, and optional `id2url` remains Task 6 work
after the provider spikes.

## Decision

`packageurl-python==0.17.6` is approved as a production dependency for PURL
parsing and serialization.

- Package: `packageurl-python`
- Version reviewed: `0.17.6`
- License: MIT
- Python support: `>=3.8` (VIPER requires `>=3.10`)
- Runtime dependencies: none declared
- Default-distribution policy: allowed
- Pinning policy: exact version in `pyproject.toml`
- Distribution obligation: retain the upstream MIT copyright and permission
  notice in packaged third-party notices

Evidence checked:

- Installed wheel metadata in the project virtual environment reports version
  `0.17.6`, license `MIT`, Python `>=3.8`, and no runtime `Requires-Dist` entries.
- PyPI release metadata identifies the wheel SHA-256 as
  `31a85c2717bc41dd818f3c62908685ff9eebcb68588213745b14a6ee9e7df7c9`.
- Upstream repository contains `mit.LICENSE` and identifies the project license
  as MIT.

Sources:

- <https://pypi.org/project/packageurl-python/0.17.6/>
- <https://github.com/package-url/packageurl-python/blob/main/mit.LICENSE>

## Packaging caveat

PyPI reports no provenance attestation for the `0.17.6` release files.  This does
not block Task 3, but a reproducible production lock/build process must verify the
published wheel checksum and include the upstream license notice.  This preflight
does not approve `id2url`, any Go resolver binary, or their transitive dependency
graphs.
