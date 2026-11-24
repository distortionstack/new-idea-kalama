# Task 5 — Provider Capability Spikes

Status: **PASS** for capability-spike scope. Neither provider is integrated into production.

## Versions and execution boundary

- `github.com/git-pkgs/registries v0.14.0`, pinned by `tools/registry_resolver/go.mod` and `go.sum`.
- `id2url==0.1.2`, pinned in `requirements-id2url.txt` and loaded only by the isolated probe. It is not a production dependency.
- Live calls are made only by `task5_benchmark.py`. Offline tests consume `task5-fixtures/provider-results.json`.
- A source archive is recorded as an archive, never as a buildable source tree.

## Capability matrix

`Verified` means the provider returned an artifact after registry metadata lookup or its own existence check. `UNVERIFIED` means `registries/fetch` computed a predictable URL after exact-version metadata succeeded; the URL itself was not promoted to verified evidence.

| Ecosystem | Provider | Exact version | Artifact | Checksum | Source archive | Repository | Docs | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Maven | registries | Yes | URL computed | No | No | Yes | Yes | UNVERIFIED |
| Maven | id2url | Yes | sources JAR | No | Yes | No | No | FOUND |
| npm | registries | Yes | URL computed | No | No | Yes | Yes | UNVERIFIED |
| npm | id2url | Yes | tarball | No | No | No | No | FOUND |
| PyPI | registries | Yes | wheel + sdist metadata | Yes | Yes | Yes | No | FOUND |
| PyPI | id2url | Yes | sdist | No | No | No | No | FOUND |
| Cargo | registries | Yes | URL computed | No | No | Yes | Yes | UNVERIFIED |
| Cargo | id2url | Yes | crate | No | No | No | No | FOUND |
| Go | registries | Yes | URL computed | No | Yes, URL unverified | Yes | Yes | UNVERIFIED |
| Go | id2url | Yes | module zip | No | Yes | No | No | FOUND |
| NuGet | registries | Yes | URL computed | No | No | No | Yes | UNVERIFIED |
| NuGet | id2url | Yes | nupkg | No | No | No | No | FOUND |
| Composer | registries | Yes | dist archive metadata | No | Yes | Yes | Yes | FOUND |
| Composer | id2url | Yes | dist archive | No | Yes | No | No | FOUND |
| RubyGems | registries | Yes | gem metadata | Yes | No | Yes | Yes | FOUND |
| RubyGems | id2url | Yes | gem | No | No | No | No | FOUND |
| Hex | registries | Yes | URL computed | No | No | Yes | Yes | UNVERIFIED |
| Hex | id2url | Yes | tarball | No | No | No | No | FOUND |

## Positive and negative findings

- Both providers resolved an exact existing version in all nine requested ecosystems.
- `registries` produced metadata-backed artifact URLs for PyPI, Composer, and RubyGems. Predictable URLs for Maven, npm, Cargo, Go, NuGet, and Hex are explicitly marked `COMPUTED_UNVERIFIED`.
- Both providers returned `NOT_FOUND` for `lodash@9999.9999.9999`; neither negative result contains a usable artifact in the fixture.
- `id2url` returned a Maven `-sources.jar`, but it exposes no checksum, repository URL, or documentation URL.
- `id2url` resolved Composer `3.5.0`, but rejected `v3.5.0` as `NOT_FOUND`; callers must not silently strip the prefix because that changes provider input semantics.
- Unsupported and malformed inputs remain distinct (`UNSUPPORTED` versus `PROVIDER_ERROR`). Provider error text is retained in sanitized fixtures.

## MVP recommendation

Use `registries` as the candidate for Task 6 evaluation. PyPI, Composer, and RubyGems are the strongest initial ecosystems because their artifact URL came from registry metadata in this run. Maven, npm, Cargo, Go, NuGet, and Hex need an independent URL verification step before their computed URLs can become resource evidence.

Keep `id2url` experimental. Its exact-version existence checks are useful corroboration, but its result surface lacks checksums/repository/docs and its AGPL-3.0-or-later license needs legal review before any distribution or service integration.

## Known limitations

- This is a point-in-time public-registry benchmark, not availability or load testing.
- No returned archive was inspected for build scripts; `buildable_source_tree` remains `false`.
- The benchmark does not authenticate to private registries.
- `id2url.__version__` reports `0.1.0` inside the 0.1.2 wheel; the probe reports the pinned distribution version instead.
- Dependency/license approval remains Task 6 work. No production dependency or shared contract changed here.

## Reproduction

```bash
cd tools/registry_resolver
go test ./...
go build -o /tmp/viper-registry-resolver .

./.venv/bin/python -m pip download --no-deps --dest /tmp/viper-id2url id2url==0.1.2
./.venv/bin/python research/resource-discovery-benchmark/task5_benchmark.py \
  --go-resolver /tmp/viper-registry-resolver \
  --id2url-wheel /tmp/viper-id2url/id2url-0.1.2-py3-none-any.whl

./.venv/bin/python -m unittest -v \
  research/resource-discovery-benchmark/test_task5_fixtures.py
```
