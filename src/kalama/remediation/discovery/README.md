# Automatic Remediation Discovery v1

Deterministic remediation discovery for Kalama Patch Planning. This replaces the
previous `ManualRemediationProvider` dependency in the production Patch Planning
path with a discovery-backed provider that routes each remediation target through
deterministic providers and produces *suggested* candidates.

## What it supports

- **OS package (FixType C)** — classifies canonical Trivy `os-pkgs` findings into
  an executable candidate **only after** the exact fixed version is proven available
  through a non-mutating package-manager query in the target container
  (`apt-cache policy`, `apk policy`, `dnf/yum` repoquery). Debian/Ubuntu, Alpine,
  and RPM-family package managers are recognized.
- **Source build (FixType A, Maven only)** — when Trivy reports a Maven language
  package and a local `pom.xml`/build manifest is present, it produces a
  **proposal-only** REBUILD candidate (target version, coordinates, build system).
  It never executes a build.
- **Prebuilt image (FixType B)** — recognises the condition where a language
  dependency has a known fixed version but no local source/build manifest and no
  trusted replacement-image mapping exists. Result: `KNOWLEDGE_REQUIRED`, no image
  candidate.

## What it does NOT support

- Generic automatic prebuilt-image replacement (no `<repo>:<version>` guessing, no
  tag probing, no speculative pulls).
- Generic Gradle / npm / pip source rebuilds.
- Automatic EOL repository migration or archive repository use.
- Automatic major-version upgrades. Target versions are selected on the installed
  release branch only.
- Any LLM / RAG / vector / web-search based remediation.

## Why human confirmation remains mandatory

Every automatically derived candidate is marked `AUTO_DISCOVERED` / `SUGGESTED` and
`trusted=False`. Discovery pre-populates the Patch Plan / Patch Form suggestions but
never sets `HUMAN_CONFIRMED` or `VERIFIED`. Patch Form submission is the approval
boundary; execution readiness for an available OS package is
`HUMAN_CONFIRMATION_REQUIRED`. Empirical facts (`CVE_REMOVED`, `PATCH_SUCCESS`,
`VERIFIED`) are produced only by later stages (Trivy After, termination outcome,
re-exploit oracle).

## Why prebuilt-image discovery is KNOWLEDGE_REQUIRED

A scanner-reported fixed product version does not identify a replacement image. The
experiment (CVE-2017-9805) showed exact-tag guessing fails and no trusted
product-version → image mapping exists. Discovery therefore stops at
`KNOWLEDGE_REQUIRED` and waits for a Human-supplied trusted image through the
existing Patch Form / `PREBUILT_IMAGE_REPLACEMENT` backend.

## Why a package FixedVersion does not imply repository availability

Trivy `FixedVersion` is scanner evidence of a fixed version, not proof it can be
installed (CVE-2019-5481). The OS provider distinguishes `FIX_VERSION_KNOWN` from
`PACKAGE_AVAILABLE`; a candidate is executable only when the non-mutating probe
confirms the exact version is available in the configured repositories.

## Why SourceBuild is proposal-only

The feasibility experiment proved one Maven rebuild can succeed (CVE-2017-5638) but
not a universal safe source rebuild executor. The provider therefore emits a REBUILD
candidate with `execution_readiness=NOT_READY` and `human_confirmation_required=true`,
does not generate or run shell build commands, and does not modify `pom.xml`.
