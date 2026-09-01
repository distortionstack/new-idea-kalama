# Deterministic Automatic Remediation Discovery — Feasibility Experiment

Experiment date: 2026-09-01 (Asia/Bangkok)

Scope: three real findings from the two vulnerable images already present locally. No
production remediation code was changed. All runtime mutations used names prefixed
`remediation-exp-` and preserved the vulnerable images.

## Executive result

| CVE | FixType | Auto classify | Auto target version | Auto candidate | Patch executed | Trivy After | Re-exploit | Human knowledge needed |
| --- | ------- | ------------- | ------------------- | -------------- | -------------- | ----------- | ---------- | ---------------------- |
| CVE-2017-5638 | A — source/dependency build | Yes, with local `pom.xml` | Yes: 2.3.32 (same branch) | Yes, from scanner + local Maven metadata | Yes, isolated Docker/Maven rebuild; existing Patch Executor does **not** support REBUILD | NOT_FOUND | Patched / marker absent | Confirmation of branch choice and permission to execute |
| CVE-2017-9805 | B — prebuilt image replacement | Yes for the deployed artifact shape; provider routing remains conditional | Yes: 2.5.13 (same branch) | No | No | Not run | Baseline check was inconclusive/negative | A real replacement-image mapping or upstream image catalog |
| CVE-2019-5481 | C — OS package upgrade | Yes | Yes: 7.52.1-5+deb9u10 | Partial: syntactically complete, not installable from configured repositories | Attempted; failed before mutation | Not run | No safe exploit oracle configured | EOL repository/archive policy and package provenance |

```text
FIXTYPE_A_FEASIBILITY: PASS
FIXTYPE_B_FEASIBILITY: FAIL
FIXTYPE_C_FEASIBILITY: PARTIAL

DETERMINISTIC_REMEDIATION_DISCOVERY: PARTIALLY_VIABLE

SHOULD_IMPLEMENT_PRODUCTION_NOW: YES_WITH_REDUCED_SCOPE
```

The experimentally justified production scope is an `OsPackageProvider` that emits
an executable candidate only after package-manager availability is proven. A
`SourceBuildProvider` may safely emit a proposed candidate/build recipe when a local
manifest provides all required coordinates, but the current executor cannot run it.
`PrebuiltImageProvider` is not justified as a general automatic provider yet; it
needs a machine-readable image-family/replacement catalog.

## Environment inventory

Initial read-only inspection found:

- `vulhub/struts2:2.3.30`, digest
  `sha256:b992e080d8e5ad332bf526ae26124d28f56ca4fc9e0eaa91510dbee9870eb2c8`.
- `vulhub/struts2:2.5.12-rest-showcase`, digest
  `sha256:d2a78993bd613d18f678dc6cadef53c07cf1a4ee3330e38d222d5da76a431099`.
- `msf-resolver-host` and `kalama-workbench-modern`, both stopped but reusable.
- `kalama-net` already present.
- Trivy 0.74.0 in `kalama-workbench-modern`, vulnerability DB updated
  2026-08-31T19:02:31Z and Java DB updated 2026-08-31T01:07:49Z.
- Copacetic was not installed on the host and was not installed for this experiment.

No prune or delete operation was performed. The experiment did pull the base image
declared by the local Dockerfile (`maven:3-jdk-8`) while executing the source build.

## Why the cases belong to their FixTypes

### A — CVE-2017-5638

Trivy classified the vulnerable occurrence as `Class=lang-pkgs`, `Type=jar`, package
`org.apache.struts:struts2-core`, installed `2.3.30`, fixed
`2.3.32, 2.5.10.1`, with Maven PURL
`pkg:maven/org.apache.struts/struts2-core@2.3.30`. The local image contains
`/usr/src/pom.xml`; the local Vulhub build context contains the Maven manifest,
Dockerfile, source tree, and a `struts2.version` property. This is a dependency/source
rebuild, not an OS package operation or a prebuilt-image substitution.

Classification: `DETERMINISTICALLY_DERIVABLE` when scanner evidence is joined to
local source metadata. Scanner evidence alone identifies a language dependency but
does not prove that rebuild inputs are available.

### B — CVE-2017-9805

The deployment is explicitly a prebuilt image in Vulhub compose:
`vulhub/struts2:2.5.12-rest-showcase`. The image contains the deployed Tomcat artifact
but exposes no source/build manifest, and the local Docker image set contains no
fixed REST-showcase image. Trivy reports Maven package
`org.apache.struts:struts2-rest-plugin` 2.5.12 fixed in 2.5.13 (same branch) or
2.3.34. A prebuilt replacement is therefore the only non-invasive candidate shape
supported by the available deployment evidence, but the replacement identity is
not derivable from Trivy.

Classification: the absence of build metadata plus an explicit prebuilt deployment
can deterministically route to `PREBUILT_IMAGE` **candidate discovery**, but it cannot
assert that a usable replacement exists.

`FIXTYPE_B_DATASET_GAP`: the locally available Vulhub data has no fixed prebuilt
REST-showcase image. The mechanically constructed tag
`vulhub/struts2:2.5.13-rest-showcase` returned `no such manifest`. “Newer tag” was not
accepted as safe, and no speculative image was pulled.

### C — CVE-2019-5481

Trivy classified three Debian OS occurrences: `curl`, `libcurl3`, and
`libcurl3-gnutls`, all installed at `7.52.1-5+deb9u9` and fixed at
`7.52.1-5+deb9u10`. Runtime `/etc/os-release` reports Debian 9 Stretch, and
`dpkg-query` independently confirmed the three installed versions. This is a genuine
OS package upgrade.

Classification: `DETERMINISTICALLY_DERIVABLE` from Trivy `Class=os-pkgs`,
`Type=debian`, package records, plus runtime distro/package-manager facts.

## BEFORE and AFTER evidence

### Case A

BEFORE:

- Image/digest: `vulhub/struts2:2.3.30` / `sha256:b992...eb2c8`.
- Container: `remediation-exp-a-before`, attached only to `kalama-net`.
- Trivy: FOUND; `org.apache.struts:struts2-core` 2.3.30; fixed
  `2.3.32, 2.5.10.1`.
- Runtime source facts: `/usr/src/pom.xml` and cached
  `struts2-core-2.3.30.jar`.
- Existing validated exploit intent:
  `exploit/multi/http/struts2_content_type_ognl`, port 8080, URI `/`, harmless
  `cmd/unix/generic` marker command `touch /tmp/success`.
- Fresh oracle: Metasploit check reported “target is vulnerable; successfully
  executed the injected code”; `/tmp/success` was present.

Candidate and application:

- Same-branch target 2.3.32 selected from Trivy's ordered fixed-version field.
- Local source metadata supplied Maven property `struts2.version`, source tree,
  build system and Dockerfile.
- Command/tool: Docker build of the local isolated `s2-045-patch` context with
  `STRUTS2_VERSION=2.3.32`.
- Patched image: `remediation-exp-a-patched:2.3.32`, image/digest
  `sha256:62f1bd394f4f0d5211d2801c459782cb4d569a39f98b167f5f4c16441497a4e4`.
- After container: `remediation-exp-a-after` on `kalama-net`.

AFTER:

- The patched `pom.xml` contains `struts2.version=2.3.32`.
- HTTP `/` remained reachable.
- Fresh Trivy scan produced no CVE-2017-5638 record (`NOT_FOUND`).
- The same Metasploit module/port/URI check reported “target appears to be patched”.
- The same marker oracle remained absent.

Result: strong PASS. Note that Kalama's current production Patch Executor reports
REBUILD as unsupported, so execution used Docker/Maven directly for the experiment.

### Case B

BEFORE:

- Image/digest: `vulhub/struts2:2.5.12-rest-showcase` /
  `sha256:d2a78993bd613d18f678dc6cadef53c07cf1a4ee3330e38d222d5da76a431099`.
- Container: `remediation-exp-b-before` on `kalama-net`.
- Trivy: FOUND; `org.apache.struts:struts2-rest-plugin` 2.5.12; fixed
  `2.3.34, 2.5.13`.
- The existing resolver configuration is explicitly `needs_review`: deployment and
  wait time are unresolved. A fresh module check against the selected URI returned
  “not vulnerable”, so empirical vulnerability was **not** claimed.

Candidate discovery:

- Local images: no candidate.
- Deterministic repository/tag construction: attempted exact same-family
  `2.5.13-rest-showcase`; registry returned no manifest.
- Registry tag enumeration was not available through the Docker CLI, and no local
  machine-readable mapping relates Struts fixed versions to Vulhub image tags.
- No candidate was accepted, so there was no patch, after scan, or re-exploit.

Result: FAIL for general deterministic prebuilt discovery; the missing information
is `KNOWLEDGE_RETRIEVAL_REQUIRED`, not inherently `HUMAN_ONLY`.

### Case C

BEFORE:

- Same source image/digest as Case A.
- Workspace: `remediation-exp-c-workspace`, isolated from `kalama-net`.
- Distro/package manager: Debian 9 Stretch / APT+dpkg.
- Installed: `curl`, `libcurl3`, `libcurl3-gnutls` at `7.52.1-5+deb9u9`.
- Trivy fixed version: `7.52.1-5+deb9u10`.

Candidate and execution:

- A candidate command is fully constructible:
  `apt-get update && apt-get install -y -- curl=7.52.1-5+deb9u10`.
- This matches the existing `DockerPatchBackend` package-manager behavior.
- Execution failed safely before mutation: all configured Stretch repositories
  returned HTTP 404 because the distro is EOL.
- Trivy also explicitly warned that Debian 9 is unsupported and detection may be
  insufficient.
- The candidate version was scanner-derived, but package availability/provenance was
  not established. Rewriting sources to an archive would introduce a repository
  policy and upstream knowledge absent from the scanner record, so it was not hidden
  inside the experiment.

Result: PARTIAL. Classification and command construction work; executable candidate
validation needs a package-manager metadata probe and an explicit EOL policy.

## Knowledge-source accounting

| Fact | Origin |
| --- | --- |
| A package/current/fixed branches/PURL | SCANNER_EVIDENCE |
| A Maven project, property and build system | LOCAL_SOURCE_METADATA |
| A base image and build command | LOCAL_SOURCE_METADATA |
| A chosen same-branch target 2.3.32 | SCANNER_EVIDENCE plus HUMAN confirmation of branch policy |
| A built image ID and runtime config | LOCAL_IMAGE_METADATA |
| B current prebuilt reference and product-shaped tag | LOCAL_SOURCE_METADATA plus LOCAL_IMAGE_METADATA |
| B fixed product version 2.5.13 | SCANNER_EVIDENCE |
| B exact candidate tag attempt | OTHER (deterministic naming heuristic; rejected after registry validation) |
| B tag absence | CONTAINER_REGISTRY_METADATA |
| C distro/ecosystem/current packages/fixed version | SCANNER_EVIDENCE plus runtime LOCAL_IMAGE_METADATA |
| C package-manager command | LOCAL_IMAGE_METADATA plus deterministic executor mapping |
| C repository 404 / candidate unavailable | PACKAGE_MANAGER_METADATA |
| Stretch archive/repository policy | KNOWLEDGE_RETRIEVAL_REQUIRED; not supplied |

No remediation fact above is attributed to LLM knowledge.

## Automation questions

### CVE-2017-5638

1. FixType automatically determined? **Yes**, after joining jar/PURL evidence to a
   local Maven manifest.
2. Fixed version automatically determined? **Yes**, though branch policy requires
   confirmation; 2.3.32 is the same-branch candidate.
3. Remediation source automatically determined? **Yes**, local Maven build metadata.
4. Concrete PatchCandidate automatic? **Yes**.
5. Existing Patch Executor? **No**; REBUILD is explicitly unsupported.
6. Trivy After? **NOT_FOUND**.
7. Re-exploit? **Confirmed patched**, marker absent.
8. Human input? Branch policy and final execution confirmation.

### CVE-2017-9805

1. FixType automatically determined? **Partially**: routing to a prebuilt provider is
   derivable, but a candidate cannot be asserted.
2. Fixed version automatically determined? **Yes**, 2.5.13 same branch.
3. Remediation source automatically determined? **No**.
4. Concrete PatchCandidate automatic? **No**.
5. Existing Patch Executor? It supports a **known local** prebuilt image, but none was
   discovered.
6. Trivy After? **Not run**.
7. Re-exploit? **Not run**; baseline exploit validation was inconclusive/negative.
8. Human input? Replacement mapping today; preferably replace this with an upstream
   machine-readable catalog.

### CVE-2019-5481

1. FixType automatically determined? **Yes**.
2. Fixed version automatically determined? **Yes**.
3. Remediation source automatically determined? **Partial**: package manager known,
   repository availability not known until probed.
4. Concrete PatchCandidate automatic? **Partial**; command candidate yes, installable
   artifact no.
5. Existing Patch Executor? **Yes**, and its conceptual command was tested.
6. Trivy After? **Not run**, because mutation did not occur.
7. Re-exploit? **Unavailable**; no safe existing exploit configuration.
8. Human input? EOL/archive repository policy and confirmation.

## Candidate model assessment

The proposed model is directionally correct but insufficient for deterministic
validation. A minimum experimental form is:

```json
{
  "cve_id": "CVE-2017-5638",
  "fix_type": "A",
  "strategy": "REBUILD",
  "current": {"package_or_product": "org.apache.struts:struts2-core", "version": "2.3.30"},
  "candidate": {
    "version": "2.3.32",
    "image": "remediation-exp-a-patched:2.3.32",
    "package": null
  },
  "evidence": [],
  "discovery_status": "DISCOVERED",
  "validation": {
    "source_available": true,
    "candidate_available": true,
    "scanner_status": "NOT_FOUND",
    "runtime_status": "REACHABLE",
    "exploit_status": "PATCHED"
  },
  "branch_policy": "SAME_BRANCH_MINIMUM_FIXED",
  "human_confirmation_required": true
}
```

The production candidate must also carry immutable source identity/digest,
ecosystem, exact occurrence/PURL, provider, provenance category, candidate validation
status, availability evidence, EOL status, branch policy, and execution support.
Without those fields, B and C can look falsely executable.

## Architecture conclusion

The proposed architecture is viable only with conservative provider contracts:

```text
Trivy + TargetFacts
  -> deterministic classifier
  -> provider discovery
  -> candidate availability/provenance validation
  -> PatchCandidate[]
  -> human confirmation
  -> supported executor
  -> Trivy After + reachability + same exploit intent
```

Provider output must distinguish `PROPOSED` from `EXECUTABLE`. `FixedVersion` is not
an executable candidate: C proves that the package artifact may be unavailable, and
B proves that a product version does not identify an image.

### WHAT_DETERMINISTIC_DISCOVERY_CAN_SOLVE

- Classify OS packages reliably from Trivy class/type and runtime distro facts.
- Construct package-manager commands after exact package/version availability is
  verified.
- Identify language dependency coordinates, current/fixed versions, and local build
  systems from PURLs plus manifests.
- Produce source-build proposals when every manifest/build input is present.
- Validate all image candidates with immutable digest + Trivy before presentation.

### WHAT_REQUIRES_EXTERNAL_KNOWLEDGE

- Prebuilt image-family and product-version-to-tag mappings.
- Registry tag catalogs and provenance/trust rules.
- EOL distribution archive locations, signing state, and organizational repository
  policy.
- Compatibility/branch semantics where scanner fixed-version lists are ambiguous.

These are primarily `MACHINE_RETRIEVABLE` or `KNOWLEDGE_RETRIEVAL_REQUIRED`; this
experiment does not justify an LLM as the default resolver.

### WHAT_STILL_REQUIRES_HUMAN_CONFIRMATION

- Accepting branch/major-version and compatibility risk.
- Accepting an EOL/archive repository policy.
- Trusting an upstream/third-party prebuilt image source.
- Authorizing execution and reviewing application-specific health checks.

## Production decision

Implement **YES_WITH_REDUCED_SCOPE**:

1. Implement a deterministic `OsPackageProvider` with a mandatory dry-run or
   package-manager availability check, explicit EOL refusal, and immutable evidence.
2. Optionally implement a non-executing `SourceBuildProvider` that emits `PROPOSED`
   candidates only when a recognized local manifest, exact dependency occurrence,
   fixed version, and build context are all present.
3. Do not implement general automatic prebuilt-image discovery until a trusted,
   machine-readable replacement mapping is available.
4. Keep human confirmation mandatory and retain Trivy After, application reachability,
   and same-intent re-exploit as separate oracles.

