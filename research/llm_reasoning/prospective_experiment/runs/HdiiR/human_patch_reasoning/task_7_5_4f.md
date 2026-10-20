# Task 7.5.4F — human-like agent patch reasoning

Run: `HdiiR`  
Scope: proposal and production-form validation only  
Execution: **not started**

## 1. Chosen remediation approach

Use `FixType B` with production-supported `HUMAN_COMMAND` actions in Kalama's
isolated `patch-workspace`. Download the official Apache Struts release library
archives, verify their SHA-256 values, expand each source WAR into a Tomcat
exploded webapp if necessary, replace the complete installed Struts module set
and the release's essential dependency closure, then remove the corresponding
unpatched WAR so it cannot overwrite the patched directory on Tomcat startup.

No replacement image was selected: neither frozen evidence nor current Kalama
artifacts identify an authoritative image that preserves this multi-webapp
target. `ARTIFACT_REPLACEMENT` was also rejected because the production Docker
backend has no executor for it. `HUMAN_COMMAND` is the implemented backend path
for this JAR/WAR layout.

## 2. Why this approach

- **EXTRACTED:** the target has no source mount and no Maven/Gradle executable.
- **EXTRACTED:** the image contains WAR and runtime-expanded copies; scanner
  paths show each vulnerable JAR twice where both representations exist.
- **EXTRACTED:** frozen OS inventory includes `curl`, `unzip`, `sha256sum`
  (coreutils), and Java 8, but no JDK `jar`, Maven, Gradle, or `zip` utility.
- **COMBINED_EVIDENCE:** a source rebuild and generic image replacement are not
  supported by the observed environment, while an official binary release can
  be applied in the existing patch-workspace using installed tools.
- **OPERATOR_DECISION:** materialize patched exploded applications and remove
  only their duplicate WARs after successful replacement. Tomcat documents both
  exploded directories and WARs as deployable artifacts in `appBase`; avoiding
  coexistence prevents a newer WAR from recreating an old exploded directory.

## 3. Interpretation of the eight actions

The actions are scanner-level package/version groups, not eight unrelated
containers and not one action per physical JAR. A WAR and its exploded runtime
copy are duplicate representations of one deployment.

| Action | Logical occurrence group | Physical apps | Treatment |
|---|---|---|---|
| patch-001 | core 2.3.1 | S2-009 | 2.3.32 release closure |
| patch-002 | core 2.3.14.2 | S2-015, S2-016 | shared 2.3.32 procedure |
| patch-003 | core 2.3.15.1 | S2-019 | 2.3.32 release closure |
| patch-004 | core 2.3.20.1 | S2-032, S2-033, S2-037, S2-045, S2-052 | shared 2.3.34 procedure |
| patch-005 | core 2.3.24.1 | S2-029 | 2.3.32 release closure |
| patch-006 | core 2.3.30 | S2-046 | 2.3.32 release closure |
| patch-007 | core 2.5.10 | S2-053 | 2.5.10.1 release closure |
| patch-008 | REST plugin 2.3.20.1 | S2-033, S2-037, S2-045, S2-052 | explicit assertion of the REST replacement performed coherently by patch-004 |

Patch-004 and patch-008 overlap physically but remain distinct evidence/actions.
Patch-004 performs one release-coherent upgrade of all installed Struts modules
in its five apps. Patch-008 is not skipped: it fails unless all four REST apps
contain `struts2-rest-plugin-2.3.34.jar`, matching core/xwork 2.3.34 and XStream
1.4.10, with no REST 2.3.20.1 JAR remaining.

## 4. Target versions

- **2.3.32** for 2.3.x deployments affected only by CVE-2017-5638. This is the
  minimal same-branch release named by S2-045 and the scanner, minimizing
  compatibility change.
- **2.3.34** for the 2.3.20.1 group that also contains the vulnerable REST
  plugin. S2-052 names 2.3.34 as the fixed 2.3 release; using 2.3.32 for core
  beside REST 2.3.34 would create an unsupported mixed Struts release.
- **2.5.10.1** for S2-053, the minimal same-branch S2-045 fix. The app has no
  REST plugin occurrence, so advancing it to 2.5.13 adds compatibility delta
  without evidence of need for the two scoped CVEs.

All three releases are now EOL. They are selected for this bounded prospective
experiment and these two confirmed CVEs, not asserted as a generally supported
2026 production baseline. A long-lived production system needs a separately
planned source migration to a currently supported Struts line.

## 5. Artifacts and dependency changes

### Directly required artifacts

- `struts2-core` at the target version for every listed app.
- `struts2-rest-plugin` 2.3.34 for S2-033, S2-037, S2-045, S2-052.

### Related release artifacts

Every already-installed `struts2-*.jar` is replaced with the artifact of the
same name and selected release. This prevents binary mixing such as core 2.3.34
with convention/config-browser 2.3.20.1. For 2.3.x, `xwork-core` is also aligned
to the selected Struts release; 2.5.10.1 has XWork merged into core and any
standalone `xwork-core` is rejected.

### Essential closure taken from the official min-lib composition

- 2.3.32: commons-fileupload 1.3.2, commons-io 2.2, commons-lang3 3.2,
  commons-logging 1.1.3, FreeMarker 2.3.22, Javassist 3.11.0.GA, OGNL 3.0.19,
  xwork-core 2.3.32.
- 2.3.34: the same base versions except OGNL 3.0.21 and xwork-core 2.3.34.
- 2.5.10.1: commons-fileupload 1.3.2, commons-io 2.4, commons-lang3 3.4,
  FreeMarker 2.3.23, Javassist 3.20.0-GA, Log4j API 2.7, OGNL 3.1.12.
- REST 2.3.34: XStream changes from runtime 1.4.2 to the parent-POM managed
  1.4.10. Existing json-lib 2.3 and Jackson 1.9.2 already match the REST POM and
  are retained.

Optional/application-specific dependencies not in the essential closure are
retained. Versions were not invented: release parent POMs and archive contents
supplied every changed version.

## 6. Authoritative sources and added evidence

The frozen checkpoint remains the starting point (`E001`–`E007`). Clarifying
evidence was acquired only from approved authoritative source classes:

| Source | What was read | Why |
|---|---|---|
| <https://struts.apache.org/docs/s2-045.html> | affected/fixed Struts lines | choose the smallest compatible S2-045 target |
| <https://struts.apache.org/docs/s2-052.html> | 2.3.34/2.5.13 fix and REST/XStream restrictions | select the REST target and identify compatibility risk |
| <https://struts.apache.org/releases> | official release history | confirm releases are Apache releases |
| <https://struts.apache.org/eol-versions.html> | 2.3.x and 2.5.x EOL status | bound the claim and record residual risk |
| Maven Central parent/core/REST POMs for 2.3.32, 2.3.34, 2.5.10.1 | managed/direct dependencies | establish release-aligned closure |
| Apache Archive 2.3.32, 2.3.34, 2.5.10.1 directories and `*-lib.zip` files | artifact availability and contents | establish exact artifact provenance |
| <https://tomcat.apache.org/tomcat-8.0-doc/deployer-howto.html> and <https://tomcat.apache.org/tomcat-8.5-doc/config/automatic-deployment.html> | WAR/exploded-directory startup behavior | justify the packaging transformation |

Publisher SHA-1 values were checked and matched. SHA-256 was computed over the
same bytes fetched in memory and is what the proposed commands enforce:

| Archive | Apache SHA-1 | Observed SHA-256 |
|---|---|---|
| struts-2.3.32-lib.zip | dc90cce9dbd0c239684b2dfdbd0167b9d5297c24 | 72301c03b11d460130b05632e382d03d7e9b8f52a42d23c70452c7d49dc29bdb |
| struts-2.3.34-lib.zip | 6e0b4f296c254126489a1f1a735a21c17342eab2 | 652d434215322a202b018129af6f70c7b17a34e7156b3653ddc0f8cee8eb0343 |
| struts-2.5.10.1-lib.zip | 97ab9111570b923ef06e94c5bb9258aea302893c | d7b42083b7aa3cb14af5639aa4019a63085ae0b688745bf540162e39e7748bbe |

A read-only attempt to re-inspect `victim-HdiiR` was made but Docker Desktop's
Linux engine pipe was unavailable. No current runtime fact was inferred from
that failed attempt; frozen scan/runtime evidence remains authoritative here.

## 7. Patch procedure

The complete commands are in `proposed_patch_form_HdiiR_r1.yaml`. Operationally:

1. patch-001 creates a bounded helper in `/tmp/kalama-HdiiR` and downloads the
   first archive over HTTPS.
2. Each archive is SHA-256 verified before any application modification.
3. For each explicitly mapped app, use an existing exploded directory or expand
   its WAR; fail if neither representation exists.
4. Install the target release's same-named Struts modules first, then delete
   superseded versions. Overlay the exact essential closure and REST dependency.
5. Assert the target core exists, then delete only that app's old WAR and its
   named Tomcat work cache. The original source image remains preserved by the
   production backend.
6. patch-008 asserts the overlapping REST work rather than repeating it.

All actions are scoped to `/usr/local/tomcat/webapps/<known-app>` inside the
Kalama-owned patch workspace. The command does not modify `victim-HdiiR`.

## 8. Validation procedure

One canonical validation command is attached to patch-001; the execution
orchestrator runs the first available validation command after all actions:

1. Verify each mapped app is an exploded directory and its old WAR is absent.
2. Verify all installed Struts modules have the selected release version.
3. Hash-compare every selected Struts module and essential-closure JAR against
   the already verified official archive.
4. Verify the four REST apps have REST 2.3.34 and XStream 1.4.10.
5. Search all webapps for every scoped vulnerable core/REST filename and fail if
   one remains.
6. Start Tomcat transiently inside the patch workspace; require HTTP success at
   the two exploit-confirmed routes `/S2-045/` and `/S2-052/orders/3`; reject
   class/linkage errors in startup output; stop Tomcat and remove staging files.

This is pre-AFTER mechanical/smoke validation. It does not replace the later
Trivy AFTER scan or re-exploit oracle, and neither was run in this task.

## 9. Decision log

| Decision/question | Evidence consulted | Conclusion | Classification | Confidence | Unresolved assumptions |
|---|---|---|---|---|---|
| What is deployed? | E001, E006, E007 | 12 relevant apps; WAR/exploded duplicates; seven core versions and one REST group | EXTRACTED | high | live Docker recheck unavailable |
| Are eight actions independent? | Patch Form + scanner `PkgPath`/duplicate counts | seven version groups; REST overlaps four apps in core 2.3.20.1 group | COMBINED_EVIDENCE | high | none material |
| Which strategy is executable? | Docker backend, runtime tools, no source/build workspace | FixType B + HUMAN_COMMAND in patch-workspace | OPERATOR_DECISION | high | outbound HTTPS at execution |
| Why not replacement image? | `unknown.replacement_image`, discovery/backend constraints | no trustworthy one-to-one image mapping | COMBINED_EVIDENCE | high | none |
| Target for non-REST 2.3.x? | S2-045 + scanner + compatibility | 2.3.32 | OPERATOR_DECISION | high | app-specific regression still possible |
| Target for 2.3.20.1/REST group? | S2-045, S2-052, POM alignment | 2.3.34 for the entire group | OPERATOR_DECISION | high | REST allow-list may require app config |
| Target for 2.5.10? | S2-045 + absent REST occurrence | 2.5.10.1 | OPERATOR_DECISION | high | app-specific regression still possible |
| What dependencies change? | parent/core/REST POMs, official archive contents, frozen runtime inventory | align installed Struts modules plus exact min-lib closure; XStream 1.4.10 for REST | COMBINED_EVIDENCE | high | optional dependencies retained |
| How to handle WAR without `zip`/JDK? | OS inventory + Tomcat deployment docs | expand to directory, patch it, remove WAR after success | OPERATOR_INFERENCE | medium-high | embedded context behavior is tested by smoke command |
| Is the proposal production-form valid? | canonical plan hash + production confirmation/codec validators | all eight actions READY_FOR_PATCH_EXECUTION | EXTRACTED | high | command execution not tested by this validation |

## 10. Remaining uncertainty

- **UNKNOWN:** whether patch-workspace will have outbound HTTPS and a currently
  trusted CA path when execution begins. Download/checksum failure is fail-closed
  and occurs before app mutation for that action.
- **UNKNOWN:** whether the S2-052 demo's domain classes need explicit
  `org.apache.struts2.rest.handler.allowedClasses` configuration under the
  S2-052 restrictions. The route smoke check is intended to expose this before
  image commit; no class name is invented in the proposal.
- **UNKNOWN:** application-level behavior beyond the two exploit-confirmed
  routes. There is no source test suite.
- **UNKNOWN:** live victim drift after the frozen checkpoint, because the Docker
  engine was unavailable for a read-only refresh. Identity revalidation remains
  a required execution precondition in Kalama.
- **KNOWN RESIDUAL RISK:** 2.3.x/2.5.x are EOL and may retain vulnerabilities
  outside the two scoped CVEs.

## 11. Production Patch Form validation

The proposal SHA-256 is
`27729857cb7ed4e28402092d67e78e320e1c541d9d5f5d8758eda3cf43dfb702`.
The actual base Patch Plan SHA-256 matched
`9988f974cd7bd6729b91a382b00fde0df83d1c8be3f1f61e0b68dab938acf7c0`.

The repository's production `apply_patch_confirmations` and
`validate_patch_plan` functions accepted the proposal. Overall readiness and
all eight action statuses are `READY_FOR_PATCH_EXECUTION`; all prior input
reasons resolve. Validation was pure/non-mutating. `submit-patch-form` was not
called.

## 12. Kalama-supplied facts versus operator reasoning

Kalama supplied run/container identity, scanner occurrences and fixed-version
candidates, the eight action boundaries, exploit-confirmed CVEs/routes, runtime
package/JAR paths, and the Patch Form/base-plan integrity boundary.

The operator supplied the shared-deployment interpretation, rejection of the
replacement-image suggestion, branch-preserving target selection, release-wide
module/dependency alignment, official archive provenance and SHA-256 values,
the WAR-to-exploded deployment method, exact action commands, cross-action REST
assertion, and pre-AFTER validation procedure.

TASK_7_5_4F_STATUS: PROPOSAL_READY_FOR_REVIEW
