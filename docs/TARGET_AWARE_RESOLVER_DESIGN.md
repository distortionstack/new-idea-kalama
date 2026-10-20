# VIPER Target-Aware Resolver Design

Status: Conceptual design and feasibility baseline

Scope: Research-only design for target-aware CVE-to-application-to-module correlation. This document does not authorize implementation, security checks, exploitation, remediation, or changes to canonical run artifacts.

## 1. Problem statement

The existing Resolver primarily resolves a scanner CVE to a compatible Metasploit candidate and projects module defaults into an Attack Form. That is insufficient when one image contains multiple applications, dependency versions, deployment contexts, or vulnerable and fixed copies of the same component.

The image used by run `jul1d` demonstrates the problem. Trivy identified CVE-2017-5638 in multiple `struts2-core` versions across separate WARs and exploded deployments. The image also contained an `S2-045` application with fixed Struts 2.3.32. A generic Metasploit default of `/struts2-showcase/` did not identify the actual service: a benign request returned 404, while `/S2-046/` returned the file-upload application associated with vulnerable Struts 2.3.30.

The core failure mode is confusing:

- a documented module default with target evidence;
- a vulnerable package occurrence with a currently served application;
- a configuration match with vulnerability verification; and
- a proposed execution configuration with authorization to execute it.

## 2. Target-aware correlation workflow

The conceptual flow is:

```text
CVE occurrence
  -> exact package/JAR/WAR and image layer
  -> deployed application and context path
  -> current runtime service and reachability
  -> documented vulnerability prerequisites
  -> compatible Metasploit module and target profile
  -> field-level evidence adjudication
  -> minimal proposed Attack Form
  -> explicit human approval
  -> separately authorized check or execution
```

### 2.1 CVE occurrence and artifact identity

Start from scanner occurrences, retaining:

- canonical CVE;
- package name and ecosystem;
- installed and fixed versions;
- archive or filesystem path;
- image digest and scan artifact digest;
- whether the occurrence is inside a WAR, JAR, layer, or exploded deployment.

WAR contents and their exploded deployment copies must be deduplicated as representations of one application, while preserving both paths as provenance.

### 2.2 Application deployment identity

Map each occurrence to an application using:

- WAR filename and exploded directory;
- Tomcat deployment logs and context metadata;
- `web.xml` display name, filters, mappings, and welcome actions;
- Struts configuration and namespaces;
- application-specific descriptors and dependency layout.

A WAR name is an inference, not proof of a live context. Context identity becomes stronger when deployment logs and benign HTTP responses agree.

### 2.3 Runtime identity

Collect read-only facts for the immutable target:

- container ID, image ID, image digest, network, and IP;
- service ports and connection reachability from the authorized resolver container;
- current deployment status;
- benign status codes, headers, redirects, and application identity;
- relevant runtime configuration and dependency versions.

No crafted vulnerability request, upload, OGNL expression, payload, or remediation command belongs in this phase.

### 2.4 Prerequisite correlation

Extract documented prerequisites from authoritative sources and compare them with target facts. Examples include:

- affected component version range;
- required parser or feature;
- application endpoint or context;
- HTTP method;
- target platform or architecture;
- required module options;
- service reachability.

The result is a field-level decision record, not a single binary claim about the whole image.

## 3. Source selection and retrieval policy

### 3.1 Source hierarchy

Use the strongest source appropriate to each fact:

1. Direct read-only target/runtime observation.
2. Live Metasploit module metadata and installed module source.
3. Official vendor advisory or project documentation.
4. NVD/CVE and GitHub Advisory records.
5. Validated local Knowledge Store records.
6. Other repositories or research references, clearly marked as supporting rather than authoritative.

No source is authoritative for every field. Runtime evidence is strongest for identity, deployment, routing, and reachability. Vendor and project sources are strongest for vulnerability conditions and remediation boundaries. Metasploit source is strongest for module behavior, option semantics, and target profiles.

### 3.2 NVD and CVE records

Retrieve the canonical CVE record using the exact CVE identifier. Record:

- URL and title;
- retrieval timestamp;
- source modification timestamp when available;
- affected configurations;
- descriptions and references;
- snapshot digest.

NVD establishes documented affected ranges and references but does not prove that a particular target is running the affected component or serving an affected application.

### 3.3 GitHub Security Advisories

Use a GHSA record when it identifies the package ecosystem, affected versions, fixed versions, or upstream repository. Record the GHSA identifier, package coordinates, version ranges, references, and snapshot digest.

GHSA data is corroborating documentation. It must not override a verified target version or deployment fact.

### 3.4 Vendor and project advisories

Prefer the affected project's own security bulletin for:

- vulnerability mechanism;
- affected and fixed versions;
- configuration prerequisites;
- supported workarounds;
- documented upgrade guidance.

For Apache Struts S2-045, the project advisory states that the Jakarta Multipart parser condition affects Struts 2.3.5–2.3.31 and 2.5–2.5.10, with fixes in 2.3.32 and 2.5.10.1.

### 3.5 Metasploit documentation and source

Inspect both live metadata and module source. Record:

- module path and CVE references;
- target profiles and default target;
- option names, types, requiredness, and defaults;
- how the check method constructs requests;
- URI normalization and redirect/error handling;
- documented application assumptions;
- module source revision or digest.

Module defaults are documented proposals, not target observations.

### 3.6 Validated local knowledge and Evidence Cache

Use local knowledge only when its context matches:

- CVE;
- component and ecosystem;
- installed version;
- image family or target class;
- phase;
- source run and evidence references.

The Evidence Cache should preserve immutable raw and normalized snapshots, authority, resource identity, retrieval metadata, content digests, and policy version. Stale cache use must remain visible and must not be presented as fresh runtime evidence.

## 4. Evidence classification and conflict rules

Every resolved field should carry:

- value;
- classification;
- confidence or strength rationale;
- source references;
- snapshot digests;
- retrieval timestamp;
- conflicts;
- unresolved requirements.

### 4.1 Classifications

`VERIFIED`

Directly observed from the authorized target or a cryptographically bound runtime artifact. Examples: container IP, successful TCP connection, HTTP 200 response, installed JAR version.

`DOCUMENTED`

Supported by an authoritative vendor, CVE, or module source. Examples: affected version range, module default target, module option type.

`INFERRED`

Derived from a reasonable but indirect mapping. Examples: `/S2-046/` inferred from `S2-046.war` before current HTTP confirmation.

`CONFLICTING`

Two credible sources disagree or runtime evidence contradicts a proposed documentation default. Example: module default `/struts2-showcase/` versus current HTTP 404 and deployed contexts `/S2-009/`, `/S2-046/`, and others.

`UNKNOWN`

The available evidence does not establish the fact. Examples: whether the module's check will classify a target as vulnerable before the check is run.

### 4.2 Adjudication

- Runtime observations outrank generic defaults for target identity, service, routing, and reachability.
- Live module metadata outranks stale local module metadata.
- Official project documentation defines vulnerability prerequisites.
- Documentation cannot prove target presence or runtime behavior.
- A conflict remains unresolved until a stronger source or new authorized observation resolves it.
- Unknown values remain unknown; they are never promoted because a value is convenient or plausible.

## 5. Target-aware Attack Form prefilling

The Resolver should generate the smallest form that contains only meaningful decisions.

### 5.1 Automatically resolvable fields

These may be inherited when evidence is current and non-conflicting:

- image and container identity;
- `RHOSTS` from canonical target facts;
- target index/name from live module metadata;
- module path when the CVE association and candidate evidence agree;
- non-security-sensitive module defaults used by the selected check;
- check-only protocol fields when the workflow itself fixes them.

### 5.2 Fields requiring review

Keep human review for:

- conflicting or inferred application paths;
- unresolved service ports;
- ambiguous target profiles;
- payloads, listeners, callback addresses, or sessions;
- preconditions that could modify state;
- any exploit or remediation action;
- documentation/runtime conflicts.

### 5.3 Configuration versus verification versus authorization

These are separate states:

1. Configuration evidence: the module and fields appear structurally compatible.
2. Vulnerability verification: an authorized check produces a classified result.
3. Execution authorization: the user explicitly approves a security-sensitive operation.

A target-aware form can improve configuration evidence without claiming vulnerability verification or execution authorization.

## 6. `jul1d` / CVE-2017-5638 case study

### Verified target facts

- Image digest: `sha256:7175cfbfed390f55f464de0527aed565eedce2b2e4de02897c7f6bef4b949d9a`
- Container: `victim-jul1d`
- Network: `kalama-net`
- IP: `172.18.0.5`
- TCP reachability: `172.18.0.5:8080` reachable from `msf-resolver-host`
- Tomcat: 8.5.20
- Java: 8u141

### Application correlation

The image contains multiple Struts deployments. Trivy occurrences in WAR and exploded paths were deduplicated. The relevant live observations were:

- `S2-045`: Struts 2.3.32, REST example, benign 303/200 response; fixed version.
- `S2-009`: Struts 2.3.1, Showcase application, benign 302/200 response.
- `S2-046`: Struts 2.3.30, file-upload application, `jakarta-stream` parser, benign 200 response.
- `S2-053`: Struts 2.5.10, benign 200 response, no confirmed Jakarta Multipart configuration.

### Incorrect default

The module default `/struts2-showcase/` returned 404 and had no corresponding deployment. It is a generic module default, not a target fact.

### Supported candidate

`/S2-046/` is the strongest future check-only candidate because:

- the context is currently served;
- the dependency is within the documented affected range;
- the application defines upload actions;
- the Jakarta Multipart parser is explicitly configured;
- TCP reachability is verified;
- the module treats `TARGETURI` as a base context path.

The actual check result remains unknown because no check was executed.

## 7. Proposed implementation phases

### Phase 1: Evidence inventory

Dependencies: existing Docker, scanner, state, and evidence infrastructure.

Acceptance criteria:

- immutable target inventory artifact;
- WAR/JAR/exploded occurrence deduplication;
- deployment and context evidence;
- no target mutation.

### Phase 2: Source adapters and snapshots

Dependencies: existing Evidence Cache and policy layer.

Acceptance criteria:

- NVD, GHSA, vendor, Metasploit, and local knowledge snapshots;
- source authority and timestamp recorded;
- stale and unavailable states explicit;
- source content is data, never executable instructions.

### Phase 3: Deterministic correlation

Dependencies: Phase 1 and 2 evidence contracts.

Acceptance criteria:

- each CVE occurrence maps to zero or more application candidates;
- package versions and application contexts are explicit;
- prerequisite matches and conflicts are field-level;
- no generic module default overrides contradictory runtime evidence.

### Phase 4: Minimal form generation

Dependencies: deterministic correlation and classification.

Acceptance criteria:

- only unresolved meaningful decisions appear;
- unrelated module defaults are hidden or inherited with provenance;
- execution authorization remains explicit;
- proposed values are traceable to evidence references.

### Phase 5: Optional LLM interpretation

Dependencies: deterministic evidence pack and schema validator.

Acceptance criteria:

- LLM receives only unresolved, source-backed fields;
- every accepted proposal cites evidence;
- LLM cannot set authorization, payload execution, or remediation;
- unsupported or conflicting proposals remain unresolved.

### Phase 6: Evaluation

Acceptance criteria:

- manual-confirmation reduction is measured;
- unsupported-claim rate does not increase;
- negative tests prove stale, conflicting, fabricated, and target-mismatched values remain rejected.

## 8. Limitations and generalization risks

- WAR names do not universally equal context paths.
- Applications may be deployed behind reverse proxies or virtual hosts.
- Multiple applications may share a dependency but have different exploitability conditions.
- Package scanners may report both archive and exploded copies.
- Version presence does not prove vulnerable configuration or reachable code paths.
- HTTP 200 does not prove that a vulnerability-relevant endpoint is active.
- Module defaults and documentation may lag installed module behavior.
- Some modules require application-specific action names, parameters, or authentication.
- Runtime inspection differs across Tomcat, Jetty, Spring Boot, Node, Python, and native services.
- The evidence precedence policy must be adaptable by field and ecosystem, not hard-coded for Apache Struts.
- “Check-only” does not automatically mean side-effect-free; the module’s check implementation must be reviewed and explicitly authorized.

## 9. Final feasibility conclusion

The existing system already supports immutable run attribution, scanner evidence, Docker identity, basic runtime facts, Metasploit metadata, evidence provenance, and strict confirmation gates.

The `jul1d` study manually demonstrated that the missing correlation data is obtainable without executing a security check. It also demonstrated that the generic module default was wrong for the actual container and that `/S2-046/` is the strongest structurally supported candidate.

What remains to automate is the application-level join between scanner occurrence, archive, deployment, current context, runtime service, documented prerequisites, module behavior, and minimal form generation.

The feasibility result is:

```text
TARGET-AWARE PREFILLING: FEASIBLE
VULNERABILITY VERIFIED: NO — check not executed
EXECUTION AUTHORIZED: NO — separate approval remains required
IMPLEMENTATION STATUS: DESIGN ONLY
```
