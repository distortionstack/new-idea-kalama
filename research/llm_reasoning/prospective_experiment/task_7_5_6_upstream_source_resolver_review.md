# Task 7.5.6 Design Review - Upstream Source Resolver

## Scope

This is a design review only. No production code was implemented. No patch was
executed. No Task 7.5.5 result was revised. This review is grounded in the
observed Task 7.5.5 failure mode for run `UZBL5`: the evidence-anchored source
graph reached enough evidence for 5 of 8 Patch Actions, but abstained on 3 of 8
because the graph did not reach required third-party dependency artifacts:

- `ognl:ognl:3.0.21`
- `com.thoughtworks.xstream:xstream:1.4.10`
- `org.freemarker:freemarker:2.3.23`

The proposed Upstream Source Resolver addresses source discovery only. It must
not decide remediation strategy or patch content.

## 1. Does the design address the Task 7.5.5 gap?

Yes, with changes.

Task 7.5.5 showed that scanner references can be valid but too narrow. The
Struts advisory and Apache staging roots were anchored, but the bounded graph
could not lawfully jump to another package authority for transitive dependencies.
The agent knew, in the ordinary software-engineering sense, that Maven Central
or Sonatype-like registries might contain those artifacts, but using that model
knowledge directly would have violated the experiment's source policy.

An Upstream Source Resolver gives Kalama a principled place to derive package
authority from machine evidence instead of from the LLM. For Maven, a PURL such
as `pkg:maven/org.apache.struts/struts2-core@2.3.20` can deterministically imply
the Maven ecosystem and a native registry lookup path. If that derivation is
represented as provenance in the source graph, later evidence retrieval can
reach package metadata and artifacts without treating the LLM as a source
oracle.

The important change is that the resolver should not output loose "interesting
URLs." It should output typed authority candidates with confidence, policy class,
and allowed follow-up operations. For example, "PURL-derived Maven registry
metadata root" is different from "package homepage from mutable POM metadata."

## 2. Does it preserve Evidence-Anchored Source Discovery?

It preserves the principle if the boundary is defined as evidence-anchored
identity derivation, not only literal URLs copied from scanner references.

Adding deps.dev and native registries weakens the boundary only if they become
free-form search substitutes. They do not weaken it if:

- the package identity comes from scanner/runtime evidence, such as ecosystem,
  package name, version, PURL, or installed artifact coordinates;
- the registry endpoint is deterministic for that ecosystem;
- retrieved metadata is recorded as a source with parentage back to that package
  identity;
- links inside metadata are not automatically trusted as equivalent authority;
- every promoted URL has a source graph edge and a deterministic reason for
  promotion.

Under that model, deps.dev and native registries are not "the agent went to the
web." They are controlled resolvers operating on package coordinates already
inside the evidence seed.

## 3. What should count as an allowed source root?

Recommended source-root classes:

| Root class | Allowed? | Notes |
| --- | --- | --- |
| Scanner `References[]` | Yes | Directly anchored. Good for advisories, docs, upstream repos, and project pages. |
| Scanner `PrimaryURL` / `DataSource` | Yes | Strong root for scanner's vulnerability record and database provenance. Should be typed as scanner-vendor evidence, not upstream authority by default. |
| PURL-derived native registry root | Yes, with strict typing | Allowed because PURL is package identity evidence. It should authorize deterministic package/version metadata paths, artifact metadata, and checksums for that ecosystem. |
| deps.dev package/version record | Yes, as discovery/corroboration | Useful independent resolver, but not final authority. Links from deps.dev require corroboration or downgrade. |
| OSV/GHSA/NVD advisory references | Yes, as advisory roots | Advisory records can introduce references, but references must be classified by type and not blindly promoted. |
| Runtime-derived URLs such as `TOMCAT_TGZ_FALLBACK_URL` | Yes | Strong root when present in image/container evidence. Deterministic archive members can be child sources. |
| Registry metadata homepage/repository/bugs fields | Conditional | Allowed as child candidates, but confidence depends on corroboration and namespace alignment. |
| Arbitrary LLM-suggested domains | No | Must be rejected as unanchored. |

## 4. Should PURL-derived registry roots be allowed?

Yes, but only for deterministic native registry operations.

Argument for allowing them:

- PURL exists specifically to encode package ecosystem and coordinates.
- The native registry is part of the package identity, not a guessed website.
- Without this, evidence discovery becomes too dependent on scanner references,
  and Task 7.5.5 shows those references can omit dependency artifact roots.
- It lets Kalama retrieve package metadata, dependency metadata, artifacts, and
  checksums under auditable rules.

Argument against allowing them:

- It expands the source graph beyond literal scanner URLs.
- It can accidentally bless the wrong namespace if package identity was parsed
  incorrectly.
- Native registry metadata can contain attacker-controlled homepage/repository
  links.

Recommended compromise:

- Allow PURL-derived registry roots as `DERIVED_PACKAGE_AUTHORITY`.
- Restrict them to deterministic registry APIs and artifact paths for the exact
  package/version or dependency coordinates found in anchored metadata.
- Treat links from that metadata as candidates requiring corroboration, not as
  automatically trusted roots.

## 5. Poisoning and spoofing risks

Risks:

- Malicious package metadata can point `homepage`, `repository`, or `bugs` to an
  attacker-controlled site.
- Repository fields can point to a fork, mirror, abandoned repo, or lookalike
  organization.
- Abandoned package takeover can make current metadata disagree with historical
  package authority.
- Dependency confusion can cause the resolver to bind to a public package with
  the same name as a private/internal package.
- Redirect abuse can move an apparently valid URL to a different domain or
  authority class.
- Registry metadata, deps.dev, scanner references, and advisory records can
  disagree.
- deps.dev can provide derived links that are useful but not authoritative.
- Maven group/artifact namespace can be misleading when projects move or
  publish under umbrella groups.
- Mutable metadata can change after the scan, so resolver output must be
  timestamped and hashed.

Mitigations:

- Record every redirect hop and final URL.
- Keep original metadata bytes and content hashes.
- Compare package namespace, repository organization, advisory references, and
  registry metadata.
- Require at least one high-authority source before elevating a repository or
  homepage to canonical upstream.
- Downgrade metadata-only links when they are not corroborated.
- Treat cross-domain redirects as review triggers unless the target is an
  expected canonical domain.
- Preserve "retrieved but not trusted" records instead of silently dropping them.

## 6. Deterministic vs LLM-assisted responsibilities

Deterministic:

- Normalize ecosystem, package name, version, PURL, Maven group/artifact, and
  native package URLs.
- Query deps.dev and native registry metadata.
- Query OSV/GHSA/NVD by CVE/package where supported.
- Parse POMs and ecosystem metadata with structured parsers.
- Normalize URLs, follow and record redirects, classify domains, and build the
  source graph.
- Retrieve checksums, signatures, artifact metadata, and immutable byte hashes.
- Enforce source policy and reject unanchored sources.
- Assign confidence using deterministic rules.

LLM-assisted:

- Interpret advisory and release-note meaning.
- Reason about upgrade choices and dependency closure tradeoffs.
- Draft environment-specific patch procedures using only retrieved evidence.
- Explain abstentions and unresolved evidence gaps.
- Propose human-review notes for risky compatibility or major-version moves.

The LLM must not create new roots, invent domains, or promote source authority.

## 7. Minimal UpstreamIdentity schema

Recommended minimal schema:

```json
{
  "schema": "kalama.upstream-identity/v1",
  "package_identity": {
    "ecosystem": "maven",
    "name": "org.apache.struts:struts2-core",
    "version": "2.3.20",
    "purl": "pkg:maven/org.apache.struts/struts2-core@2.3.20",
    "normalized_name": "org.apache.struts:struts2-core"
  },
  "roots": [
    {
      "root_id": "USR-001",
      "kind": "native_registry",
      "url": "https://repo1.maven.org/maven2/org/apache/struts/struts2-core/2.3.20/",
      "authority_class": "DERIVED_PACKAGE_AUTHORITY",
      "derivation": "PURL_DERIVED_MAVEN_PATH",
      "parent_evidence": "PATCH_REASONING_SEED:TRIVY_BEFORE#...",
      "confidence": "HIGH",
      "allowed_operations": ["metadata", "pom", "artifact", "checksum"],
      "content_hash": null
    }
  ],
  "candidates": [
    {
      "kind": "source_repository",
      "url": "https://github.com/apache/struts",
      "source": "native_registry_scm",
      "corroborated_by": ["scanner_reference", "deps_dev"],
      "confidence": "HIGH",
      "status": "PROMOTED"
    }
  ],
  "advisory_roots": [],
  "confidence": "HIGH",
  "provenance": {
    "created_from": ["scanner_finding", "purl", "registry_metadata"],
    "resolver_version": "kalama-upstream-source-resolver",
    "created_at": "ISO-8601"
  },
  "warnings": []
}
```

For production, root records should also include `retrieved_at`, `http_status`,
`final_url`, redirect chain, byte hash when retrieved, and policy decision.

## 8. Confidence model

Use deterministic confidence rules.

`HIGH`:

- PURL/package identity is present and parses cleanly.
- Native registry metadata is retrieved from the deterministic ecosystem root.
- At least one independent source corroborates the same upstream repository or
  project identity: scanner reference, advisory reference, deps.dev, or signed
  release metadata.
- Redirects stay within expected authority or are explicitly known canonical
  redirects.

`MEDIUM`:

- Native registry metadata is valid but not independently corroborated; or
- deps.dev plus an advisory reference agree, but native registry metadata is
  incomplete; or
- repository/homepage is plausible but namespace evidence is partial.

`LOW`:

- Advisory/reference-only evidence.
- Metadata-only homepage/repository links without corroboration.
- Historical package identity is plausible but not strongly tied to current
  scanner evidence.

`NEEDS_REVIEW`:

- Multiple plausible upstreams.
- Namespace mismatch.
- Cross-domain redirect to unexpected authority.
- Registry metadata and advisory references disagree.
- Package appears abandoned, transferred, renamed, or mirrored.

`UNTRUSTED`:

- Link is only LLM-suggested.
- Third-party blog/forum/download mirror with no package-authority path.
- Metadata points to a domain that conflicts with package/advisory identity.

Confidence should be explainable as a list of rule hits, not a model-generated
score.

## 9. Remediation Evidence Retriever inputs and behavior

The Remediation Evidence Retriever should consume:

- package identity and exact vulnerable/fixed versions;
- allowed registry roots and allowed operations;
- promoted upstream repository/documentation/security/advisory roots;
- confidence and warnings;
- source graph parent IDs for provenance;
- policy limits for traversal depth and link types.

Retrieval behavior:

- Advisory: retrieve scanner roots plus OSV/GHSA/NVD package/CVE records, then
  follow typed advisory references that meet policy.
- Release notes: retrieve from promoted upstream documentation roots, version
  tags, or registry release metadata; do not search arbitrary docs.
- POM/dependency metadata: retrieve deterministic POM or package metadata paths
  from native registry roots; parse dependencies structurally.
- Artifact source: retrieve only from allowed native registry artifact paths,
  signed release distribution roots, or runtime-derived local donor paths.
- Checksum/integrity: retrieve registry checksum files, signatures, digests, or
  locally computed hashes; record algorithm and byte hash.
- Migration/upgrade docs: retrieve only from promoted documentation/security
  roots or links contained in already-promoted upstream docs.

The retriever should be allowed to return `EVIDENCE_GRAPH_INSUFFICIENT` when a
dependency closure cannot be completed under policy.

## 10. New bypass risks and guardrails

New bypass risk exists if the resolver becomes a laundering step where the agent
can turn arbitrary URLs into "candidates" and then treat them as roots.

Guardrails:

- Resolver inputs must be structured evidence, not free-form LLM text.
- Every root must have `derivation` and `parent_evidence`.
- LLM-proposed URLs are forbidden as roots; at most they can be logged as
  rejected observations.
- Metadata links are candidates until deterministic promotion rules accept them.
- deps.dev links cannot be promoted without corroboration or namespace alignment.
- Native registry roots authorize only ecosystem-specific operations, not
  arbitrary external links.
- Source graph validation must fail on missing parent, missing hash for retrieved
  bytes, unexplained redirect, or unapproved domain transition.
- Patch reasoning can consume only evidence packs, not resolver internals that
  were rejected or untrusted.
- Report all `UNTRUSTED`, `NEEDS_REVIEW`, and rejected sources.

## 11. Experimental evaluation plan

Recommended follow-up task after 7.5.5: Task 7.5.6A, design-level resolver
replay without production implementation.

Proposed protocol:

1. Freeze the existing `UZBL5` seed and Task 7.5.5 source graph as baseline.
2. Build a non-production replay harness that accepts only frozen scanner/runtime
   fields: CVE, package name, ecosystem, installed version, fixed version, PURL,
   scanner references, and runtime-derived URLs.
3. Produce an `UpstreamIdentity` candidate set for the Struts package and the
   missing transitive dependency coordinates.
4. Do not let an LLM supply any URL. Use deterministic PURL/native registry,
   deps.dev, OSV/GHSA/NVD, and existing scanner/runtime references only.
5. Generate a new source graph with explicit parentage from seed fields to each
   derived source.
6. Audit whether the graph reaches the three missing artifacts or confirms that
   it still cannot.
7. Compare against Task 7.5.5:
   - number of retrieved anchored sources;
   - number of unanchored/rejected sources;
   - whether missing dependency evidence is resolved;
   - whether any source was introduced without provenance;
   - whether the 5/8 and 3/8 outcome would remain, improve, or fail validation.
8. Stop before any Patch Form submission or patch execution.

Success criteria:

- Source graph remains auditable.
- All new roots are derived from seed package identity or trusted advisory
  records.
- No arbitrary LLM-discovered URL is accepted.
- Any improvement over 5/8 is attributable to deterministic resolver reach, not
  hidden model knowledge.

## 12. Final verdict

ACCEPT WITH CHANGES.

Reasons:

- The design directly addresses the 7.5.5 gap: scanner references were valid but
  too narrow for third-party dependency closure.
- PURL-derived native registry roots are a principled, auditable way to reach
  package authority without asking the LLM to invent Maven Central, Sonatype, or
  equivalent domains.
- deps.dev is useful as corroboration/discovery, but must not be final authority.
- Registry metadata links are useful but potentially attacker-controlled and
  must be candidate sources until corroborated.
- The source boundary remains evidence-anchored if derivations are deterministic,
  typed, parented, hashed, and validated.
- The design needs stricter schema fields, deterministic confidence rules, and
  explicit guardrails against URL laundering before production implementation.

TASK_7_5_6_STATUS: DESIGN_ACCEPTED_WITH_CHANGES
