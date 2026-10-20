# Task 7.5.6A - Upstream Source Resolver Replay

## 1. Scope and non-execution statement

This was a research-only replay for run `UZBL5`. It did not implement production
Kalama code, did not change the normal pipeline, did not submit a Patch Form, did
not execute a patch, did not run AFTER scan, did not re-exploit, did not run
evaluation, and did not write VALIDATED remediation Knowledge.

The replay tested whether deterministic package-identity-derived native registry
roots can close the Task 7.5.5 source-coverage gap without allowing the LLM to
invent websites.

## 2. Inputs and hashes

| Input | SHA-256 |
| --- | --- |
| `PATCH_REASONING_SEED/manifest.json` | `89386175433CAF5B6DB9B0123A9C430E62AA030809D4CBCB6AADC1380A790130` |
| Baseline `source_graph.json` | `82AF3843D8D5980C2F50458B4A964D3C9D6B9D5B528097DA7E21CA3D1C2D49B2` |
| Baseline `missing_evidence.json` | `90C7BBF27AF6D7D9AAE7E4426DA7FA82A8E89A1EFC6AC5F6901E761F9ADD4006` |
| Baseline `proposed_patch_form_UZBL5_r1.yaml` | `8A8897233C3982E4F436B0E299819B184C030C4A856ACCDA071FE995E934A457` |
| Baseline `production_validation.json` | `6BBB00B68A4829B3399B95F9455419C14C9518D33F70093707C72A05D3A55149` |
| Task 7.5.6 design review | `3731545887BDF3577E9C8A26EB8F55F606BC7A3C6D1B552674E03AE1CBEDE931` |

Replay harness artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `resolver_replay.py` | `8B71DC6A246AE8986E53CE0DAA2A2D6DA9164D47FD6263286270C247FF6E9848` |
| `upstream_identity_schema.json` | `07967691FCCA2FBB34E209A144A084F05235F74AF7B47F4951B6AD5CC627FF9B` |
| `replay_source_graph.json` | `74A1EC78F31F4A7BA9F8E191FF4510546A332BFF2C61D9AD2A7B6E7F0E85C662` |
| `replay_artifact_reachability.json` | `AD8FD4AAAEDF1C9F673A2992795E909C56C0ECA4953A6989CB380348830CA481` |
| `upstream_identities.json` | `95E12B91925F974C7B056B68C7041294234442D81682472EE9D8E0E5A88C6EDB` |

## 3. Extracted package identities

The replay extracted only dependency coordinates already present in Task 7.5.5
structured evidence:

| Coordinate | PURL | Parent evidence | Affected actions |
| --- | --- | --- | --- |
| `com.thoughtworks.xstream:xstream:1.4.10` | `pkg:maven/com.thoughtworks.xstream/xstream@1.4.10` | `baseline_source_graph:S241,S242,S243; parent_poms:S104` | `patch-004`, `patch-008` |
| `ognl:ognl:3.0.21` | `pkg:maven/ognl/ognl@3.0.21` | `baseline_source_graph:S208,S209,S210; parent_poms:S104` | `patch-004`, `patch-008` |
| `org.freemarker:freemarker:2.3.23` | `pkg:maven/org.freemarker/freemarker@2.3.23` | `baseline_source_graph:S226,S227,S228; parent_poms:S108` | `patch-007` |

These coordinates were not supplied by LLM text. They came from baseline
source-graph records whose parents were anchored Struts POM records.

## 4. Derived source root classes

The replay used two source-root classes:

- `DEPENDENCY_COORDINATE_DERIVED_NATIVE_REGISTRY_ROOT`: deterministic Maven
  native registry paths under `https://repo.maven.apache.org/maven2`, derived
  from already-parented dependency coordinates.
- `DEPS_DEV_DISCOVERY_ROOT`: deterministic deps.dev package/version records
  derived from the same coordinates. These were discovery/corroboration only and
  not final artifact authority.

No general search engine query was used. No arbitrary URL was introduced by the
LLM. No deps.dev metadata link was promoted to a trusted source root.

## 5. UpstreamIdentity records summary

The replay produced three `kalama.upstream-identity.replay/v1` records, one for
each missing dependency. Each identity has:

- ecosystem: `maven`
- exact group/artifact/version
- deterministic PURL
- one native-registry root with `DERIVED_PACKAGE_AUTHORITY`
- `allowed_operations`: `metadata`, `pom`, `artifact`, `checksum`
- parent evidence back to baseline source graph records

deps.dev returned candidate links for source repositories, issue trackers, and
homepages. They were retained as `CANDIDATE_ONLY_NOT_PROMOTED` with `LOW`
confidence. Several candidate links used `http://` or `git@...` forms; those are
useful observations but require production downgrade/review rules before any
promotion.

## 6. Replay source graph summary

`replay_source_graph_validation.json`:

- source count: 15
- derived root count: 3
- retrieved count: 12
- fetch failed count: 0
- missing parents: none
- unparented sources: none
- content hash mismatches: none
- valid: true

Every retrieved source has a parent replay root, and every replay root has parent
evidence pointing back to the baseline source graph.

## 7. Dependency reachability table

| Dependency | POM reachable | Artifact reachable | Checksum reachable | SHA-1 sidecar matched artifact | Would resolve Task 7.5.5 missing evidence |
| --- | --- | --- | --- | --- | --- |
| `com.thoughtworks.xstream:xstream:1.4.10` | yes | yes | yes | yes | yes |
| `ognl:ognl:3.0.21` | yes | yes | yes | yes | yes |
| `org.freemarker:freemarker:2.3.23` | yes | yes | yes | yes | yes |

## 8. Artifact/checksum reachability table

| Dependency | Artifact SHA-256 | SHA-1 expected | SHA-1 actual |
| --- | --- | --- | --- |
| `com.thoughtworks.xstream:xstream:1.4.10` | `a1587f35fa617513607c86ec9e6e4de5eb8acdf9a3a6d7f7458f8a8c40b00858` | `dfecae23647abc9d9fd0416629a4213a3882b101` | `dfecae23647abc9d9fd0416629a4213a3882b101` |
| `ognl:ognl:3.0.21` | `9c5419feb6c9652572c8e12f3de044253ac7ec2da87dbbb1f647ff65d357c5f6` | `f9db8f1e0372e124ac2d62355512501296a3666b` | `f9db8f1e0372e124ac2d62355512501296a3666b` |
| `org.freemarker:freemarker:2.3.23` | `a6dc0d252fa000f0d2bd98b2168c4c36a56f3efe5136d041c0df08f017300758` | `cd143cd8c02a9f838e3cb75a6dfe133750437f6d` | `cd143cd8c02a9f838e3cb75a6dfe133750437f6d` |

## 9. Comparison with Task 7.5.5 baseline

Baseline Task 7.5.5:

- 136 source records
- 97 retrieved records
- 34 fetch-failed records
- 5 actions production-validator ready
- 3 actions abstained: `patch-004`, `patch-007`, `patch-008`
- missing evidence category: no evidence-anchored route to required dependency
  artifacts

Replay:

- 15 source records
- 12 retrieved records
- 0 fetch-failed records
- all three previously missing dependency artifacts reached
- all three artifact SHA-1 checksums reached and matched

This explains why Task 7.5.5 stopped at 5/8: the original policy allowed Apache
staging paths but not a package-identity-derived native registry root for the
third-party dependencies. Once deterministic native Maven registry roots were
allowed and parented to baseline dependency coordinates, the missing artifacts
became reachable.

This does not claim remediation success. It also does not claim the three
abstained actions are validator-ready. It supports only source reachability and
artifact-integrity reachability.

## 10. Rejected/untrusted sources

No replay source lacked parentage. No replay source was accepted from LLM text.
No rejected unanchored source was needed.

Downgraded candidate observations from deps.dev:

- XStream candidates: `http://github.com/x-stream/xstream`,
  `https://github.com/x-stream/xstream/issues/`, `http://x-stream.github.io`
- OGNL candidates: `git@github.com:jkuhnert/ognl.git`,
  `http://jira.opensymphony.com/browse/OGNL`, `http://ognl.org`
- Freemarker candidates: `git@github.com:freemarker/freemarker.git`,
  `http://freemarker.org/`

These links remained candidate-only and were not used as artifact authority.

## 11. Evidence boundary preservation

The replay preserved the evidence boundary because:

- every native registry root was derived from a structured dependency coordinate
  already present in the baseline source graph;
- each coordinate had a parent anchored POM source;
- allowed operations were restricted to Maven metadata/POM/artifact/checksum
  paths;
- deps.dev records were not promoted to final authority;
- every retrieved byte stream was hashed;
- validation found no missing parents or unparented sources.

The one sensitive policy point is that production Kalama must own and audit the
ecosystem-to-native-registry map. The LLM must not choose `repo.maven.apache.org`
or any equivalent domain at runtime.

## 12. Sufficiency of Task 7.5.6 design changes

The accepted-with-changes design is sufficient for the observed 7.5.5 source
coverage gap if implemented with strict guardrails. The replay shows that
PURL/dependency-coordinate-derived Maven roots can reach the exact dependency
artifacts and checksums that were previously missing.

The design is not sufficient if deps.dev links, POM homepage fields, SCM fields,
or arbitrary metadata links are promoted automatically. The production resolver
must distinguish artifact authority from project-documentation candidates.

## 13. Recommended production guardrails

- Maintain an explicit Kalama-owned registry map per ecosystem.
- Allow PURL-derived native registry roots only for deterministic package paths
  and exact coordinates.
- Allow dependency-coordinate roots only when the coordinate was parsed from an
  already-anchored POM or metadata record.
- Record source graph parentage for every derived root.
- Record redirect chains and downgrade unexpected redirects.
- Treat deps.dev as corroboration only.
- Treat metadata homepage, SCM, issue tracker, and docs links as candidates until
  corroborated.
- Keep checksum retrieval and byte hashing deterministic.
- Fail validation on missing parentage, unapproved domain transition, or missing
  content hash for retrieved bytes.
- Keep LLM reasoning downstream of the evidence pack; never let it create roots.
- Make "source coverage improved" separate from "patch validator-ready" and
  separate from "remediation validated."

## 14. Git status and files created/modified

New research-only files under
`research/llm_reasoning/prospective_experiment/task_7_5_6a_upstream_replay/`:

- `resolver_replay.py`
- `upstream_identity_schema.json`
- `upstream_identities.json`
- `replay_source_graph.json`
- `replay_source_graph.sha256`
- `replay_source_graph_validation.json`
- `replay_artifact_reachability.json`
- `replay_missing_evidence_comparison.json`
- `retrieved_sources_manifest.json`
- `retrieved_sources_manifest.sha256`
- retrieved POM/JAR/JAR.sha1/deps.dev JSON files for XStream, OGNL, and Freemarker
- `task_7_5_6a.md`

The repository remains dirty from pre-existing unrelated work. No reset, clean,
stash, checkout, revert, production edit, patch execution, or canonical UZBL5
mutation was performed.

## Evaluation answers

1. PURL/dependency-coordinate-derived native registry roots preserved the
   evidence boundary in this replay because each was parented to structured
   baseline evidence.
2. Deterministic native registry operations reached all three missing
   dependencies.
3. Reachable dependencies: `ognl:ognl:3.0.21`,
   `com.thoughtworks.xstream:xstream:1.4.10`, and
   `org.freemarker:freemarker:2.3.23`.
4. Artifact integrity/checksum evidence became reachable for all three; each
   JAR SHA-1 matched the retrieved sidecar.
5. deps.dev added corroboration and candidate project links, but native registry
   retrieval was enough for artifact reachability.
6. deps.dev metadata links were downgraded to low-confidence candidate-only
   observations, especially `http://` and `git@...` links.
7. No source required LLM-invented domain knowledge during the replay. Production
   must enforce this by owning the registry map outside the LLM.
8. The replay explains why 7.5.5 stopped at 5/8: the earlier graph lacked an
   allowed route from anchored coordinates to a native registry artifact root.
9. The replay would likely convert the three abstentions into
   evidence-supported source candidates, but not automatically into validated
   patch commands.
10. Required guardrails are strict registry maps, parentage validation, checksum
   hashing, candidate-link downgrade, deps.dev non-authority, and no LLM-created
   roots.

TASK_7_5_6A_STATUS: REPLAY_SUPPORTS_DESIGN_WITH_GUARDRAILS
