# Evidence Sufficiency for LLM-Assisted Remediation

## Motivation and the scanner gap

Vulnerability scanners excel at identification: they report which component is
vulnerable, which CVE applies, which version is installed, where it resides,
and sometimes which version fixes it. What they do not provide is a safe
remediation. A scanner `FixedVersion` string is not artifact provenance: it
does not say where the fixed artifact lives, who published it, or whether it
is still available. It is not dependency closure: a fixed core module
typically drags a set of dependency versions with it, and the scanner says
nothing about whether those companions exist or resolve. It is not
compatibility evidence: moving from one release line to another can change
plugin APIs, configuration semantics, and module alignment. It is not runtime
deployment semantics: replacing files inside a containerized application
server requires knowing how that server deploys, redeploys, expands, and
preserves archives. And it is certainly not an executable patch command with
a matching validation procedure. Treating a fixed-version string as a patch
plan conflates naming a destination with proving a safe route.

## An evidence sufficiency ladder

The sufficiency model therefore stratifies evidence into cumulative levels.
Scanner and runtime evidence alone (L0) supports identification and version
candidates but nothing executable. Traversing the scanner's own references
(L1) adds advisory confirmation and, where the graph reaches, repository and
deployment documentation — enough, in the observed case, to confirm fixed
releases and to ground procedure for a subset of targets. Deterministic
advisory-authority queries (L2) add independent affected/fixed confirmation
without adding artifacts. Package-identity-derived native registry roots
(L3) add provenance, integrity sidecars, and dependency closure, because the
package manager's namespace deterministically implies where metadata,
manifests, artifacts, and checksums for exact coordinates must live.
Promoted upstream documentation (L4) adds compatibility, migration, and
release-note reasoning. Runtime-vendor documentation (L5) adds the
deployment and validation semantics of the actual runtime. Each level states
not only what it enables but what must still remain unknown without it, and
retrieval at every level is deterministic: fixed inputs, fixed mappings,
typed operations, hashed bytes, recorded parentage.

## Why the resolver must be deterministic

The source resolver exists because scanner references, while trustworthy, are
narrow: they describe the vulnerable project, not necessarily the third-party
artifacts its fixed releases depend on. Allowing the language model to bridge
that gap from memory — guessing a registry, a URL, a checksum — would
dissolve the audit boundary the entire pipeline depends on. The resolver
therefore derives roots from machine evidence rather than model knowledge: a
Package URL encodes ecosystem and coordinates, and a Kalama-owned registry
map turns those coordinates into exact metadata, manifest, artifact, and
checksum paths. Discovery aids such as dependency-index lookups contribute
corroboration and candidate project links, but never final artifact
authority; links embedded in package metadata remain candidates until
deterministic promotion rules — corroboration plus namespace alignment —
accept them. Every derived root carries its derivation and parent evidence,
so the resulting source graph shows precisely how each byte was reached.

## The bounded role of the language model

Within this architecture the language model is powerful but deliberately
downstream. It never discovers sources, never promotes authority, and never
declares remediation verified. It interprets: reading advisory language and
release notes, weighing upgrade tradeoffs, aligning modules across
deployments, and drafting environment-specific procedures strictly from
retrieved evidence. It is gated by sufficiency thresholds: version
suggestions from advisory-confirmed evidence, provenance and closure claims
only with registry evidence, and command or validation-command proposals
only when provenance, integrity, closure, compatibility, and runtime
procedure evidence are jointly present. Below a threshold the model's
required output is not a guess but a typed abstention — null commands,
explicit unknown fields, and machine-readable missing-evidence codes.

## Abstention as engineering virtue

That abstention is a first-class result, not a failure mode. In the
case study grounding this design, the evidence-anchored traversal produced
validator-ready actions for five of eight patch targets while three
correctly remained unresolved: the required third-party artifacts were
unreachable through any allowed route, and the one unanchored guess at a
registry page was rejected and left unused. A system that fabricates a
plausible-looking patch for those three targets would score higher on
naive completion metrics and be strictly more dangerous. The abstaining
system preserved auditability, told its operators exactly what was missing
and where it had looked, and left the door open for a principled extension
— deterministic native-registry roots — that later closed the gap without
weakening the boundary.

## Exploit-validated confirmation

Finally, no amount of pre-execution evidence, however complete, constitutes
proof of remediation. Production validation checks that a patch proposal is
well-formed and evidence-linked; it cannot show the vulnerability is gone
or the application still works. That confirmation belongs to the exploit-
validated pipeline: execute the approved patch, rescan the resulting
artifact, re-run the exploit that originally confirmed the vulnerability,
and classify remediation only on that observed outcome. The evidence
sufficiency model thus terminates where empirical validation begins —
deterministic retrieval makes proposals trustworthy enough to review,
human judgment makes them authorized enough to execute, and adversarial
re-testing makes them proven enough to believe.
