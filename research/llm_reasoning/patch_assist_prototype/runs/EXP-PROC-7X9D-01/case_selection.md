# Case Selection — EXP-PROC-7X9D-01

## Selected case

- CVEs: primary CVE-2019-10092 (MEDIUM, mod_proxy error-page XSS) with
  incidental CVE-2019-10098 (MEDIUM, mod_rewrite open redirect); both fixed
  per scanner in the same revision.
- Package: `apache2` 2.4.10-10+deb8u12 (deb, debian-8.10, amd64),
  PURL `pkg:deb/debian/apache2@2.4.10-10+deb8u12?arch=amd64&distro=debian-8.10`.
- Scanner fixed version: 2.4.10-10+deb8u15 (Debian LTS, DLA-1900-1).
- Registry-latest secure revision: 2.4.10-10+deb8u16 (Debian LTS,
  DLA-1900-2 regression update; live jessie-security index carries only this
  stanza — the scanner-fixed deb8u15 stanza is superseded and absent).
- Image: `kalama-lab:type-c-shellshock` (vulhub/bash:4.3.0-with-httpd,
  RepoDigest `sha256:1ee787c9…`), Debian 8.10 (EOSL), 258 total findings,
  single action `patch-001` scoped to the apache2 findings.
- L0 seed: `frozen_seed.json`
  (sha256:80afbdafd624df658a7bfe906cc7a3ea4878a064127842a625347396028e9910),
  extracted read-only from the frozen in-repo Trivy scan bytes
  (trivy 0.74.0, 2026-09-17). No rescan (docker daemon unavailable); reuse
  recorded in seed provenance. No container executed.

## Why it is suitable

1. Real scanner/runtime-bound candidate: Trivy `Status: fixed` OS-package
   finding (`result_class: os-pkgs`, `result_type: debian`) on the lab image,
   with identifiable component, installed version, and fixed-version path.
2. Deterministic source-root derivation possible at every level (see
   source_graph.json): scanner references, scanner DataSource, PURL +
   distro-derived registry indexes, tracker child links, OSV ADVISORY-typed
   references, runtime CMD identity, distro-derived manpages.
3. L3 retrievable: jessie main index carries the installed deb8u12 stanza
   with triple hashes; jessie-security index carries the deb8u16 stanza with
   artifact path, size, triple hashes, Depends/Pre-Depends; the .deb
   downloads and its SHA-256 matches the stanza byte-for-byte; snapshot list
   corroborates deb8u12/deb8u15/deb8u16 existence.
4. L4 retrievable AND scientifically interesting: DLA-1900-1 announce prose
   (both CVEs → deb8u15), upstream httpd 2.4 vulnerabilities page (affected
   range incl. 2.4.10, fixed in upstream 2.4.41), DLA tracker records, and —
   decisively — DLA-1900-2 announce prose stating the deb8u15 fix for
   CVE-2019-10092 was *incomplete and regressive* (balancer-manager
   regression, Debian bug 941202) and that deb8u16 carries the correct
   upstream patch. L4 therefore refines the version answer beyond the
   scanner-fixed revision instead of merely confirming it.
5. L5 retrievable under existing source policy (the gap EXP-BASH-7X9B-01
   could not fill): the runtime CMD itself is `apache2ctl`, the control
   interface of the candidate package, giving a provenance-linked vendor
   root (httpd.apache.org, corroborated by the `Homepage:` field of the
   S009/S010 index stanzas) with procedure-level docs on invocation,
   stop/restart/graceful semantics, and `-v`/`-t` verification; plus Debian
   jessie manpages for `apache2ctl` (exact runtime binary, incl.
   restart/configtest/status) and `apt-get` (install `pkg=version`,
   update-before-upgrade semantics). No blog/forum/mirror content; no
   invented URLs (the one invented-pattern URL attempted, S019, 404'd and is
   recorded as FETCH_FAILED, mitigated by S020).
6. Non-trivial: scanner-fixed (deb8u15) ≠ registry-latest (deb8u16);
   scanner-fixed is both superseded in the live index AND deficient per L4;
   the `apache2` meta-package upgrade drives version-pinned siblings
   (apache2-bin, apache2-data) via Depends; mod_proxy/mod_rewrite config
   state is unobservable from image history (verification-scope boundary).
7. Bounded: one meta-package, one CVE pair sharing a fix line, one correct
   fix revision (deb8u16), three monotonic arms from one seed.

## Scope boundaries (recorded, not resolved — no reasoning in this phase)

- patch-001 covers the `apache2` meta-package action for CVE-2019-10092 +
  CVE-2019-10098. Sibling binary packages apache2-bin/-data/-utils carry the
  same CVEs at the same versions; they are in scope ONLY as
  Depends-driven closure of the apache2 upgrade (stanzas recorded), not as
  independent actions. The future Agent must not claim coverage beyond the
  Depends closure.
- mod_proxy / mod_rewrite module configuration state (whether the proxy
  error page or self-referential redirects are even reachable) is NOT
  observable from frozen image history; verification claims are bounded to
  package-version + config-syntax + service-state checks, not exploit
  reachability.
- Source-built `/usr/local/bash-4.3.0` (first in PATH) is out of scope.
- The other ~250 non-apache2 findings are out of scope.
- No live container was executed; runtime evidence is image-config and
  image-history facts only. No BEFORE-exploit binding is claimed.
- deb8u15 (scanner-fixed) bytes were deliberately NOT retrieved: superseded
  in the live index and deficient per L4; recorded as an explicit bounded
  gap (see missing_evidence.json), not an oversight.

## Rejected candidates (brief; full audit in contamination_audit.md)

- Struts2 / CVE-2017-5638 family: CONTAMINATED (full prior patch reasoning,
  proposals, commands on record). Rejected without inspection.
- Elasticsearch / CVE-2015-1427: CONTAMINATED (complete pipeline patch
  record in output/). Rejected without inspection.
- bash / CVE-2019-9924 (EXP-BASH-7X9B-01 case): excluded by design — prior
  Agent/Reviewer experiment used the same remediation answer, and its L5
  was honestly unobtainable. Reusing it would violate requirements 2–3 and
  the L5 mandate.
- apache2 CVE-2019-0217/CVE-2019-0220 pair (fixed deb8u14): same package and
  same L5 story, but two revisions further from latest (deb8u14 → deb8u16);
  the 10092/10098 pair (deb8u15 → deb8u16, single-step supersession with an
  explicit deficient-fix narrative) is the tighter prospective instrument.
  Not contaminated either; deprioritized, not rejected.
- All other same-image packages (perl, tar, apt, libtasn1-6, …): no
  runtime service identity, hence no service-restart L5; apt itself lacks a
  vendor service procedure. Deprioritized for L5 weakness, not rejected for
  contamination.
