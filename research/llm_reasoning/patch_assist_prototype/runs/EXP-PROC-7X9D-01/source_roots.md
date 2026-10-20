# Source-root ownership

Roots are deterministic. No LLM/model invented any root. Every retrieved
source carries a provenance path to one of the three seed roots.

## Roots

- SEED-01 — scanner finding (frozen_seed.json#scanner_finding): derives
  scanner References[], package/PURL identity, distro identity.
  Allowed: derive-references, derive-package-identity, derive-datasource.
- SEED-02 — scanner DataSource
  (frozen_seed.json#scanner_finding.primary_vulnerability.data_source,
  Debian Security Tracker): tracker CVE-path navigation.
  Allowed: tracker-cve-navigation.
- SEED-03 — runtime image config/history
  (frozen_seed.json#runtime_evidence + image history build steps):
  runtime/vendor identity derivation (apache2ctl → Apache HTTP Server;
  apt-get build-step → Debian apt) and procedure-facts-only use.
  Allowed: vendor-identity-derivation, procedure-facts-only.

## Derivation rules used

- SCANNER_REFERENCE_TRAVERSAL: URL taken verbatim from the frozen scanner
  References[] array (S001, S002, S003).
- ADVISORY_QUERY: deterministic CVE-identity query against NVD / OSV / KEV
  endpoints (S004, S005, S007).
- ADVISORY_TRACKER_CVE_PATH: DataSource root + CVE identity path
  (S006).
- ADVISORY_TYPED_REFERENCE_TRAVERSAL: URL taken verbatim from the OSV
  record where OSV types it ADVISORY (S014: DLA-1900-2 announce URL).
- TRACKER_CHILD_LINK: hyperlink present in the bytes of an already
  retrieved tracker page (S012 from S006; S021 from S012; S013 from S021).
- PACKAGE_IDENTITY_DERIVED_LIST: snapshot MR API path from ecosystem +
  package name (S008).
- DISTRO_DERIVED_ARCHIVE_INDEX: archive.debian.org dists path from PURL
  distro (jessie) + component (S009, S010).
- INDEX_DERIVED_ARTIFACT_PATH: Filename field of the retrieved index
  stanza (S011 from S010).
- RUNTIME_IDENTITY_VENDOR_DOC: vendor documentation root derived from the
  runtime control-binary identity (apache2ctl → httpd.apache.org/docs/2.4/),
  corroborated by the `Homepage: http://httpd.apache.org/` field of the
  S009/S010 index stanzas (S015, S016).
- DISTRO_DERIVED_MANPAGE: Debian manpages path from distro (jessie) +
  package identity, corroborated by the manpage's own source stamp
  (S017: "from apache2 2.4.10-10+deb8u12" = installed revision).
- RUNTIME_TOOL_DERIVED_MANPAGE: Debian manpages path from the
  package-manager tool identity observed in frozen image history
  (apt-get) + distro scoping (S018: "APT 1.0.9.8.4").
- DOC_CHILD_LINK: hyperlink on an already retrieved L5 doc to the vendor
  "Server and Supporting Programs" reference (S020 from S015).
- PACKAGE_DERIVED_MANPAGE_ATTEMPT: same rule as DISTRO_DERIVED_MANPAGE
  for the apache2(8) page; server returned 404 (S019, FETCH_FAILED,
  retained for transparency).

## Discoverability vs authority

No search engine, blog, forum, mirror, or unparented source was used. The
OSV record (S005) aided discovery of S014 only as a typed ADVISORY
reference; S014's authority comes from being the signed Debian LTS
announce, corroborated by tracker record S013 and VendorID lineage — not
from OSV having listed it.
