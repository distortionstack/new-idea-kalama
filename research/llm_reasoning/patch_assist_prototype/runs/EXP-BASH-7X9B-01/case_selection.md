# Case Selection — EXP-BASH-7X9B-01

## Selected case

- CVE: CVE-2019-9924 (HIGH; rbash BASH_CMDS writable) with incidental
  CVE-2016-9401 (MEDIUM; popd), same package and same scanner fixed version.
- Package: `bash` 4.3-11+deb8u1 (deb, debian-8.10, amd64),
  PURL `pkg:deb/debian/bash@4.3-11+deb8u1?arch=amd64&distro=debian-8.10`.
- Scanner fixed version: 4.3-11+deb8u2 (Debian LTS, DLA-1726-1).
- Image: `kalama-lab:type-c-shellshock` (vulhub/bash:4.3.0-with-httpd,
  RepoDigest `sha256:1ee787c9…`), Debian 8.10 (EOSL), 258 total findings,
  single action `patch-001` scoped to the bash findings.

## Why it is suitable

1. Executable/testable in principle via the documented lab image; Phase 1
   itself ran no container (image inspect + tar scan only, read-only).
2. Scanner-visible vulnerability with identifiable component, installed
   version, and a fixed-version path (Trivy `Status: fixed`).
3. L3-plausible: Debian archive/security indexes carry exact-version
   metadata with hashes; the .deb is directly retrievable.
4. L4-plausible: DLA tracker record, GNU bash CHANGES fix entry, Debian
   changelog convention.
5. L5-questionable by design: no app-server vendor docs are reachable under
   policy, so the runtime-doc-vs-runtime-evidence question (STEP 9) is live.
6. Non-trivial: EOL/LTS repository availability is genuinely uncertain
   (Trivy itself warns detection may be insufficient; LAB_CASES.md notes a
   PACKAGE_AVAILABLE negative is possible), the backport-vs-upstream
   version-family question (deb8u2 vs 4.4-1) needs interpretation, and
   container service handling (apache2ctl foreground, no declared ports)
   needs procedure evidence.
7. Bounded: one package, one primary CVE (+1 incidental, same fix), one
   fixed Debian revision, three arms from one seed.

## Scope boundaries (recorded, not resolved — no reasoning in this phase)

- The image also carries a source-built `/usr/local/bash-4.3.0` (upstream
  4.3.0, first in PATH) that is NOT covered by the distro scanner finding.
  It is recorded in the seed as a scope boundary; patch-001 covers only the
  scanner-visible distro package action.
- No live container was executed; runtime evidence is image-config and
  image-history facts only. No BEFORE-exploit binding is claimed.
- The 257 non-bash findings are out of scope for this single-action
  experiment.
