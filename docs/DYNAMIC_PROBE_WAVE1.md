# Dynamic probe foundation — Wave 1

Dynamic probes are deliberately distinct from image scanning. Trivy and Grype
observe package/image content; a future Nuclei adapter will observe one live,
run-bound HTTP endpoint. This Wave contains no runner, CLI flag, artifact
publication, candidate correlation, or prioritization change.

## Enforced now

- An endpoint carries `run_id`, `container_id`, name, network, IP, port,
  scheme, and readiness state. Its key includes the run/container identity,
  rather than being derived only from a URL.
- Wave-1 endpoint objects accept only HTTP or HTTPS.
- An approved template manifest is an exact list of IDs, relative paths,
  SHA-256 values, and mapped CVEs. Duplicate IDs, relative-path traversal,
  symlink escapes from the template root, and malformed hashes are rejected.
- Optional Doctor configuration validates local binary/template/manifest
  identities without downloading, updating, or repairing anything.

## Deferred enforcement

The future runner must enforce the policy at execution time: HTTP-only engine
arguments, no redirects, no OAST/Interactsh, no intrusive/fuzz/DoS/
brute-force/local/headless/code/JavaScript/DNS/raw-network templates, no remote
template source or update, and re-checking container identity before and after
the probe. Template allowlisting and runner flags are defense in depth; a later
Wave must additionally restrict network egress to the victim belonging to the
current `run_id`.

The required manifest shape is:

```yaml
schema: kalama.nuclei-template-policy/v1
profile: safe-cve-http
template_revision: reviewed-commit-or-release
approved_templates:
  - template_id: cves/example.yaml
    relative_path: http/cves/example.yaml
    expected_sha256: <64 lowercase hex characters>
    expected_signature_status: verified
    mapped_cves: [CVE-2099-0001]
```

`NucleiDoctorConfig` is intentionally only a Python-level optional preflight
input in this Wave. Normal `kalama doctor` and every pipeline command remain
unchanged until a later explicit enablement Wave.
