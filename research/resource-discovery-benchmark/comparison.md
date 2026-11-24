# Comparison

ผลจาก run `v2` ใน `results.json` และ raw evidence ที่สร้างวันที่ 2026-11-21

| Provider | Ecosystem | Exact version | Source | Binary | Verification | Status | Evidence |
|---|---|---:|---:|---:|---:|---|---|
| deps.dev | Maven, npm, PyPI, Cargo | PASS exact endpoint | metadata only | no artifact | no trusted checksum | PARTIAL | `results.json`, raw Maven/npm/PyPI/Cargo |
| deps.dev | Debian | NOT_CALLED (unsupported mapping) | N/A | N/A | N/A | UNSUPPORTED | `benchmark.py:SUPPORTED_DEPS` |
| Direct Registry API | Maven | PASS (5/5 endpoints per case) | `.jar` + `-sources.jar` URLs discovered | GET attempted, bounded | no expected checksum | PARTIAL | `raw/maven-*.json` |
| Direct Registry API | npm | PASS exact version metadata | registry metadata exposes tarball URL | metadata only in this run | npm metadata not promoted to trusted checksum | PARTIAL | `raw/npm-express.json` |
| Direct Registry API | PyPI | PASS exact version metadata | metadata includes release files | metadata only in this run | PyPI digest requires per-file extraction | PARTIAL | `raw/pypi-requests.json` |
| Direct Registry API | Cargo | PASS exact version metadata | crate metadata | metadata only in this run | registry checksum requires extraction | PARTIAL | `raw/cargo-serde.json` |
| Direct Registry API | Debian Snapshot | NOT_FOUND for tested routes | no usable artifact URL | no | no | NOT_FOUND / NEEDS_ROUTE_FIX | `raw/debian-*.json` |
| OSV | Maven/npm/PyPI/Cargo | query returned HTTP 200 | vulnerability metadata, not package artifact | no | no | PARTIAL | `raw/*.json` |
| purlcli 0.1.0 | smoke blocked by broken dependency | not executed | not tested | not tested | not tested | PROVIDER_ERROR | `raw/tool-smoke.json` |
| FetchCode 0.8.5 | npm Python API returned exact release metadata; Maven returned `None`/TypeError | npm download URL + VCS URL | no artifact downloaded | fields were null for tested npm result | PARTIAL | `raw/tool-smoke.json` |
| purl2meta 0.1.1 | installed; no stable CLI entry point found | NOT_TESTED | NOT_TESTED | NOT_TESTED | BLOCKED_TOOL_INTERFACE | `raw/tool-smoke.json` |
| ClearlyDefined / PurlDB REST / Software Heritage | NOT_TESTED in this run | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | `raw/tool-smoke.json` |
