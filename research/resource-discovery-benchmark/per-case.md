# Per-case results

ผลต่อเคสจาก `results.json` หลังการทดลองจริง:

| Case group | Result | Evidence |
|---|---|---|
| Maven 5 cases | Direct POM, binary JAR และ source JAR endpoints ตอบ HTTP 200; deps.dev และ OSV ตอบ HTTP 200 | `raw/maven-*.json` |
| Debian 3 cases | Snapshot `binpackages` และ `srcpackages` routes ที่ประกอบจาก PURL ตอบ 404; จัดเป็น `NOT_FOUND` ของ endpoint mapping ไม่ใช่ `UNSUPPORTED` ecosystem | `raw/debian-*.json` |
| npm express | Registry metadata และ deps.dev/OSV ตอบ 200; exact version 4.17.1 | `raw/npm-express.json` |
| PyPI requests | PyPI JSON และ deps.dev/OSV ตอบ 200; exact version 2.31.0 | `raw/pypi-requests.json` |
| Cargo serde | crates.io API และ deps.dev/OSV ตอบ 200; exact version 1.0.197 | `raw/cargo-serde.json` |
| negative-version | Registry endpoints 404; OSV 200 หมายถึง query สำเร็จ ไม่ใช่ package มีอยู่ | `raw/negative-version.json` |
| negative-purl | `INVALID_INPUT` จาก packageurl-python | `raw/negative-purl.json` |
| unsupported-ecosystem | `UNSUPPORTED` โดยไม่เรียก provider | `raw/unsupported-ecosystem.json` |
