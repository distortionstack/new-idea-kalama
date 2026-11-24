# Direct Provider Investigation — 2026-11-21

รอบนี้ใช้เฉพาะ 4 PURL ที่กำหนด และไม่เพิ่ม test cases หรือ adapter ใหม่

## Commands and versions

คำสั่งที่ใช้จริงถูกเก็บไว้ใน `raw/provider-direct-2026-11-21/commands.txt` พร้อม response headers/body แยกไฟล์

```text
curl -sS -D <headers> -o <body> 'https://public.purldb.io/api/validate/?purl=<encoded>&check_existence=true'
curl -sS -D <headers> -o <body> 'https://public.purldb.io/api/collect/?purl=<encoded>'
curl -sS -D <headers> -o <body> 'https://api.clearlydefined.io/definitions/<coordinates>'
./.venv/bin/python -c 'from fetchcode.package import info; info(<purl>)'
./.venv/bin/purlcli --help
```

Tool versions: `packageurl-python 0.17.6`, `fetchcode 0.8.5`, `purldb-toolkit 0.1.0`, `packagedb 2.0.0`, `purl2meta 0.1.1`, Python `3.14.4`.

## PurlDB REST API

`GET /api/validate/` returned HTTP 200 and valid JSON for all four inputs. Maven packages returned `valid=true, exists=true` with the same exact PURL/version. Both Debian inputs returned `valid=true, exists=false`; this proves PurlDB's validation response, not that Debian packages are absent from Debian Snapshot. The raw responses preserve the exact claims.

`GET /api/collect/` returned HTTP 404 HTML for all four requests. It was not treated as package absence because the response was not a package JSON response. PurlDB therefore demonstrated exact package existence for the two Maven PURLs, but did not provide usable resource metadata for this four-case run.

## ClearlyDefined API

Coordinates used:

- Maven: `maven/mavencentral/org.apache.tomcat/tomcat-catalina/9.0.98`
- Maven: `maven/mavencentral/org.apache.struts/struts2-rest-plugin/2.5.13`
- Debian: `deb/debian/libglapi-mesa/13.0.6-1%2Bb2`
- Debian: `deb/debian/perl-modules-5.24/5.24.1-3%2Bdeb9u5`

Both Maven definitions returned HTTP 200 and response coordinates matched exact namespace/name/revision. They supplied:

- binary URL, source archive URL, registry/version URLs;
- expected SHA-1 and SHA-256 for the binary artifact;
- source archive coordinates and revision;
- file-level hashes for the described artifact.

For Tomcat, the definition supplied binary SHA-256 `38940a585577dd145858648e849786602c847bac964569548319a3afe889dc87` and source archive URL `https://search.maven.org/remotecontent?filepath=org/apache/tomcat/tomcat-catalina/9.0.98/tomcat-catalina-9.0.98-sources.jar`. For Struts, it supplied binary SHA-256 `f43e8ea108811a2b9d54d342f4442cd9fdcb6a4e79ce488858477d7832a27a59` and the corresponding exact-version source archive URL. These are expected metadata values; the artifact bytes were not downloaded in this focused probe, so no integrity verification claim is made.

Both Debian definitions returned HTTP 404 / no definition. This is `NOT_FOUND` for ClearlyDefined data, not proof that Debian packages are unsupported generally.

## FetchCode 0.8.5 source/interface finding

`fetchcode.package.info()` is a router wrapper. It catches `NoRouteAvailable` and returns `None`. The installed `fetchcode/package.py` registers routes for cargo, Debian Ubuntu, PyPI, npm, Composer, RubyGems and other ecosystems, but no `@router.route("pkg:maven/.*")` route exists. Therefore Maven returns `None` because FetchCode 0.8.5 has no Maven package-info route. The earlier `TypeError` came from caller code iterating the `None` result; it is not a Maven response error.

The npm call `info('pkg:npm/express@4.17.1')` returned exact release metadata, including `download_url` and `vcs_url`, confirming that the interface works where a route exists.

## purldb-toolkit / packagedb compatibility

`purldb-toolkit 0.1.0` declares `fetchcode`, `packageurl-python`, `requests`, and `click`, but its `purlcli.py` imports `packagedb.package_managers.VERSION_API_CLASSES_BY_PACKAGE_TYPE`. Installed `packagedb 2.0.0` contains no `packagedb.package_managers` module, so `purlcli --help` fails at import time with `ModuleNotFoundError`. This is a package compatibility defect in the tested distribution combination, not a provider result.

## Debian Snapshot correction

The previous `/mr/package/<name>/<version>/binpackages` and `/srcpackages` construction was wrong. The machine-readable API uses `/mr/binary/<binary>/<binary_version>/binfiles`. The corrected endpoint returned exact `binary` and `binary_version`, architecture rows, SHA-1 file identifiers, filenames, sizes, archive names and paths via `/mr/file/<sha1>/info`.

- `libglapi-mesa` returned exact binary version `13.0.6-1+b2`; `amd64` file name and size were returned. The file info path identifies source package directory `mesa` but does not by itself prove source package version.
- `perl-modules-5.24` returned exact binary version `5.24.1-3+deb9u5`; `all` file name and size were returned. The file info path identifies source package directory `perl`.

Source package lookup must use the separately identified source name/version with `/mr/package/<source>/.../srcfiles`; binary version must not be copied into source version without Debian metadata evidence.

## Hash and identity rules applied

The benchmark now hashes raw response bytes (`body_bytes`) only when the complete bounded body was read. HTTP error bodies never become artifact hashes. A truncated response is `NOT_COMPUTED_TRUNCATED`; local SHA-256 remains `LOCAL_HASH_ONLY` unless compared with an expected checksum from trusted metadata. HTTP 200 is recorded as availability only; identity/version require matching response fields or coordinates.

## Provider decision for this round

ClearlyDefined reduced Maven registry work for the tested cases by supplying exact coordinates, source/binary URLs and expected binary hashes. PurlDB validated Maven existence but its collect endpoint returned 404 in this public deployment and its Debian existence result conflicted with the independently working Debian Snapshot binary endpoint. Neither provider is sufficient alone for VIPER's OS-package and historical-version requirements. FetchCode is not a Maven provider in version 0.8.5, and purldb-toolkit cannot run with the tested packagedb version.
