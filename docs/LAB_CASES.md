# Kalama FixType Lab Cases

These are local Docker images built from the checked-out Vulhub labs. Run them
only in the local Docker lab environment.

## FixType C — OS package

Image: `kalama-lab:type-c-shellshock`

Source: `/home/distorion/vulhub/bash/CVE-2014-6271`

Primary vulnerability: `CVE-2014-6271` (Shellshock). Trivy reports the
vulnerable Bash package as an OS package, so remediation discovery should
classify its package action as FixType `C`.

Run:

```bash
kalama run --image kalama-lab:type-c-shellshock
```

The lab listens on port 80. A Type C plan is executable only when the package
manager can prove that a fixed package version is available in the image's
configured repositories. An old repository can therefore produce a valid
`PACKAGE_AVAILABLE` negative result instead of a patch command.

## FixType A — Maven source build

Image: `kalama-lab:type-a-struts2-s2-045`

Source and manifest: `/home/distorion/vulhub/struts2/s2-045-patch/pom.xml`

Primary vulnerability: `CVE-2017-5638` in `org.apache.struts:struts2-core`
version `2.3.30`. The local Maven manifest is required to classify the result
as FixType `A` instead of a prebuilt-image (Type B) candidate.

Run:

```bash
export KALAMA_SOURCE_ROOT=/home/distorion/vulhub/struts2/s2-045-patch
kalama run --image kalama-lab:type-a-struts2-s2-045
```

Type A discovery currently creates a human-confirmed `REBUILD` proposal. It
does not automatically run an arbitrary Maven rebuild; retain the source-root
variable until the Patch Form is generated and review the proposed command.

## Rebuild commands

```bash
docker tag vulhub/bash:4.3.0-with-httpd kalama-lab:type-c-shellshock
docker build --build-arg STRUTS2_VERSION=2.3.30 \
  --tag kalama-lab:type-a-struts2-s2-045 \
  /home/distorion/vulhub/struts2/s2-045-patch
```
