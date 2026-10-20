# Task 7.5.4D evidence acquisition

No patch, validation command, or remediation decision is included here.

## Runtime observations

- OBSERVED: `victim-HdiiR` id `adf18dec3c2ffb30ee3e70507013843306bb6cbb24037c87977d2e632c7b6ba2`, image digest `sha256:7aa386b4b606bec5f6a7f015bab6bd1cc84169beadb2a632b6939e6e703e47db`, no mounts.
- OBSERVED: Java is OpenJDK 8u141. Tomcat webapps contain both exploded directories and WAR files.
- OBSERVED: S2-045 and S2-052 each contain `struts2-core-2.3.20.1.jar` with SHA-256 `710280f1d6b781185d7ccdce38c2deb0cfef1bba343f67c32f06efdd62f0a28c`.
- OBSERVED: their library inventories include `struts2-rest-plugin-2.3.20.1.jar`, `xwork-core-2.3.20.1.jar`, and `xstream-1.4.2.jar`.
- OBSERVED: no Maven or Gradle executable was found in the victim.

## Authoritative upstream evidence

- EXTRACTED: Apache Struts S2-052 identifies CVE-2017-9805, affected releases 2.1.6–2.3.33 and 2.5–2.5.12, recommends 2.3.34 or 2.5.13, and records compatibility-relevant REST class restrictions. URL: https://struts.apache.org/docs/s2-052.html
- EXTRACTED: the current Resolver/MSF metadata supplies the S2-045 and S2-052 CVE/module references; the current Patch Form provides fixed-version candidates and action identities.

## Unknowns deliberately retained

- UNKNOWN: authoritative image mapping that replaces this complete multi-webapp image.
- UNKNOWN: artifact closure and compatibility outcome for any candidate release against every deployed application.
- UNKNOWN: a source/build workspace for this image.

## Deterministic extraction audit

Installed JAR names/versions/hashes, action identities, scanner candidates, container identity, and direct Apache advisory facts are deterministic. Selecting a coherent remediation image or dependency closure requires cross-evidence reasoning and is intentionally not answered.
