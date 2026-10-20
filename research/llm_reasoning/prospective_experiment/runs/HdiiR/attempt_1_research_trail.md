# HdiiR Patch Attempt 1 — research/action trail

## 2026-09-15 — scope established

- **OBSERVED:** `HdiiR` is paused at `STEP_5_PATCH`; `PRE_PATCH` is validated.
- **DECIDED:** investigate only current HdiiR evidence and authoritative upstream/vendor sources. Historical `lkW2d` remediation material is excluded.
- **DECIDED:** no LLM, no AFTER workflow, and exactly one patch execution will be performed.

## Evidence classification convention

- **OBSERVED** is a direct runtime/container/log fact.
- **EXTRACTED** is a value carried by a current Kalama or authoritative source.
- **INFERRED** is a bounded conclusion from those facts.
- **DECIDED** is an operator choice made for Attempt 1.

## 2026-09-15 — patch-plan scope and execution constraints

- **EXTRACTED:** Kalama generated `patch_form_HdiiR_r1.yaml` with actions `patch-001` through `patch-008`. Actions `001`–`007` cover distinct installed `struts2-core` versions (2.3.1, 2.3.14.2, 2.3.15.1, 2.3.20.1, 2.3.24.1, 2.3.30, 2.5.10) for CVE-2017-5638; `008` covers `struts2-rest-plugin` 2.3.20.1 for CVE-2017-9805. This is scanner-wide image scope, not just the two exploited paths.
- **OBSERVED:** `victim-HdiiR` contains exploded Tomcat applications, including `S2-045` and `S2-052`, both with `struts2-core-2.3.20.1.jar`; their Maven metadata identifies `struts2-rest-showcase` 2.3.20.1. The container has no source mount and no Maven executable, only `apt-get`.
- **EXTRACTED:** fixed-version candidates are 2.3.32/2.5.10.1 for the core actions and 2.3.34/2.5.13 for the REST plugin action. Every action is `PREBUILT_IMAGE_REPLACEMENT` with `ARTIFACT_SOURCE_UNRESOLVED`.
- **EXTRACTED:** the production backend accepts a prebuilt/image replacement only when a trusted, concrete replacement image/source identifier is supplied. Its own discovery documentation explicitly records that product-version to trusted image mapping is unavailable for this class of target.
- **INFERRED:** Maven coordinates and fixed versions alone cannot safely identify a replacement for this deliberately multi-application image, nor establish that a new image preserves all deployments and target bindings.
- **DECIDED:** do not fabricate a Docker image reference, checksum, or destructive replacement command. No Patch Form can be truthfully completed for Attempt 1 until an authoritative rebuilt/replacement image identity exists.

## Task 7.5.4D — prospective evidence acquisition

- **OBSERVED:** captured victim identity, Java 8u141, empty mounts, Tomcat exploded/WAR inventory, relevant JAR inventories and the shared current core-JAR hash.
- **EXTRACTED:** current Kalama scanner/resolver/BEFORE/Patch Form evidence was copied unchanged; Apache S2-052 advisory evidence was recorded without converting it to a procedure.
- **NORMALIZED:** emitted a stable-ID evidence inventory. It preserves unknown full-image replacement and dependency-closure facts rather than proposing a solution.
- **DECIDED:** froze only pre-proposal evidence. The string audit found build-layer commands inside immutable scanner metadata; these are source-image history, not a proposed patch or validation command, and are retained as raw evidence rather than removed.
