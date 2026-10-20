# Technical deep dive

## Scanning and enrichment

The before artifact identifies Trivy `0.74.0`, the exact source digest, raw findings, package paths, installed versions and fixed versions. CVEs are normalized/deduplicated by package/CVE occurrence; non-CVE identifiers are excluded from prioritization. CVSS is selected under the recorded `nvd-source-first-v1` policy, EPSS is a date-pinned FIRST snapshot, and KEV is a dated CISA snapshot. Missing data is not silently converted into a high score (`src/kalama/prioritizer/enrichment.py:404-439`). Scanner presence is package evidence; it does not prove exploitability or reachable application code.

## Prioritization

The exact formula is `score = CVSS + 3*EPSS + 3*KEV_listed`, where `KEV_listed` is 1 or 0. The implementation validates CVSS in [0,10] and EPSS in [0,1], excludes unavailable enrichment, then sorts by KEV listed first, descending EPSS, descending CVSS, and stable input order (`src/kalama/prioritizer/scoring.py:16-51`). The artifact records `kalama-priority-v1`, Top-30, and snapshots. The repository provides the weight choice as implementation policy, not an empirical justification; call that CODE-SUPPORTED, not experimentally justified.

## Resolver and exploitation

Resolver output contains module candidates and form fields. The submission selected three candidates; 14 Top-N records had no module and 13 were skipped. Before execution produced two attributable sessions and one inconclusive result. An exploit success is not merely a successful process exit: the oracle requires attributable impact/session evidence; check-only or check-without-impact becomes inconclusive (`src/kalama/execution/oracle.py:80-99`, `src/kalama/execution/orchestrator.py:157-194`). Exact payload/module/options are in the run-specific configs and forms; reuse from J1Thf is only partially evidenced by a retrospective note.

## Patching

The plan was human-gated. Revision 1 was followed by a forced post-patch smoke retry; revision 2 used a 2.3.34 dependency closure and checksum-verified downloads, with changes confined to exploded `S2-045`/`S2-052` `WEB-INF/lib` trees. The plan preserved other WARs and recorded six scope-excluded no-op actions. Success means command and local validation success, not a vulnerability-level verdict. The after scanner proved the scope was incomplete: vulnerable occurrences remained elsewhere.

## Verification

The after scan targeted the recorded patched digest, not the source image. It found both intended CVEs. Re-exploit used two ready configs, invariant binding was recorded as equal, and both attempts were complete negatives with no new session and no environment error. That supports “the tested exploit configurations did not obtain a session on the patched target,” not “the image is safe” or “all vulnerable paths are fixed.” The classifier combines the negative oracle with positive scanner evidence and returns `INCONCLUSIVE` (`src/kalama/reexploit/classifier.py:22-49`).

## LLM

No run-specific LLM request, provider response, proposal artifact, or accepted/rejected LLM field is linked in the `lkW2d` artifact index. Current LLM configuration and later research modules are not proof of historical use. The defensible statement is: **LLM involvement in this run is UNVERIFIED; the retained records support human form submission and human-generated patch procedures, not an LLM-assisted result.**

## Security limitations

The experiment has narrow exploit coverage, no full candidate-universe denominator, scanner/package-path ambiguity across multiple WARs, incomplete database provenance, environment-specific target options, and no proof of repeatability. These limitations are material to any claim of general effectiveness.

