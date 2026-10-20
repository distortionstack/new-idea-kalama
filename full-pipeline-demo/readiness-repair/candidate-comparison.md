# Candidate comparison

| Rank | Image / CVE | Evidence and strategy | Assessment |
|---|---|---|---|
| 1 | `kalama-lab:type-c-shellshock` / CVE-2014-6271 | Documented FixType C OS-package lab; Trivy package finding; expected Package Manager strategy; Shellshock lab on port 80 | Strongest simple candidate, but Docker, image digest, module availability, and repository fixed-version availability are unverified until daemon is up |
| 2 | `kalama-lab:type-a-struts2-s2-045` / CVE-2017-5638 | Documented Maven source-build lab; requires `KALAMA_SOURCE_ROOT`; current docs say it creates human-confirmed REBUILD and does not automatically rebuild | Not suitable for this run because source rebuild is outside the preferred supported simple path |
| 3 | `2d8ru/struts2` / CVE-2017-5638, CVE-2017-9805 | Historical BEFORE exploit evidence exists, but multiple WAR/JAR occurrences caused incomplete patch coverage in `lkW2d` | Rejected for demonstration until occurrence-complete patching is available |
| 4 | `vulhub/elasticsearch:1.4.2` / CVE-2015-1427 | Historical BEFORE exploit and patch artifacts exist, but `AoFTs` ended with AFTER exploit success and remediation `FAILED` | Rejected due to contradictory validation |

Provisional selection: the Shellshock FixType C lab is the strongest feasible
candidate, subject to live verification of immutable digest, Trivy finding,
Metasploit module, package-manager availability, and target reachability. No
case was executed.
