# Candidate validation

Status: **REJECTED — Shellshock candidate unsuitable for this run**

Validated at 2026-10-14 in the authorized Docker Desktop lab.

| Check | Evidence | Result |
|---|---|---|
| Image | `kalama-lab:type-c-shellshock` | Present |
| Immutable image ID | `sha256:1ee787c9df082795ce4dce11bdc1dc04a69bda3dbf9ba104b342873e448a1332` | Recorded |
| Trivy | Trivy 0.74.0, Debian 8.10 scan | Completed |
| Intended CVE | `CVE-2014-6271` | **0 findings** |
| Bash | `/usr/local/bash-4.3.0/bin/bash`, GNU bash 4.3.0 | Present |
| Debian package | `bash 4.3-11+deb8u1` installed/candidate | Does not prove custom Bash remediation |
| CGI | `/cgi-bin/` ScriptAlias and ExecCGI configuration present | Reachability not executed |
| Metasploit | Expected module directory absent in resolver container | Unsupported/unverified |

Because the authoritative scanner did not identify the intended CVE and no
Metasploit support was verified, no Shellshock run was created and no exploit or
patch was executed.
