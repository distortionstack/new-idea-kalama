# End-to-end run search

Result: **NO_FULLY_VERIFIED_END_TO_END_RUN_FOUND**.

Search scope: all `output/**/state/run_*.json` files and the referenced
artifact indexes, scan results, exploit results, patch results, and evaluation
files. Total examined: **21 runs**.

| Candidate | Status / coverage | Disqualifying reason |
|---|---|---|
| `lkW2d` | Completed all stages; 2 BEFORE exploits; patch 8/8 | AFTER scan still `FOUND` for both CVEs; remediation `INCONCLUSIVE`; no positive validation |
| `AoFTs` | Completed all stages; 1 BEFORE exploit; patch 1/1 | AFTER exploit `EXPLOIT_SUCCEEDED`; remediation `FAILED` |
| `5d93W` | Through BEFORE exploit | Patch, AFTER scan, re-exploit, evaluation not started |
| `UZBL5`, `HdiiR` | Through patch-plan boundary | Waiting for Patch Form input; later stages absent |
| `GyxMo`, `M58zM`, `neZfP` | Through patch execution | AFTER scan, re-exploit, evaluation not started |
| `J1Thf`, `Ng16e`, `2oz1q`, `NZq9y`, `qS8x5`, `7mWRT` | Through resolver/patch boundary | Patch plan/execution or later stages absent |
| `cQkOX`, `ee6ol` | Failed at resolver | No BEFORE exploit or later stages |
| `93AF1` | Failed at BEFORE exploit | No patch or later stages |
| `W9Z6H`, `XZYRq` | Failed at target scan | No downstream stages |
| `YKdop` | Waiting at resolver | BEFORE exploit and later stages absent |
| `EEr6U`, `KWs7N`, `DFR9M` | Through resolver | BEFORE exploit and later stages absent |

The strongest demonstration candidate is `lkW2d`, but it is explicitly not a
verified successful remediation. `AoFTs` is rejected more strongly because
the AFTER exploit remained successful despite the AFTER scan's `NOT_FOUND`.
