from __future__ import annotations
from collections import defaultdict
from .models import ScannerResult

def build_scan_set(results):
    """Group observations only at candidate level; never double-count scanners."""
    grouped = defaultdict(list)
    for result in results:
        if result.status == "SUCCEEDED":
            for finding in result.findings:
                grouped[finding.candidate_key].append(finding)
    candidates = []
    for key, observations in sorted(grouped.items()):
        candidates.append({"candidate_key": list(key), "vulnerability_id": key[0],
                           "component": key[1], "detected_by": sorted({x.scanner for x in observations}),
                           "observations": [x.to_dict() for x in observations]})
    return {"schema": "kalama.scan-set/v1", "scanners": [{"scanner": r.scanner, "status": r.status,
            "version": r.version, "artifact_path": r.artifact_path, "artifact_sha256": r.artifact_sha256,
            "error": r.error} for r in results], "candidates": candidates}
