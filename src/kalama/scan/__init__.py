"""Additive multi-scanner normalization; legacy Trivy flow remains supported."""
from .models import NormalizedFinding, ScannerResult
from .grype import parse_grype_report
from .scan_set import build_scan_set

__all__ = ["NormalizedFinding", "ScannerResult", "parse_grype_report", "build_scan_set"]
