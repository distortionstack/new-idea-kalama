"""Pipeline Step 2 target preparation and Trivy scanning."""

from .coordinator import execute_step2
from .models import Step2Request, Step2Result, TargetFacts
from .trivy_scanner import scan_image, validate_trivy_json
from .victim_manager import SubprocessCommandRunner, resolve_image
from .workbench import WorkbenchToolRunner

__all__ = ["Step2Request", "Step2Result", "SubprocessCommandRunner", "TargetFacts",
           "WorkbenchToolRunner", "execute_step2", "resolve_image", "scan_image",
           "validate_trivy_json"]
