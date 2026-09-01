"""Trivy execution, structural validation, and atomic artifact publication."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from .models import (
    ImageIdentity, Step2FailureCode, Step2Issue, TrivyArtifact,
)
from .victim_manager import CommandRunner, Step2OperationError, _command_issue


def validate_trivy_json(data: Any) -> Mapping[str, Any]:
    if not isinstance(data, dict):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.ARTIFACT_VALIDATION_FAILED, "trivy_validation",
            "Trivy output must be a top-level JSON object"))
    schema = data.get("SchemaVersion")
    if schema != 2:
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.TRIVY_SCHEMA_UNSUPPORTED, "trivy_validation",
            f"supported Trivy SchemaVersion is 2, got {schema!r}"))
    if not isinstance(data.get("Results"), list):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.ARTIFACT_VALIDATION_FAILED, "trivy_validation",
            "Trivy Results must be an array"))
    for optional in ("ArtifactName", "ArtifactType"):
        if optional in data and data[optional] is not None and not isinstance(data[optional], str):
            raise Step2OperationError(Step2Issue(
                Step2FailureCode.ARTIFACT_VALIDATION_FAILED, "trivy_validation",
                f"Trivy {optional} must be a string when present"))
    if "Metadata" in data and data["Metadata"] is not None and not isinstance(data["Metadata"], dict):
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.ARTIFACT_VALIDATION_FAILED, "trivy_validation",
            "Trivy Metadata must be an object when present"))
    return data


def _scan_args(output: str, subject: str) -> tuple[str, ...]:
    return ("trivy", "image", "--scanners", "vuln", "--list-all-pkgs",
            "--format", "json", "--output", output, subject)


def scan_image(image: ImageIdentity, output_path: Path, runner: CommandRunner,
               *, timeout: float | None = None) -> TrivyArtifact:
    temporary: str | None = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="wb", dir=output_path.parent, prefix=f".{output_path.name}.",
            suffix=".tmp", delete=False)
        temporary = handle.name
        handle.close()
        result = runner.run(_scan_args(temporary, image.canonical_identity), timeout=timeout)
        if result.exit_code == 127:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.TRIVY_NOT_AVAILABLE, "trivy_execution", "Trivy executable is unavailable", result))
        if result.exit_code != 0:
            raise Step2OperationError(_command_issue(
                Step2FailureCode.TRIVY_EXECUTION_FAILED, "trivy_execution", "Trivy image scan failed", result, True))
        try:
            raw = Path(temporary).read_bytes()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise Step2OperationError(Step2Issue(
                Step2FailureCode.TRIVY_INVALID_JSON, "trivy_validation",
                f"Trivy produced invalid JSON: {exc}"))
        validate_trivy_json(data)
        with open(temporary, "rb") as validated:
            os.fsync(validated.fileno())
        try:
            os.replace(temporary, output_path)
        except OSError as exc:
            raise Step2OperationError(Step2Issue(
                Step2FailureCode.ARTIFACT_WRITE_FAILED, "artifact_write",
                f"unable to atomically publish Trivy artifact: {exc}"))
        temporary = None
        canonical = output_path.read_bytes()
        digest = hashlib.sha256(canonical).hexdigest()
        trivy = data.get("Trivy") if isinstance(data.get("Trivy"), dict) else {}
        return TrivyArtifact(
            "trivy", trivy.get("Version") if isinstance(trivy.get("Version"), str) else None,
            image.canonical_identity, image.requested_reference, image.image_id,
            image.selected_digest, str(output_path), digest, data["SchemaVersion"],
            data.get("CreatedAt") if isinstance(data.get("CreatedAt"), str) else None,
        )
    except OSError as exc:
        raise Step2OperationError(Step2Issue(
            Step2FailureCode.ARTIFACT_WRITE_FAILED, "artifact_write",
            f"unable to create or read Trivy artifact: {exc}")) from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
