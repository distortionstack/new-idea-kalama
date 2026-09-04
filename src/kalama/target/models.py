"""Immutable contracts for Pipeline Step 2 target preparation and scanning."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ImageSourceKind(str, Enum):
    LOCAL_EXISTING = "LOCAL_EXISTING"
    PULLED = "PULLED"
    LOCAL_BUILT = "LOCAL_BUILT"
    UNKNOWN = "UNKNOWN"


class ObservationStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNKNOWN = "UNKNOWN"


class Step2Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class Step2FailureCode(str, Enum):
    INVALID_RUN_ID = "INVALID_RUN_ID"
    IMAGE_NOT_FOUND = "IMAGE_NOT_FOUND"
    IMAGE_PULL_FAILED = "IMAGE_PULL_FAILED"
    IMAGE_INSPECT_FAILED = "IMAGE_INSPECT_FAILED"
    IMAGE_IDENTITY_MISMATCH = "IMAGE_IDENTITY_MISMATCH"
    CONTAINER_CONFLICT = "CONTAINER_CONFLICT"
    CONTAINER_CREATE_FAILED = "CONTAINER_CREATE_FAILED"
    CONTAINER_START_FAILED = "CONTAINER_START_FAILED"
    CONTAINER_INSPECT_FAILED = "CONTAINER_INSPECT_FAILED"
    NETWORK_NOT_FOUND = "NETWORK_NOT_FOUND"
    NETWORK_ATTACH_FAILED = "NETWORK_ATTACH_FAILED"
    RUNTIME_NOT_READY = "RUNTIME_NOT_READY"
    RUNTIME_INSPECTION_FAILED = "RUNTIME_INSPECTION_FAILED"
    TRIVY_NOT_AVAILABLE = "TRIVY_NOT_AVAILABLE"
    TRIVY_EXECUTION_FAILED = "TRIVY_EXECUTION_FAILED"
    TRIVY_INVALID_JSON = "TRIVY_INVALID_JSON"
    TRIVY_SCHEMA_UNSUPPORTED = "TRIVY_SCHEMA_UNSUPPORTED"
    ARTIFACT_VALIDATION_FAILED = "ARTIFACT_VALIDATION_FAILED"
    ARTIFACT_WRITE_FAILED = "ARTIFACT_WRITE_FAILED"


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class Step2Issue:
    code: Step2FailureCode
    stage: str
    message: str
    retryable: bool = False
    command: tuple[str, ...] | None = None
    exit_code: int | None = None
    stderr: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "stage": self.stage, "message": self.message,
                "retryable": self.retryable,
                "command": list(self.command) if self.command else None,
                "exit_code": self.exit_code, "stderr": self.stderr}


@dataclass(frozen=True)
class Step2Request:
    run_id: str
    image_reference: str
    output_path: str
    network: str = "kalama-net"
    phase: str = "before"
    platform: str | None = None
    environment: tuple[tuple[str, str], ...] = ()
    command: tuple[str, ...] = ()
    entrypoint: tuple[str, ...] = ()
    ports: tuple[str, ...] = ()
    volumes: tuple[str, ...] = ()
    startup_timeout: float = 30.0
    startup_grace_period: float = 0.0
    victim_runtime_required: bool = True


@dataclass(frozen=True)
class ImageIdentity:
    requested_reference: str
    image_id: str
    repo_digests: tuple[str, ...]
    selected_digest: str | None
    repo_tags: tuple[str, ...]
    platform: str | None
    source_kind: ImageSourceKind

    @property
    def canonical_identity(self) -> str:
        return self.selected_digest or self.image_id

    def to_dict(self) -> dict[str, Any]:
        return {"requested_reference": self.requested_reference, "image_id": self.image_id,
                "repo_digests": list(self.repo_digests), "selected_digest": self.selected_digest,
                "repo_tags": list(self.repo_tags), "platform": self.platform,
                "source_kind": self.source_kind.value,
                "canonical_identity": self.canonical_identity}


@dataclass(frozen=True)
class ExposedPort:
    container_port: int
    protocol: str
    source: str = "docker_exposed_port"

    def to_dict(self) -> dict[str, Any]:
        return {"container_port": self.container_port, "protocol": self.protocol, "source": self.source}


@dataclass(frozen=True)
class PublishedPort:
    container_port: int
    protocol: str
    host_ip: str | None
    host_port: int | None
    source: str = "docker_port_binding"

    def to_dict(self) -> dict[str, Any]:
        return {"container_port": self.container_port, "protocol": self.protocol,
                "host_ip": self.host_ip, "host_port": self.host_port, "source": self.source}


@dataclass(frozen=True)
class ListeningPort:
    container_port: int
    protocol: str
    address: str
    source: str = "proc_net"

    def to_dict(self) -> dict[str, Any]:
        return {"container_port": self.container_port, "protocol": self.protocol,
                "address": self.address, "source": self.source}


@dataclass(frozen=True)
class TargetFacts:
    run_id: str
    phase: str
    container_name: str
    container_id: str
    container_state: str
    requested_image_reference: str
    image_id: str
    image_digest: str | None
    network: str
    ip_address: str | None
    environment: tuple[str, ...]
    command: tuple[str, ...]
    entrypoint: tuple[str, ...]
    exposed_ports: tuple[ExposedPort, ...]
    published_ports: tuple[PublishedPort, ...]
    listening_ports_status: ObservationStatus
    listening_ports: tuple[ListeningPort, ...]
    reachable_ports_status: ObservationStatus = ObservationStatus.UNKNOWN
    reachable_ports: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "phase": self.phase,
                "container_name": self.container_name, "container_id": self.container_id,
                "container_state": self.container_state,
                "requested_image_reference": self.requested_image_reference,
                "image_id": self.image_id, "image_digest": self.image_digest,
                "network": self.network, "ip_address": self.ip_address,
                "environment": list(self.environment), "command": list(self.command),
                "entrypoint": list(self.entrypoint),
                "exposed_ports": [x.to_dict() for x in self.exposed_ports],
                "published_ports": [x.to_dict() for x in self.published_ports],
                "listening_ports_status": self.listening_ports_status.value,
                "listening_ports": [x.to_dict() for x in self.listening_ports],
                "reachable_ports_status": self.reachable_ports_status.value,
                "reachable_ports": list(self.reachable_ports)}


@dataclass(frozen=True)
class TrivyArtifact:
    scanner: str
    trivy_version: str | None
    scan_subject: str
    requested_image: str
    image_id: str
    image_digest: str | None
    artifact_path: str
    artifact_sha256: str
    schema_version: int
    created_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"scanner": self.scanner, "trivy_version": self.trivy_version,
                "scan_subject": self.scan_subject, "requested_image": self.requested_image,
                "image_id": self.image_id, "image_digest": self.image_digest,
                "artifact_path": self.artifact_path, "artifact_sha256": self.artifact_sha256,
                "schema_version": self.schema_version, "created_at": self.created_at}


@dataclass(frozen=True)
class Step2Result:
    status: Step2Status
    image_identity: ImageIdentity | None = None
    target_facts: TargetFacts | None = None
    trivy_artifact: TrivyArtifact | None = None
    warnings: tuple[Step2Issue, ...] = ()
    failure: Step2Issue | None = None

    @property
    def success(self) -> bool:
        return self.status == Step2Status.SUCCEEDED

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value,
                "image_identity": self.image_identity.to_dict() if self.image_identity else None,
                "target_facts": self.target_facts.to_dict() if self.target_facts else None,
                "trivy_artifact": self.trivy_artifact.to_dict() if self.trivy_artifact else None,
                "warnings": [x.to_dict() for x in self.warnings],
                "failure": self.failure.to_dict() if self.failure else None}
