"""Canonical, immutable exploit-configuration data contract.

The models describe how a CVE should be tested and what still needs
confirmation.  They contain no execution or pipeline-state behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from kalama.resolver.models import CandidateRankingResult, DiscoveryStatus, PayloadDiscoveryStatus


class ConfirmationStatus(str, Enum):
    UNRESOLVED = "UNRESOLVED"
    SUGGESTED = "SUGGESTED"
    AUTO_CONFIRMED = "AUTO_CONFIRMED"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"


class FieldSource(str, Enum):
    UNSET = "UNSET"
    MODULE_DEFAULT = "MODULE_DEFAULT"
    MODULE_RANKING = "MODULE_RANKING"
    SINGLE_CANDIDATE = "SINGLE_CANDIDATE"
    TARGET_FACT = "TARGET_FACT"
    ENVIRONMENT_BINDING = "ENVIRONMENT_BINDING"
    HUMAN = "HUMAN"
    HUMAN_ATTACK_FORM = "HUMAN_ATTACK_FORM"


class EnvironmentPhase(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"


class ConfigReadiness(str, Enum):
    UNRESOLVED = "UNRESOLVED"
    READY_FOR_CONFIRMATION = "READY_FOR_CONFIRMATION"
    READY_TO_EXECUTE = "READY_TO_EXECUTE"


class ConfigInputReason(str, Enum):
    NO_MSF_MODULE = "NO_MSF_MODULE"
    DISCOVERY_ERROR = "DISCOVERY_ERROR"
    AMBIGUOUS_MODULE = "AMBIGUOUS_MODULE"
    MODULE_CONFIRMATION_REQUIRED = "MODULE_CONFIRMATION_REQUIRED"
    TARGET_REQUIRED = "TARGET_REQUIRED"
    TARGETURI_REQUIRED = "TARGETURI_REQUIRED"
    PAYLOAD_SELECTION_REQUIRED = "PAYLOAD_SELECTION_REQUIRED"
    PAYLOAD_OPTION_REQUIRED = "PAYLOAD_OPTION_REQUIRED"
    MODULE_OPTION_REQUIRED = "MODULE_OPTION_REQUIRED"
    PRECONDITION_REQUIRED = "PRECONDITION_REQUIRED"
    PRE_ATTACK_REQUIRED = "PRE_ATTACK_REQUIRED"
    EXECUTION_PROTOCOL_REQUIRED = "EXECUTION_PROTOCOL_REQUIRED"
    ENVIRONMENT_RHOSTS_REQUIRED = "ENVIRONMENT_RHOSTS_REQUIRED"
    ENVIRONMENT_RPORT_REQUIRED = "ENVIRONMENT_RPORT_REQUIRED"


@dataclass(frozen=True)
class ExploitValue:
    value: Any = None
    suggested_value: Any = None
    source: FieldSource = FieldSource.UNSET
    confirmation_status: ConfirmationStatus = ConfirmationStatus.UNRESOLVED
    reason: str | None = None
    required: bool = False

    @property
    def confirmed(self) -> bool:
        return self.confirmation_status in {
            ConfirmationStatus.AUTO_CONFIRMED,
            ConfirmationStatus.HUMAN_CONFIRMED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "suggested_value": self.suggested_value,
            "source": self.source.value,
            "confirmation_status": self.confirmation_status.value,
            "reason": self.reason,
            "required": self.required,
        }


@dataclass(frozen=True)
class ModuleSelection:
    module: ExploitValue
    ranking: CandidateRankingResult
    discovery_status: DiscoveryStatus
    discovery_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module.to_dict(),
            "ranking": self.ranking.to_dict(),
            "discovery_status": self.discovery_status.value,
            "discovery_errors": list(self.discovery_errors),
        }


@dataclass(frozen=True)
class TargetSelection:
    target_index: ExploitValue
    target_name: ExploitValue
    default_target_index: int | None = None
    default_target_name: str | None = None
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_index": self.target_index.to_dict(),
            "target_name": self.target_name.to_dict(),
            "default_target_index": self.default_target_index,
            "default_target_name": self.default_target_name,
            "required": self.required,
        }


@dataclass(frozen=True)
class ConfigOption:
    name: str
    type: str | None
    required: bool
    default: Any
    field: ExploitValue

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "field": self.field.to_dict(),
        }


@dataclass(frozen=True)
class PayloadConfiguration:
    payload: ExploitValue
    compatible_payloads: tuple[str, ...] = ()
    compatibility_evidence: tuple[str, ...] = ()
    options: tuple[ConfigOption, ...] = ()
    discovery_status: PayloadDiscoveryStatus = PayloadDiscoveryStatus.UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload.to_dict(),
            "compatible_payloads": list(self.compatible_payloads),
            "compatibility_evidence": list(self.compatibility_evidence),
            "options": [option.to_dict() for option in self.options],
            "discovery_status": self.discovery_status.value,
        }


@dataclass(frozen=True)
class PreconditionConfiguration:
    description: str | None = None
    commands: tuple[str, ...] = ()
    source: FieldSource = FieldSource.UNSET
    confirmation_status: ConfirmationStatus = ConfirmationStatus.UNRESOLVED
    required: bool = False
    execution_target: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.confirmation_status in {
            ConfirmationStatus.AUTO_CONFIRMED,
            ConfirmationStatus.HUMAN_CONFIRMED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "commands": list(self.commands),
            "source": self.source.value,
            "confirmation_status": self.confirmation_status.value,
            "required": self.required,
            "execution_target": self.execution_target,
        }


@dataclass(frozen=True)
class PreAttackCommand:
    command: str | None = None
    execution_target: str | None = None
    confirmation_status: ConfirmationStatus = ConfirmationStatus.UNRESOLVED
    required: bool = False

    @property
    def confirmed(self) -> bool:
        return self.confirmation_status in {
            ConfirmationStatus.AUTO_CONFIRMED,
            ConfirmationStatus.HUMAN_CONFIRMED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "execution_target": self.execution_target,
            "confirmation_status": self.confirmation_status.value,
            "required": self.required,
        }


@dataclass(frozen=True)
class ExecutionProtocol:
    check_supported: bool
    run_check: bool
    run_exploit: bool
    session_confirmation_expected: bool
    confirmation_status: ConfirmationStatus = ConfirmationStatus.UNRESOLVED

    @property
    def confirmed(self) -> bool:
        return self.confirmation_status in {
            ConfirmationStatus.AUTO_CONFIRMED,
            ConfirmationStatus.HUMAN_CONFIRMED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_supported": self.check_supported,
            "run_check": self.run_check,
            "run_exploit": self.run_exploit,
            "session_confirmation_expected": self.session_confirmation_expected,
            "confirmation_status": self.confirmation_status.value,
        }


@dataclass(frozen=True)
class EnvironmentBinding:
    run_id: str | None
    phase: EnvironmentPhase
    container_name: str | None = None
    container_id: str | None = None
    image: str | None = None
    image_id: str | None = None
    image_digest: str | None = None
    network: str | None = None
    ip_address: str | None = None
    rhosts: ExploitValue = ExploitValue(required=True)
    rport: ExploitValue = ExploitValue(required=False)
    lhost: ExploitValue = ExploitValue(required=False)
    port_binding_source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "phase": self.phase.value,
            "container_name": self.container_name,
            "container_id": self.container_id,
            "image": self.image,
            "image_id": self.image_id,
            "image_digest": self.image_digest,
            "network": self.network,
            "ip_address": self.ip_address,
            "rhosts": self.rhosts.to_dict(),
            "rport": self.rport.to_dict(),
            "lhost": self.lhost.to_dict(),
            "port_binding_source": self.port_binding_source,
        }


@dataclass(frozen=True)
class InvariantExploitConfiguration:
    module_selection: ModuleSelection
    target_selection: TargetSelection
    targeturi: ExploitValue
    module_options: tuple[ConfigOption, ...]
    payload: PayloadConfiguration
    preconditions: PreconditionConfiguration
    pre_attack: PreAttackCommand
    execution_protocol: ExecutionProtocol

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_selection": self.module_selection.to_dict(),
            "target_selection": self.target_selection.to_dict(),
            "targeturi": self.targeturi.to_dict(),
            "module_options": [option.to_dict() for option in self.module_options],
            "payload": self.payload.to_dict(),
            "preconditions": self.preconditions.to_dict(),
            "pre_attack": self.pre_attack.to_dict(),
            "execution_protocol": self.execution_protocol.to_dict(),
        }


@dataclass(frozen=True)
class ExploitConfig:
    cve_id: str
    invariant: InvariantExploitConfiguration
    environment: EnvironmentBinding
    readiness: ConfigReadiness = ConfigReadiness.UNRESOLVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "readiness": self.readiness.value,
            "invariant": self.invariant.to_dict(),
            "environment": self.environment.to_dict(),
        }


@dataclass(frozen=True)
class ConfigValidationIssue:
    reason: ConfigInputReason
    field: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "reason": self.reason.value,
            "field": self.field,
            "message": self.message,
        }


@dataclass(frozen=True)
class ConfigValidationResult:
    ready: bool
    readiness: ConfigReadiness
    issues: tuple[ConfigValidationIssue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "readiness": self.readiness.value,
            "issues": [issue.to_dict() for issue in self.issues],
        }
