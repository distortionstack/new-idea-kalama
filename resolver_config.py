"""Pure construction and validation for canonical exploit configurations."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from resolver_config_models import (
    ConfigInputReason,
    ConfigOption,
    ConfigReadiness,
    ConfigValidationIssue,
    ConfigValidationResult,
    ConfirmationStatus,
    EnvironmentBinding,
    EnvironmentPhase,
    ExecutionProtocol,
    ExploitConfig,
    ExploitValue,
    FieldSource,
    InvariantExploitConfiguration,
    ModuleSelection,
    PayloadConfiguration,
    PreAttackCommand,
    PreconditionConfiguration,
    TargetSelection,
)
from resolver_models import (
    CandidateAmbiguityStatus,
    CandidateRankingResult,
    DiscoveryResult,
    DiscoveryStatus,
    ModuleCandidate,
    ModuleOption,
    PayloadDiscoveryStatus,
    TargetFacts,
)


ENVIRONMENT_OPTION_NAMES = {"RHOSTS", "RPORT", "LHOST"}

# Image-specific lab routes are stronger than a Metasploit module's generic
# application-context default, but remain suggestions requiring confirmation.
TARGETURI_HINTS = {
    ("vulhub/struts2:2.5.12-rest-showcase",
     "exploit/multi/http/struts2_rest_xstream"): "/orders/3",
}


def _module_option(candidate: ModuleCandidate | None, name: str) -> ModuleOption | None:
    if candidate is None:
        return None
    wanted = name.upper()
    return next((option for option in candidate.options if option.name.upper() == wanted), None)


def _normalize_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _service_ports(target_facts: TargetFacts) -> tuple[int, ...]:
    # Runtime observations are authoritative for auto-confirmation. Image
    # EXPOSE metadata and host-side published ports remain evidence, but do
    # not prove that a service is listening inside the victim.
    ports = {item.port for item in target_facts.reachable_ports}
    ports.update(item.port for item in target_facts.observed_ports)
    return tuple(sorted(ports))


def _build_module_selection(
    discovery: DiscoveryResult,
    ranking: CandidateRankingResult,
) -> tuple[ModuleSelection, ModuleCandidate | None]:
    top_ranked = next(iter(ranking.ranked_candidates), None)
    candidate = None if top_ranked is None else top_ranked.candidate

    if candidate is None:
        module = ExploitValue(required=True, reason="no module candidate is available")
    elif ranking.ambiguity_status == CandidateAmbiguityStatus.SINGLE_CANDIDATE:
        module = ExploitValue(
            value=candidate.module_path,
            suggested_value=candidate.module_path,
            source=FieldSource.SINGLE_CANDIDATE,
            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED,
            reason="only one module candidate was discovered; no module disambiguation is needed",
            required=True,
        )
    else:
        module = ExploitValue(
            suggested_value=candidate.module_path,
            source=FieldSource.MODULE_RANKING,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason=(
                "ranking produced a clear suggestion; confirmation is still required"
                if ranking.ambiguity_status == CandidateAmbiguityStatus.CLEAR_WINNER
                else "ranking is ambiguous; the leading path is a suggestion only"
            ),
            required=True,
        )

    return ModuleSelection(
        module=module,
        ranking=ranking,
        discovery_status=discovery.status,
        discovery_errors=discovery.errors,
    ), candidate


def _build_target_selection(candidate: ModuleCandidate | None) -> TargetSelection:
    if candidate is None or not candidate.targets:
        return TargetSelection(ExploitValue(), ExploitValue(), required=False)

    details = candidate.target_details
    default = candidate.default_target_index
    default_detail = next((item for item in details if item.index == default), None)
    target_name = ExploitValue(required=True, reason="Metasploit target requires confirmation")
    target_index = ExploitValue(required=True, reason="Metasploit target requires confirmation")
    if default_detail is not None:
        target_index = ExploitValue(suggested_value=default_detail.index,
                                    source=FieldSource.MODULE_DEFAULT,
                                    confirmation_status=ConfirmationStatus.SUGGESTED,
                                    reason="real Metasploit default target; confirmation is still required",
                                    required=True)
        target_name = ExploitValue(suggested_value=default_detail.name,
                                   source=FieldSource.MODULE_DEFAULT,
                                   confirmation_status=ConfirmationStatus.SUGGESTED,
                                   reason="name of the real Metasploit default target",
                                   required=True)
    elif len(candidate.targets) == 1:
        target_name = ExploitValue(
            suggested_value=candidate.targets[0],
            source=FieldSource.SINGLE_CANDIDATE,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason="the module exposes one named target, but its index/default was not introspected",
            required=True,
        )
    return TargetSelection(
        target_index=target_index,
        target_name=target_name,
        default_target_index=default if default_detail is not None else None,
        default_target_name=default_detail.name if default_detail is not None else None,
        required=True,
    )


def _suggested_option_field(option: ModuleOption) -> ExploitValue:
    name = option.name.upper()
    if name in ENVIRONMENT_OPTION_NAMES:
        return ExploitValue(
            source=FieldSource.ENVIRONMENT_BINDING,
            reason="value is supplied by the phase-specific environment binding",
            required=option.required,
        )
    if option.default is not None:
        return ExploitValue(
            suggested_value=option.default,
            source=FieldSource.MODULE_DEFAULT,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason="Metasploit module default; not yet confirmed",
            required=option.required,
        )
    return ExploitValue(reason="module option has no declared default", required=option.required)


def _build_module_options(
    candidate: ModuleCandidate | None,
) -> tuple[tuple[ConfigOption, ...], ExploitValue]:
    if candidate is None:
        return (), ExploitValue(reason="module is unresolved")

    configured = []
    targeturi = ExploitValue(reason="module does not declare TARGETURI", required=False)
    for option in candidate.options:
        field = _suggested_option_field(option)
        if option.name.upper() == "TARGETURI":
            # Module defaults remain suggestions; TARGETURI is a later human
            # confirmation field even when the module marks it optional.
            targeturi = replace(field, required=True)
            field = targeturi
        configured.append(ConfigOption(
            name=option.name,
            type=option.type,
            required=option.required,
            default=option.default,
            field=field,
        ))
    return tuple(configured), targeturi


def _build_execution_protocol(candidate: ModuleCandidate | None) -> ExecutionProtocol:
    if candidate is None:
        return ExecutionProtocol(False, False, False, False)
    # Intended-protocol suggestion only, never an oracle result. Check-capable
    # modules begin check-only; modules without check support propose exploit.
    return ExecutionProtocol(
        check_supported=candidate.check_supported,
        run_check=candidate.check_supported,
        run_exploit=not candidate.check_supported,
        session_confirmation_expected=False,
        confirmation_status=ConfirmationStatus.SUGGESTED,
    )


def _build_environment_binding(
    target_facts: TargetFacts,
    candidate: ModuleCandidate | None,
    phase: EnvironmentPhase,
) -> EnvironmentBinding:
    rhosts_option = _module_option(candidate, "RHOSTS")
    rport_option = _module_option(candidate, "RPORT")

    rhosts_required = bool(rhosts_option and rhosts_option.required)
    if target_facts.ip_address:
        rhosts = ExploitValue(
            value=target_facts.ip_address,
            suggested_value=target_facts.ip_address,
            source=FieldSource.TARGET_FACT,
            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED,
            reason="bound from explicit target runtime facts",
            required=rhosts_required,
        )
    else:
        rhosts = ExploitValue(reason="target IP is unavailable", required=rhosts_required)

    if target_facts.msf_ip:
        lhost = ExploitValue(
            value=target_facts.msf_ip,
            suggested_value=target_facts.msf_ip,
            source=FieldSource.TARGET_FACT,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason="suggested from the Metasploit container IP on the target Docker network",
        )
    else:
        lhost = ExploitValue(reason="Metasploit IP is unavailable")

    default_rport = None if rport_option is None else _normalize_port(rport_option.default)
    service_ports = _service_ports(target_facts)
    rport_required = bool(rport_option and rport_option.required)
    port_source = None
    if len(service_ports) > 1:
        rport = ExploitValue(
            suggested_value=default_rport if default_rport in service_ports else None,
            source=FieldSource.MODULE_DEFAULT if default_rport in service_ports else FieldSource.UNSET,
            confirmation_status=(
                ConfirmationStatus.SUGGESTED
                if default_rport in service_ports else ConfirmationStatus.UNRESOLVED
            ),
            reason=f"multiple target service ports remain plausible: {list(service_ports)}",
            required=rport_required,
        )
        port_source = "ambiguous_target_ports"
    elif len(service_ports) == 1 and default_rport == service_ports[0]:
        rport = ExploitValue(
            value=service_ports[0],
            suggested_value=service_ports[0],
            source=FieldSource.TARGET_FACT,
            confirmation_status=ConfirmationStatus.AUTO_CONFIRMED,
            reason="module default matches the sole observed/published container service port",
            required=rport_required,
        )
        port_source = "module_default+target_service"
    elif len(service_ports) == 1 and default_rport is None:
        rport = ExploitValue(
            suggested_value=service_ports[0],
            source=FieldSource.TARGET_FACT,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason="sole target service port is a suggestion; module has no usable default",
            required=rport_required,
        )
        port_source = "target_service"
    elif default_rport is not None:
        rport = ExploitValue(
            suggested_value=default_rport,
            source=FieldSource.MODULE_DEFAULT,
            confirmation_status=ConfirmationStatus.SUGGESTED,
            reason="module default is not corroborated by an unambiguous target service port",
            required=rport_required,
        )
        port_source = "module_default"
    else:
        rport = ExploitValue(reason="no reliable RPORT fact is available", required=rport_required)

    return EnvironmentBinding(
        run_id=target_facts.run_id,
        phase=phase,
        container_name=target_facts.container_name,
        container_id=target_facts.container_id,
        image=target_facts.image,
        image_id=target_facts.image_id,
        image_digest=target_facts.image_digest,
        network=target_facts.network,
        ip_address=target_facts.ip_address,
        rhosts=rhosts,
        rport=rport,
        lhost=lhost,
        port_binding_source=port_source,
    )


def validate_exploit_config(config: ExploitConfig) -> ConfigValidationResult:
    """Return structured readiness issues without performing external calls."""
    issues: list[ConfigValidationIssue] = []
    invariant = config.invariant
    selection = invariant.module_selection

    if selection.discovery_status == DiscoveryStatus.ENVIRONMENT_ERROR:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.DISCOVERY_ERROR,
            "invariant.module_selection",
            "module discovery failed because of an environment/query error",
        ))
    elif selection.discovery_status == DiscoveryStatus.NO_MSF_MODULE:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.NO_MSF_MODULE,
            "invariant.module_selection",
            "no Metasploit module candidate was discovered",
        ))
    elif not selection.module.confirmed:
        reason = (
            ConfigInputReason.AMBIGUOUS_MODULE
            if selection.ranking.ambiguity_status == CandidateAmbiguityStatus.AMBIGUOUS
            else ConfigInputReason.MODULE_CONFIRMATION_REQUIRED
        )
        issues.append(ConfigValidationIssue(
            reason,
            "invariant.module_selection.module",
            "module selection has not been confirmed",
        ))

    target = invariant.target_selection
    if target.required and not (target.target_index.confirmed or target.target_name.confirmed):
        issues.append(ConfigValidationIssue(
            ConfigInputReason.TARGET_REQUIRED,
            "invariant.target_selection",
            "Metasploit TARGET has not been confirmed",
        ))

    if invariant.targeturi.required and not invariant.targeturi.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.TARGETURI_REQUIRED,
            "invariant.targeturi",
            "TARGETURI requires confirmation",
        ))

    for option in invariant.module_options:
        upper_name = option.name.upper()
        if upper_name in ENVIRONMENT_OPTION_NAMES or upper_name == "TARGETURI":
            continue
        if option.required and not option.field.confirmed:
            issues.append(ConfigValidationIssue(
                ConfigInputReason.MODULE_OPTION_REQUIRED,
                f"invariant.module_options.{option.name}",
                f"required module option {option.name} is unresolved",
            ))

    required_names = {item.name.upper() for item in invariant.module_options if item.required}
    if "RHOSTS" in required_names and not config.environment.rhosts.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.ENVIRONMENT_RHOSTS_REQUIRED,
            "environment.rhosts",
            "required RHOSTS environment binding is unresolved",
        ))
    if "RPORT" in required_names and not config.environment.rport.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.ENVIRONMENT_RPORT_REQUIRED,
            "environment.rport",
            "required RPORT environment binding is unresolved",
        ))

    protocol = invariant.execution_protocol
    if not protocol.confirmed or not (protocol.run_check or protocol.run_exploit):
        issues.append(ConfigValidationIssue(
            ConfigInputReason.EXECUTION_PROTOCOL_REQUIRED,
            "invariant.execution_protocol",
            "execution/check protocol has not been confirmed",
        ))

    module_path = selection.module.value or selection.module.suggested_value or ""
    requires_payload = protocol.run_exploit and not module_path.startswith("auxiliary/")
    if requires_payload and not invariant.payload.payload.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.PAYLOAD_SELECTION_REQUIRED,
            "invariant.payload.payload",
            "payload selection is required for exploit execution",
        ))
    if requires_payload:
        for option in invariant.payload.options:
            if option.required and not option.field.confirmed:
                issues.append(ConfigValidationIssue(
                    ConfigInputReason.PAYLOAD_OPTION_REQUIRED,
                    f"invariant.payload.options.{option.name}",
                    f"required payload option {option.name} is unresolved",
                ))

    if invariant.preconditions.required and not invariant.preconditions.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.PRECONDITION_REQUIRED,
            "invariant.preconditions",
            "required precondition has not been confirmed",
        ))
    if invariant.pre_attack.required and not invariant.pre_attack.confirmed:
        issues.append(ConfigValidationIssue(
            ConfigInputReason.PRE_ATTACK_REQUIRED,
            "invariant.pre_attack",
            "required pre-attack command has not been confirmed",
        ))

    if not issues:
        readiness = ConfigReadiness.READY_TO_EXECUTE
    elif selection.module.suggested_value is not None or selection.module.value is not None:
        readiness = ConfigReadiness.READY_FOR_CONFIRMATION
    else:
        readiness = ConfigReadiness.UNRESOLVED
    return ConfigValidationResult(not issues, readiness, tuple(issues))


def build_exploit_config(
    discovery: DiscoveryResult,
    ranking: CandidateRankingResult,
    target_facts: TargetFacts,
    phase: EnvironmentPhase = EnvironmentPhase.BEFORE,
) -> ExploitConfig:
    """Transform discovery/ranking/facts into a conservative config draft."""
    if discovery.cve_id != ranking.cve_id:
        raise ValueError("discovery and ranking CVE IDs do not match")

    module_selection, candidate = _build_module_selection(discovery, ranking)
    module_options, targeturi = _build_module_options(candidate)
    if candidate is not None:
        hinted_uri = TARGETURI_HINTS.get((target_facts.image, candidate.module_path))
        if hinted_uri is not None:
            targeturi = replace(
                targeturi,
                suggested_value=hinted_uri,
                source=FieldSource.TARGET_FACT,
                confirmation_status=ConfirmationStatus.SUGGESTED,
                reason="known route for the committed lab image; confirmation is still required",
                required=True,
            )
    protocol = _build_execution_protocol(candidate)
    invariant = InvariantExploitConfiguration(
        module_selection=module_selection,
        target_selection=_build_target_selection(candidate),
        targeturi=targeturi,
        module_options=module_options,
        payload=PayloadConfiguration(payload=ExploitValue(
            required=protocol.run_exploit,
            reason="payload selection has not been performed",
        ), compatible_payloads=tuple(item.name for item in candidate.payloads) if candidate else (),
            compatibility_evidence=("live_msfconsole",) if candidate and candidate.payloads else (),
            discovery_status=(candidate.payload_discovery_status if candidate
                              else PayloadDiscoveryStatus.UNAVAILABLE)),
        preconditions=PreconditionConfiguration(),
        pre_attack=PreAttackCommand(),
        execution_protocol=protocol,
    )
    config = ExploitConfig(
        cve_id=discovery.cve_id,
        invariant=invariant,
        environment=_build_environment_binding(target_facts, candidate, phase),
    )
    validation = validate_exploit_config(config)
    return replace(config, readiness=validation.readiness)
