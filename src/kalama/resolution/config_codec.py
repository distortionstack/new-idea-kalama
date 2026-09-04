"""Strict reconstruction of canonical configs from trusted JSON artifacts."""

from __future__ import annotations

from typing import Any, Mapping

from kalama.resolver.config_models import (
    ConfigOption, ConfigReadiness, ConfirmationStatus, EnvironmentBinding,
    EnvironmentPhase, ExecutionProtocol, ExploitConfig, ExploitValue, FieldSource,
    InvariantExploitConfiguration, ModuleSelection, PayloadConfiguration,
    PreAttackCommand, PreconditionConfiguration, TargetSelection,
)
from kalama.resolver.models import (
    CandidateAmbiguityStatus, CandidateRankingEvidence, CandidateRankingResult,
    DiscoveryStatus, ModuleCandidate, ModuleOption, ModuleTarget, PayloadDiscoveryStatus,
    PayloadEvidence, RankedModuleCandidate,
)


def _map(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def exploit_value_from_dict(raw: Any) -> ExploitValue:
    value = _map(raw, "exploit value")
    return ExploitValue(value.get("value"), value.get("suggested_value"),
                        FieldSource(value.get("source")),
                        ConfirmationStatus(value.get("confirmation_status")),
                        value.get("reason"), bool(value.get("required", False)))


def _candidate(raw: Any) -> ModuleCandidate:
    value = _map(raw, "module candidate")
    options = tuple(ModuleOption(x["name"], x.get("type"), bool(x.get("required")),
                                 x.get("default"))
                    for x in (_map(item, "module option") for item in value.get("options", [])))
    targets = tuple(ModuleTarget(int(x["index"]), str(x["name"]))
                    for x in (_map(item, "module target")
                              for item in value.get("target_details", [])))
    payloads = tuple(PayloadEvidence(str(item["name"]), tuple(
        ModuleOption(x["name"], x.get("type"), bool(x.get("required")), x.get("default"))
        for x in (_map(option, "payload option") for option in item.get("options", []))))
        for item in (_map(raw_payload, "payload evidence")
                     for raw_payload in value.get("payloads", [])))
    return ModuleCandidate(
        value["module_path"], value.get("rank") or "unknown", value.get("disclosure_date"),
        tuple(value.get("platform") or ()), tuple(value.get("targets") or ()),
        bool(value.get("check_supported")), tuple(value.get("references") or ()), options,
        value.get("discovery_source"), tuple(value.get("metadata_source") or ()),
        targets, value.get("default_target_index"),
        PayloadDiscoveryStatus(value.get("payload_discovery_status", "UNAVAILABLE")), payloads)


def _ranking(raw: Any) -> CandidateRankingResult:
    value = _map(raw, "candidate ranking")
    ranked = []
    for item_raw in value.get("ranked_candidates", []):
        item = _map(item_raw, "ranked candidate")
        evidence = tuple(CandidateRankingEvidence(
            x["reason"], int(x["weight"]), x.get("matched"), x.get("detail"))
            for x in (_map(e, "ranking evidence") for e in item.get("evidence", [])))
        ranked.append(RankedModuleCandidate(_candidate(item["candidate"]), int(item["score"]),
                                            evidence, int(item["rank_position"])))
    return CandidateRankingResult(value["cve_id"], tuple(ranked),
                                  CandidateAmbiguityStatus(value["ambiguity_status"]),
                                  value.get("top_candidate_gap"))


def _option(raw: Any) -> ConfigOption:
    value = _map(raw, "config option")
    return ConfigOption(value["name"], value.get("type"), bool(value.get("required")),
                        value.get("default"), exploit_value_from_dict(value["field"]))


def exploit_config_from_dict(raw: Any) -> ExploitConfig:
    root = _map(raw, "exploit config")
    invariant = _map(root.get("invariant"), "invariant")
    module = _map(invariant.get("module_selection"), "module selection")
    target = _map(invariant.get("target_selection"), "target selection")
    payload = _map(invariant.get("payload"), "payload")
    preconditions = _map(invariant.get("preconditions"), "preconditions")
    pre_attack = _map(invariant.get("pre_attack"), "pre_attack")
    protocol = _map(invariant.get("execution_protocol"), "execution protocol")
    environment = _map(root.get("environment"), "environment")
    canonical_invariant = InvariantExploitConfiguration(
        ModuleSelection(exploit_value_from_dict(module["module"]), _ranking(module["ranking"]),
                        DiscoveryStatus(module["discovery_status"]),
                        tuple(module.get("discovery_errors") or ())),
        TargetSelection(exploit_value_from_dict(target["target_index"]),
                        exploit_value_from_dict(target["target_name"]),
                        target.get("default_target_index"), target.get("default_target_name"),
                        bool(target.get("required"))),
        exploit_value_from_dict(invariant["targeturi"]),
        tuple(_option(x) for x in invariant.get("module_options", [])),
        PayloadConfiguration(exploit_value_from_dict(payload["payload"]),
                             tuple(payload.get("compatible_payloads") or ()),
                             tuple(payload.get("compatibility_evidence") or ()),
                             tuple(_option(x) for x in payload.get("options", [])),
                             PayloadDiscoveryStatus(payload.get("discovery_status", "UNAVAILABLE"))),
        PreconditionConfiguration(preconditions.get("description"),
                                  tuple(preconditions.get("commands") or ()),
                                  FieldSource(preconditions["source"]),
                                  ConfirmationStatus(preconditions["confirmation_status"]),
                                  bool(preconditions.get("required")),
                                  preconditions.get("execution_target")),
        PreAttackCommand(pre_attack.get("command"), pre_attack.get("execution_target"),
                         ConfirmationStatus(pre_attack["confirmation_status"]),
                         bool(pre_attack.get("required"))),
        ExecutionProtocol(bool(protocol.get("check_supported")), bool(protocol.get("run_check")),
                          bool(protocol.get("run_exploit")),
                          bool(protocol.get("session_confirmation_expected")),
                          ConfirmationStatus(protocol["confirmation_status"])),
    )
    canonical_environment = EnvironmentBinding(
        environment.get("run_id"), EnvironmentPhase(environment["phase"]),
        environment.get("container_name"), environment.get("container_id"),
        environment.get("image"), environment.get("image_id"), environment.get("image_digest"),
        environment.get("network"), environment.get("ip_address"),
        exploit_value_from_dict(environment["rhosts"]),
        exploit_value_from_dict(environment["rport"]),
        exploit_value_from_dict(environment["lhost"]), environment.get("port_binding_source"))
    return ExploitConfig(root["cve_id"], canonical_invariant, canonical_environment,
                         ConfigReadiness(root.get("readiness", "UNRESOLVED")))
