from __future__ import annotations

from typing import Any, Mapping

from resolver_config_models import ConfirmationStatus
from ..resolution.models import ResolverCVEResult, ResolverCVEStatus
from .models import EVIDENCE_SCHEMA, EvidencePack


def _payload_subset(names: tuple[str, ...], limit: int = 48) -> list[str]:
    preferred = [x for x in names if any(token in x.casefold() for token in
                 ("cmd/unix", "generic", "reverse", "shell"))]
    return sorted(dict.fromkeys(preferred or list(names)))[:limit]


def _scanner_summary(occurrence: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("canonical_cve_id", "package_name", "package_purl", "installed_version",
            "fixed_versions", "scanner_severity", "target", "primary_url")
    return {key: occurrence.get(key) for key in keys if key in occurrence}


def build_evidence_pack(run_id: str, item: ResolverCVEResult,
                        target: Mapping[str, Any]) -> EvidencePack | None:
    config, discovery = item.exploit_config, item.discovery
    if config is None or discovery is None or item.validation is None:
        return None
    if item.status != ResolverCVEStatus.WAITING_FOR_USER_INPUT or not discovery.candidates:
        return None
    if not item.validation.issues:
        return None
    invariant = config.invariant
    candidates = list(discovery.candidates)
    selected = invariant.module_selection.module.value or invariant.module_selection.module.suggested_value
    candidate = next((x for x in candidates if x.module_path == selected), None)
    allowed = []
    if not invariant.module_selection.module.confirmed: allowed.append("module")
    if invariant.target_selection.target_index.confirmation_status != ConfirmationStatus.AUTO_CONFIRMED:
        allowed.append("target")
    if not invariant.targeturi.confirmed: allowed.append("targeturi")
    if not config.environment.rport.confirmed: allowed.append("rport")
    if not invariant.payload.payload.confirmed: allowed.append("payload")
    allowed.extend(["execution_protocol", "preconditions"])
    if candidate:
        allowed.append("module_options")
    if invariant.payload.payload.value and invariant.payload.options:
        allowed.append("payload_options")
    allowed = sorted(set(allowed))
    if not allowed:
        return None

    ports = {
        "exposed": sorted({int(x.get("container_port")) for x in target.get("exposed_ports", [])
                           if isinstance(x, Mapping) and isinstance(x.get("container_port"), int)}),
        "listening": sorted({int(x.get("container_port")) for x in target.get("listening_ports", [])
                             if isinstance(x, Mapping) and isinstance(x.get("container_port"), int)}),
        "reachable": sorted(x for x in target.get("reachable_ports", []) if isinstance(x, int)),
        "published": sorted({int(x.get("container_port")) for x in target.get("published_ports", [])
                             if isinstance(x, Mapping) and isinstance(x.get("container_port"), int)}),
    }
    all_module_options = ({x.name: {"type": x.type, "required": x.required, "default": x.default}
                           for x in candidate.options} if candidate else {})
    important = [name for name, value in all_module_options.items()
                 if value["required"] or name.upper() in {"RPORT", "TARGETURI", "SSL", "VHOST"}]
    module_options = {name: all_module_options[name] for name in sorted(important)[:32]}
    targets = ([x.to_dict() for x in candidate.target_details] if candidate else [])
    payload_names = invariant.payload.compatible_payloads
    doc = {
        "schema": EVIDENCE_SCHEMA, "run_id": run_id, "phase": "BEFORE",
        "cve_id": item.input.cve_id,
        "target": {"image": target.get("requested_image_reference"),
                   "container_id": target.get("container_id"),
                   "ip_address": target.get("ip_address"), "network": target.get("network"),
                   "ports": ports},
        "scanner": {"occurrences": [_scanner_summary(x) for x in item.input.occurrences]},
        "metasploit": {"candidate_modules": [x.module_path for x in candidates],
                       "selected_module": selected, "targets": targets,
                       "default_target_index": candidate.default_target_index if candidate else None,
                       "module_options": module_options,
                       "compatible_payload_count": len(payload_names),
                       "compatible_payload_subset": _payload_subset(payload_names),
                       "payload_discovery_status": invariant.payload.discovery_status.value,
                       "payload_options": {x.name: {"type": x.type, "required": x.required,
                                                    "default": x.default}
                                           for x in invariant.payload.options}},
        "resolver": {"module": invariant.module_selection.module.to_dict(),
                     "target": invariant.target_selection.to_dict(),
                     "targeturi": invariant.targeturi.to_dict(),
                     "rport": config.environment.rport.to_dict(),
                     "lhost": config.environment.lhost.to_dict(),
                     "execution_protocol": invariant.execution_protocol.to_dict()},
        "resolved_fields": {"rhosts": config.environment.rhosts.to_dict()},
        "unresolved_fields": sorted({x.field for x in item.validation.issues}),
        "allowed_proposal_fields": allowed,
    }
    refs = {"target.image", "target.ip_address", "target.network", "target.ports.exposed",
            "target.ports.listening", "target.ports.reachable", "target.ports.published",
            "scanner.occurrences", "metasploit.candidate_modules", "metasploit.targets",
            "metasploit.default_target_index", "metasploit.module_options",
            "metasploit.compatible_payload_subset",
            "metasploit.payload_options", "resolver.module", "resolver.target",
            "resolver.targeturi", "resolver.rport", "resolver.lhost",
            "resolver.execution_protocol"}
    return EvidencePack(run_id, item.input.cve_id, doc, frozenset(refs),
                        frozenset(payload_names), frozenset(all_module_options),
                        frozenset(x.name for x in invariant.payload.options))
