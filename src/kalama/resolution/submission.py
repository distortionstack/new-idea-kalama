"""Pure, allowlisted application of explicit Attack Form confirmations."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from kalama.resolver.config import validate_exploit_config
from kalama.resolver.config_models import (
    ConfigOption, ConfirmationStatus, ExploitConfig, ExploitValue, FieldSource,
)
from kalama.resolver.models import PayloadDiscoveryStatus


class SubmissionValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AppliedConfig:
    config: ExploitConfig
    validation: Any


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD", f"{name} must be an object")
    return value


def _confirmed(raw: Any) -> tuple[bool, Any]:
    if not isinstance(raw, Mapping) or "confirmed" not in raw or raw["confirmed"] is None:
        return False, None
    return True, raw["confirmed"]


def _human(field: ExploitValue, value: Any) -> ExploitValue:
    return replace(field, value=value, source=FieldSource.HUMAN_ATTACK_FORM,
                   confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED)


def _typed(value: Any, option: ConfigOption) -> Any:
    kind = (option.type or "").lower()
    if kind in {"bool", "boolean"} and not isinstance(value, bool):
        raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                        f"{option.name} must be boolean")
    if kind in {"integer", "int", "port"}:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                            f"{option.name} must be an integer")
        if kind == "port" and not 1 <= value <= 65535:
            raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                            f"{option.name} must be a valid port")
    if kind in {"string", "enum", "address", "address_range", "path"} and not isinstance(value, str):
        raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                        f"{option.name} must be text")
    return value


def _apply_options(existing: tuple[ConfigOption, ...], submitted: Any,
                   *, payload: bool = False) -> tuple[ConfigOption, ...]:
    values = _mapping(submitted, "options") if submitted is not None else {}
    known = {x.name: x for x in existing}
    unknown = set(values) - set(known)
    if unknown:
        code = "ATTACK_FORM_INVALID_PAYLOAD" if payload else "ATTACK_FORM_INVALID_OPTION"
        raise SubmissionValidationError(code, f"unknown option(s): {', '.join(sorted(unknown))}")
    output = []
    for option in existing:
        supplied, value = _confirmed(values.get(option.name))
        output.append(replace(option, field=_human(option.field, _typed(value, option)))
                      if supplied else option)
    return tuple(output)


def _payload_options(config: ExploitConfig, module: str, payload_name: str,
                     introspector: Callable[[str, str], Any] | None) -> tuple[ConfigOption, ...]:
    """Materialize only the live-introspected schema for the selected payload."""
    for ranked in config.invariant.module_selection.ranking.ranked_candidates:
        if ranked.candidate.module_path != module:
            continue
        for payload in ranked.candidate.payloads:
            if payload.name != payload_name:
                continue
            if not payload.options:
                if introspector is None:
                    return ()
                payload = introspector(module, payload_name)
                if payload.name != payload_name:
                    raise SubmissionValidationError(
                        "ATTACK_FORM_INVALID_PAYLOAD", "payload introspection identity mismatch")
            output = []
            for option in payload.options:
                if option.name.upper() == "LHOST" and config.environment.lhost.suggested_value:
                    field = ExploitValue(
                        suggested_value=config.environment.lhost.suggested_value,
                        source=FieldSource.ENVIRONMENT_BINDING,
                        confirmation_status=ConfirmationStatus.SUGGESTED,
                        reason="Metasploit IP on the committed target network",
                        required=option.required)
                elif option.default is not None:
                    field = ExploitValue(
                        suggested_value=option.default, source=FieldSource.MODULE_DEFAULT,
                        confirmation_status=ConfirmationStatus.SUGGESTED,
                        reason="Metasploit payload default; confirmation is still required",
                        required=option.required)
                else:
                    field = ExploitValue(reason="payload option has no deterministic value",
                                         required=option.required)
                output.append(ConfigOption(option.name, option.type, option.required,
                                           option.default, field))
            return tuple(output)
    return ()


def apply_human_confirmation(
    config: ExploitConfig, human_input: Mapping[str, Any], *,
    payload_introspector: Callable[[str, str], Any] | None = None,
) -> AppliedConfig:
    allowed = {"rank", "input_reasons", "module", "target", "targeturi", "module_options",
               "payload", "payload_options", "preconditions", "pre_attack",
               "execution_protocol", "environment", "guidance"}
    unknown = set(human_input) - allowed
    if unknown:
        raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD",
                                        f"unknown CVE field(s): {', '.join(sorted(unknown))}")
    invariant, environment = config.invariant, config.environment

    module_raw = human_input.get("module")
    supplied, value = _confirmed(module_raw)
    if supplied:
        candidates = {x.candidate.module_path
                      for x in invariant.module_selection.ranking.ranked_candidates}
        if value not in candidates:
            raise SubmissionValidationError("ATTACK_FORM_INVALID_MODULE",
                                            "confirmed module is not a discovered candidate")
        selection = replace(invariant.module_selection,
                            module=_human(invariant.module_selection.module, value))
        invariant = replace(invariant, module_selection=selection)

    target_raw = _mapping(human_input["target"], "target") if "target" in human_input else {}
    index_raw = target_raw.get("index", {})
    name_raw = target_raw.get("name", {})
    has_index, index = _confirmed(index_raw)
    has_name, name = _confirmed(name_raw)
    if has_index or has_name:
        targets = ()
        target_details = ()
        selected = invariant.module_selection.module.value
        for ranked in invariant.module_selection.ranking.ranked_candidates:
            if ranked.candidate.module_path == selected:
                targets = ranked.candidate.targets
                target_details = ranked.candidate.target_details
                break
        detail_by_index = {item.index: item.name for item in target_details}
        valid_indexes = set(detail_by_index) if target_details else set(range(len(targets)))
        if has_index and (isinstance(index, bool) or not isinstance(index, int)
                          or index not in valid_indexes):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_TARGET", "invalid target index")
        if has_name and (not isinstance(name, str) or name not in targets):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_TARGET", "invalid target name")
        expected_name = detail_by_index.get(index) if target_details else (
            targets[index] if has_index else None)
        if has_index and has_name and expected_name != name:
            raise SubmissionValidationError("ATTACK_FORM_INVALID_TARGET",
                                            "target index and name do not correspond")
        target = invariant.target_selection
        target = replace(target,
                         target_index=_human(target.target_index, index) if has_index else target.target_index,
                         target_name=_human(target.target_name, name) if has_name else target.target_name)
        invariant = replace(invariant, target_selection=target)

    has_uri, uri = _confirmed(human_input.get("targeturi"))
    if has_uri:
        if not isinstance(uri, str):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION", "TARGETURI must be text")
        invariant = replace(invariant, targeturi=_human(invariant.targeturi, uri))

    invariant = replace(invariant,
                        module_options=_apply_options(invariant.module_options,
                                                      human_input.get("module_options")))
    payload_raw = human_input.get("payload")
    has_payload, payload_value = _confirmed(payload_raw)
    payload = invariant.payload
    if has_payload:
        if (not isinstance(payload_value, str)
                or payload.discovery_status != PayloadDiscoveryStatus.FOUND
                or payload_value not in payload.compatible_payloads):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_PAYLOAD",
                                            "payload is not in compatible payload evidence")
        selected_module = invariant.module_selection.module.value
        payload = replace(payload, payload=_human(payload.payload, payload_value),
                          options=_payload_options(config, selected_module, payload_value,
                                                   payload_introspector))
    payload = replace(payload, options=_apply_options(payload.options,
                                                      human_input.get("payload_options"), payload=True))
    invariant = replace(invariant, payload=payload)

    if "preconditions" in human_input:
        raw = _mapping(human_input["preconditions"], "preconditions")
        description, commands = raw.get("description"), raw.get("commands")
        execution_target = raw.get("execution_target")
        if description is not None or commands or execution_target is not None:
            if description is not None and not isinstance(description, str):
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION", "description must be text")
            if not isinstance(commands, list) or any(not isinstance(x, str) for x in commands):
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION", "commands must be text array")
            if execution_target is not None and not isinstance(execution_target, str):
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                                "precondition execution_target must be text")
            invariant = replace(invariant, preconditions=replace(
                invariant.preconditions, description=description,
                commands=tuple(commands), execution_target=execution_target,
                source=FieldSource.HUMAN_ATTACK_FORM,
                confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED))

    if "pre_attack" in human_input:
        raw = _mapping(human_input["pre_attack"], "pre_attack")
        command, target = raw.get("command"), raw.get("execution_target")
        if command is not None or target is not None:
            if ((command is not None and not isinstance(command, str))
                    or (target is not None and not isinstance(target, str))):
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                                "pre-attack values must be text")
            invariant = replace(invariant, pre_attack=replace(
                invariant.pre_attack, command=command, execution_target=target,
                confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED))

    if "execution_protocol" in human_input:
        raw = _mapping(human_input["execution_protocol"], "execution_protocol")
        allowed_protocol = {"check_supported", "run_check", "run_exploit",
                            "session_confirmation_expected", "confirmation_status",
                            "mode", "confirmed"}
        if set(raw) - allowed_protocol:
            raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD",
                                            "unknown execution protocol field")
        if raw.get("confirmed") is True:
            protocol = invariant.execution_protocol
            mode = raw.get("mode")
            if mode is None:
                run_check, run_exploit = protocol.run_check, protocol.run_exploit
            elif mode == "check-only" and protocol.check_supported:
                run_check, run_exploit = True, False
            elif mode == "check-then-exploit" and protocol.check_supported:
                run_check, run_exploit = True, True
            elif mode == "exploit-only":
                run_check, run_exploit = False, True
            else:
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                                "execution protocol mode is unsupported")
            invariant = replace(invariant, execution_protocol=replace(
                protocol, run_check=run_check, run_exploit=run_exploit,
                session_confirmation_expected=run_exploit,
                confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED))
            if run_exploit:
                invariant = replace(invariant, payload=replace(
                    invariant.payload,
                    payload=replace(invariant.payload.payload, required=True)))
        elif raw.get("confirmed") not in (None, False):
            raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION",
                                            "execution_protocol.confirmed must be true, false, or null")

    if "environment" in human_input:
        raw = _mapping(human_input["environment"], "environment")
        if set(raw) - {"rhosts", "rport", "lhost", "binding_source"}:
            raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD",
                                            "environment identity is read-only")
        rhosts_supplied, rhosts = _confirmed(raw.get("rhosts"))
        if rhosts_supplied and rhosts != environment.rhosts.value:
            raise SubmissionValidationError("ATTACK_FORM_UNKNOWN_FIELD", "RHOSTS is read-only")
        has_rport, rport = _confirmed(raw.get("rport"))
        has_lhost, lhost = _confirmed(raw.get("lhost"))
        if has_rport:
            if isinstance(rport, bool) or not isinstance(rport, int) or not 1 <= rport <= 65535:
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION", "RPORT is invalid")
            environment = replace(environment, rport=_human(environment.rport, rport),
                                  port_binding_source="human_attack_form")
        if has_lhost:
            if not isinstance(lhost, str) or not lhost:
                raise SubmissionValidationError("ATTACK_FORM_INVALID_OPTION", "LHOST is invalid")
            environment = replace(environment, lhost=_human(environment.lhost, lhost))

    updated = replace(config, invariant=invariant, environment=environment)
    validation = validate_exploit_config(updated)
    return AppliedConfig(replace(updated, readiness=validation.readiness), validation)
