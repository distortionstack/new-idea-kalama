import json
import unittest
from dataclasses import FrozenInstanceError, replace

from kalama.resolver.config import build_exploit_config, validate_exploit_config
from kalama.resolver.config_models import (
    ConfigInputReason,
    ConfigOption,
    ConfigReadiness,
    ConfirmationStatus,
    EnvironmentPhase,
    ExecutionProtocol,
    ExploitValue,
    FieldSource,
    PayloadConfiguration,
    PreAttackCommand,
    PreconditionConfiguration,
)
from kalama.resolver.core import rank_discovery_candidates
from kalama.resolver.models import (
    CandidateAmbiguityStatus,
    DiscoveryResult,
    DiscoveryStatus,
    ModuleCandidate,
    ModuleOption,
    ModuleTarget,
    ObservedPort,
    PublishedPort,
    TargetFacts,
)


def module(path, *, rank="normal", check=True, targets=(), options=()):
    return ModuleCandidate(
        module_path=path,
        rank=rank,
        targets=tuple(targets),
        check_supported=check,
        options=tuple(options),
        metadata_source=("live_msfconsole",),
    )


def build(candidates, facts=None, cve_id="CVE-2099-2001"):
    discovery = DiscoveryResult(cve_id, DiscoveryStatus.FOUND, tuple(candidates))
    facts = facts or TargetFacts()
    ranking = rank_discovery_candidates(discovery, facts)
    return discovery, ranking, facts, build_exploit_config(discovery, ranking, facts)


def issue_reasons(config):
    return {issue.reason for issue in validate_exploit_config(config).issues}


class CanonicalExploitConfigTests(unittest.TestCase):
    def test_ambiguous_modules_remain_unresolved(self):
        _, ranking, _, config = build((module("exploit/b"), module("exploit/a")))

        selection = config.invariant.module_selection.module
        self.assertEqual(ranking.ambiguity_status, CandidateAmbiguityStatus.AMBIGUOUS)
        self.assertEqual(selection.suggested_value, "exploit/a")
        self.assertIsNone(selection.value)
        self.assertEqual(selection.confirmation_status, ConfirmationStatus.SUGGESTED)
        self.assertFalse(validate_exploit_config(config).ready)
        self.assertIn(ConfigInputReason.AMBIGUOUS_MODULE, issue_reasons(config))

    def test_clear_winner_is_suggestion_not_confirmation(self):
        _, ranking, _, config = build((
            module("exploit/normal", rank="normal"),
            module("exploit/excellent", rank="excellent"),
        ))

        selection = config.invariant.module_selection.module
        self.assertEqual(ranking.ambiguity_status, CandidateAmbiguityStatus.CLEAR_WINNER)
        self.assertEqual(selection.suggested_value, "exploit/excellent")
        self.assertIsNone(selection.value)
        self.assertEqual(selection.confirmation_status, ConfirmationStatus.SUGGESTED)
        self.assertIn(ConfigInputReason.MODULE_CONFIRMATION_REQUIRED, issue_reasons(config))

    def test_single_candidate_has_automatic_provenance_not_human_confirmation(self):
        _, ranking, _, config = build((module("exploit/only"),))
        selection = config.invariant.module_selection.module

        self.assertEqual(ranking.ambiguity_status, CandidateAmbiguityStatus.SINGLE_CANDIDATE)
        self.assertEqual(selection.value, "exploit/only")
        self.assertEqual(selection.source, FieldSource.SINGLE_CANDIDATE)
        self.assertEqual(selection.confirmation_status, ConfirmationStatus.AUTO_CONFIRMED)
        self.assertNotEqual(selection.confirmation_status, ConfirmationStatus.HUMAN_CONFIRMED)
        self.assertNotIn(ConfigInputReason.AMBIGUOUS_MODULE, issue_reasons(config))

    def test_targeturi_default_is_only_suggested(self):
        targeturi = ModuleOption("TARGETURI", "path", True, "/")
        _, _, _, config = build((module("exploit/http", options=(targeturi,)),))
        field = config.invariant.targeturi

        self.assertEqual(field.suggested_value, "/")
        self.assertIsNone(field.value)
        self.assertEqual(field.source, FieldSource.MODULE_DEFAULT)
        self.assertEqual(field.confirmation_status, ConfirmationStatus.SUGGESTED)
        self.assertIn(ConfigInputReason.TARGETURI_REQUIRED, issue_reasons(config))

    def test_vulhub_struts_rest_route_overrides_generic_module_context(self):
        targeturi = ModuleOption("TARGETURI", "path", True,
                                 "/struts2-rest-showcase/orders/3")
        facts = TargetFacts(image="vulhub/struts2:2.5.12-rest-showcase")
        _, _, _, config = build((module(
            "exploit/multi/http/struts2_rest_xstream", options=(targeturi,)),), facts)
        self.assertEqual(config.invariant.targeturi.suggested_value, "/orders/3")
        self.assertEqual(config.invariant.targeturi.source, FieldSource.TARGET_FACT)
        self.assertFalse(config.invariant.targeturi.confirmed)

    def test_required_unknown_module_option_is_never_dropped(self):
        vhost = ModuleOption("VHOST", "string", True, None)
        _, _, _, config = build((module("exploit/http", options=(vhost,)),))

        self.assertEqual([item.name for item in config.invariant.module_options], ["VHOST"])
        option = config.invariant.module_options[0]
        self.assertTrue(option.required)
        self.assertIsNone(option.field.value)
        validation = validate_exploit_config(config)
        self.assertIn(ConfigInputReason.MODULE_OPTION_REQUIRED, {
            issue.reason for issue in validation.issues
        })

    def test_environment_facts_bind_without_entering_invariant_config(self):
        options = (
            ModuleOption("RHOSTS", "address_range", True, None),
            ModuleOption("RPORT", "port", True, 8080),
        )
        facts = TargetFacts(
            run_id="aB3x9",
            container_name="victim-aB3x9",
            container_id="container-before",
            image="example:vulnerable",
            image_id="sha256:image",
            image_digest="sha256:before",
            network="kalama-net",
            ip_address="172.18.0.3",
            observed_ports=(ObservedPort(8080, service="http"),),
            published_ports=(PublishedPort(8080, 18080),),
            msf_ip="172.18.0.2",
        )
        _, _, _, config = build((module("exploit/http", options=options),), facts)

        self.assertEqual(config.environment.phase, EnvironmentPhase.BEFORE)
        self.assertEqual(config.environment.rhosts.value, "172.18.0.3")
        self.assertEqual(config.environment.rport.value, 8080)
        self.assertEqual(config.environment.lhost.value, "172.18.0.2")
        self.assertEqual(config.environment.network, "kalama-net")
        self.assertTrue(config.environment.rhosts.confirmed)
        self.assertTrue(config.environment.rport.confirmed)
        option_fields = {item.name: item.field for item in config.invariant.module_options}
        self.assertEqual(option_fields["RHOSTS"].source, FieldSource.ENVIRONMENT_BINDING)
        self.assertIsNone(option_fields["RHOSTS"].value)

    def test_multiple_ports_do_not_collapse_to_confirmed_rport(self):
        rport = ModuleOption("RPORT", "port", True, 8080)
        facts = TargetFacts(observed_ports=(ObservedPort(8080), ObservedPort(9200)))
        _, _, _, config = build((module("exploit/http", options=(rport,)),), facts)

        self.assertIsNone(config.environment.rport.value)
        self.assertEqual(config.environment.rport.suggested_value, 8080)
        self.assertEqual(config.environment.rport.confirmation_status, ConfirmationStatus.SUGGESTED)
        self.assertEqual(config.environment.port_binding_source, "ambiguous_target_ports")
        self.assertIn(ConfigInputReason.ENVIRONMENT_RPORT_REQUIRED, issue_reasons(config))

    def test_module_default_without_runtime_support_is_never_confirmed(self):
        rport = ModuleOption("RPORT", "port", True, 80)
        facts = TargetFacts(
            observed_ports=(ObservedPort(1099), ObservedPort(64000)),
            reachable_ports=(ObservedPort(1099), ObservedPort(64000)),
            exposed_ports=(ObservedPort(80),),
        )
        _, ranking, _, config = build((module("exploit/http", options=(rport,)),), facts)
        self.assertIsNone(config.environment.rport.value)
        self.assertIsNone(config.environment.rport.suggested_value)
        self.assertEqual(config.environment.port_binding_source, "ambiguous_target_ports")
        port_evidence = next(x for x in ranking.ranked_candidates[0].evidence
                             if x.reason == "rport_target_match")
        self.assertFalse(port_evidence.matched)
        self.assertIn("no listening/reachable runtime evidence", port_evidence.detail)

    def test_default_target_is_suggested_with_real_index_not_confirmed(self):
        candidate = replace(module("exploit/target", targets=("Automatic", "Linux")),
                            target_details=(ModuleTarget(0, "Automatic"), ModuleTarget(1, "Linux")),
                            default_target_index=0)
        _, _, _, config = build((candidate,))
        target = config.invariant.target_selection
        self.assertEqual(target.default_target_index, 0)
        self.assertEqual(target.target_index.suggested_value, 0)
        self.assertEqual(target.target_name.suggested_value, "Automatic")
        self.assertFalse(target.target_index.confirmed)

    def test_exploit_protocol_requires_payload_but_confirmed_check_only_does_not(self):
        _, _, _, exploit_config = build((module("exploit/no_check", check=False),))
        self.assertTrue(exploit_config.invariant.execution_protocol.run_exploit)
        self.assertIn(ConfigInputReason.PAYLOAD_SELECTION_REQUIRED, issue_reasons(exploit_config))

        _, _, _, check_config = build((module("exploit/check", check=True),))
        confirmed_protocol = replace(
            check_config.invariant.execution_protocol,
            confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED,
        )
        confirmed_invariant = replace(
            check_config.invariant,
            execution_protocol=confirmed_protocol,
        )
        check_config = replace(check_config, invariant=confirmed_invariant)
        reasons = issue_reasons(check_config)
        self.assertNotIn(ConfigInputReason.PAYLOAD_SELECTION_REQUIRED, reasons)
        self.assertTrue(validate_exploit_config(check_config).ready)
        self.assertEqual(validate_exploit_config(check_config).readiness, ConfigReadiness.READY_TO_EXECUTE)

    def test_payload_option_precondition_and_pre_attack_models_validate(self):
        _, _, _, config = build((module("exploit/no_check", check=False),))
        payload_option = ConfigOption(
            "LPORT", "port", True, 4444,
            ExploitValue(required=True, reason="payload option unresolved"),
        )
        payload = PayloadConfiguration(
            payload=ExploitValue(
                value="cmd/unix/reverse",
                source=FieldSource.HUMAN,
                confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED,
                required=True,
            ),
            options=(payload_option,),
        )
        invariant = replace(
            config.invariant,
            payload=payload,
            preconditions=PreconditionConfiguration(required=True),
            pre_attack=PreAttackCommand(required=True),
            execution_protocol=replace(
                config.invariant.execution_protocol,
                confirmation_status=ConfirmationStatus.HUMAN_CONFIRMED,
            ),
        )
        config = replace(config, invariant=invariant)
        reasons = issue_reasons(config)

        self.assertIn(ConfigInputReason.PAYLOAD_OPTION_REQUIRED, reasons)
        self.assertIn(ConfigInputReason.PRECONDITION_REQUIRED, reasons)
        self.assertIn(ConfigInputReason.PRE_ATTACK_REQUIRED, reasons)

    def test_serialization_preserves_invariant_environment_and_lifecycle_semantics(self):
        options = (
            ModuleOption("TARGETURI", "path", True, "/"),
            ModuleOption("RHOSTS", "address_range", True, None),
            ModuleOption("RPORT", "port", True, 8080),
        )
        facts = TargetFacts(
            run_id="aB3x9", container_name="victim-aB3x9", network="kalama-net",
            ip_address="172.18.0.3", observed_ports=(ObservedPort(8080),),
        )
        _, _, _, config = build((module(
            "exploit/http", targets=("Automatic",), options=options,
        ),), facts)
        serialized = config.to_dict()

        self.assertEqual(serialized["invariant"]["targeturi"]["suggested_value"], "/")
        self.assertIsNone(serialized["invariant"]["targeturi"]["value"])
        self.assertEqual(serialized["invariant"]["module_selection"]["module"]["value"], "exploit/http")
        self.assertIn("target_selection", serialized["invariant"])
        self.assertIn("payload", serialized["invariant"])
        self.assertIn("preconditions", serialized["invariant"])
        self.assertIn("pre_attack", serialized["invariant"])
        self.assertIn("execution_protocol", serialized["invariant"])
        self.assertEqual(serialized["environment"]["rhosts"]["value"], "172.18.0.3")
        self.assertEqual(json.dumps(serialized, sort_keys=True), json.dumps(config.to_dict(), sort_keys=True))

    def test_build_is_immutable_and_does_not_mutate_inputs(self):
        candidate = module("exploit/immutable", options=(
            ModuleOption("RPORT", "port", True, 8080),
        ))
        facts = TargetFacts(observed_ports=(ObservedPort(8080),))
        discovery = DiscoveryResult("CVE-2099-2012", DiscoveryStatus.FOUND, (candidate,))
        ranking = rank_discovery_candidates(discovery, facts)
        snapshots = (discovery.to_dict(), ranking.to_dict(), facts.to_dict())

        config = build_exploit_config(discovery, ranking, facts)

        self.assertEqual(snapshots, (discovery.to_dict(), ranking.to_dict(), facts.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            config.readiness = ConfigReadiness.READY_TO_EXECUTE

    def test_no_module_and_discovery_error_remain_distinct(self):
        facts = TargetFacts()
        no_module = DiscoveryResult("CVE-2099-2013", DiscoveryStatus.NO_MSF_MODULE)
        no_ranking = rank_discovery_candidates(no_module, facts)
        no_config = build_exploit_config(no_module, no_ranking, facts)
        self.assertIn(ConfigInputReason.NO_MSF_MODULE, issue_reasons(no_config))

        environment_error = DiscoveryResult(
            "CVE-2099-2014", DiscoveryStatus.ENVIRONMENT_ERROR,
            errors=("msfconsole unavailable",),
        )
        error_ranking = rank_discovery_candidates(environment_error, facts)
        error_config = build_exploit_config(environment_error, error_ranking, facts)
        self.assertIn(ConfigInputReason.DISCOVERY_ERROR, issue_reasons(error_config))


if __name__ == "__main__":
    unittest.main()
