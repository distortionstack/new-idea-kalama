import json
import unittest

from resolver_core import rank_discovery_candidates, rank_module_candidates
from resolver_models import (
    CandidateAmbiguityStatus,
    DiscoveryResult,
    DiscoveryStatus,
    ModuleCandidate,
    ModuleOption,
    ObservedPort,
    PublishedPort,
    TargetFacts,
)


def candidate(path, *, rank="normal", check=False, rport=None, live=True):
    options = () if rport is None else (
        ModuleOption("RPORT", "port", True, rport),
    )
    return ModuleCandidate(
        module_path=path,
        rank=rank,
        check_supported=check,
        options=options,
        metadata_source=("live_msfconsole",) if live else ("cache.json",),
    )


def evidence_for(ranked_candidate, reason):
    return next(item for item in ranked_candidate.evidence if item.reason == reason)


class ResolverCandidateRankingTests(unittest.TestCase):
    def test_single_candidate(self):
        only = candidate("exploit/only", rank="excellent")
        result = rank_module_candidates("CVE-2099-1001", (only,), TargetFacts())

        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.SINGLE_CANDIDATE)
        self.assertEqual(result.ranked_candidates[0].candidate, only)
        self.assertIsNone(result.top_candidate_gap)

    def test_metasploit_rank_orders_candidates_and_explains_weight(self):
        normal = candidate("exploit/normal", rank="normal")
        excellent = candidate("exploit/excellent", rank="excellent")
        result = rank_module_candidates(
            "CVE-2099-1002", (normal, excellent), TargetFacts(),
        )

        self.assertEqual(result.ranked_candidates[0].candidate, excellent)
        rank_evidence = evidence_for(result.ranked_candidates[0], "metasploit_rank")
        self.assertEqual((rank_evidence.detail, rank_evidence.weight), ("excellent", 6))
        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.CLEAR_WINNER)

    def test_check_support_is_a_moderate_positive_signal(self):
        no_check = candidate("exploit/no_check")
        with_check = candidate("exploit/with_check", check=True)
        result = rank_module_candidates(
            "CVE-2099-1003", (no_check, with_check), TargetFacts(),
        )

        self.assertEqual(result.ranked_candidates[0].candidate, with_check)
        check_evidence = evidence_for(result.ranked_candidates[0], "check_supported")
        self.assertTrue(check_evidence.matched)
        self.assertEqual(check_evidence.weight, 2)
        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.CLEAR_WINNER)

    def test_observed_rport_match_is_positive_evidence(self):
        elasticsearch = candidate("exploit/elasticsearch", rport=9200)
        web = candidate("exploit/web", rport="8080")
        facts = TargetFacts(observed_ports=(ObservedPort(8080, service="http"),))
        result = rank_module_candidates(
            "CVE-2099-1004", (elasticsearch, web), facts,
        )

        self.assertEqual(result.ranked_candidates[0].candidate, web)
        port_evidence = evidence_for(result.ranked_candidates[0], "rport_target_match")
        self.assertTrue(port_evidence.matched)
        self.assertEqual(port_evidence.weight, 2)
        self.assertIn("8080", port_evidence.detail)

    def test_multiple_plausible_ports_remain_ambiguous(self):
        # Even a structural rank advantage must not erase the fact that each
        # module aligns with a different live service and either may be the
        # CVE-relevant endpoint.
        port_8080 = candidate("exploit/web", rank="excellent", rport=8080)
        port_9200 = candidate("exploit/search", rank="normal", rport=9200)
        facts = TargetFacts(
            observed_ports=(ObservedPort(8080), ObservedPort(9200)),
            published_ports=(
                PublishedPort(container_port=8080, host_port=18080),
                PublishedPort(container_port=9200, host_port=19200),
            ),
        )
        result = rank_module_candidates(
            "CVE-2099-1005", (port_8080, port_9200), facts,
        )

        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.AMBIGUOUS)
        self.assertEqual(result.top_candidate_gap, 3)
        self.assertEqual(
            {item.candidate for item in result.ranked_candidates},
            {port_8080, port_9200},
        )
        self.assertTrue(all(
            evidence_for(item, "rport_target_match").matched
            for item in result.ranked_candidates
        ))

    def test_exact_tie_is_deterministic_but_ambiguous(self):
        zulu = candidate("exploit/zulu")
        alpha = candidate("exploit/alpha")
        result = rank_module_candidates(
            "CVE-2099-1006", (zulu, alpha), TargetFacts(),
        )

        self.assertEqual(
            [item.candidate.module_path for item in result.ranked_candidates],
            ["exploit/alpha", "exploit/zulu"],
        )
        self.assertEqual([item.rank_position for item in result.ranked_candidates], [1, 1])
        self.assertEqual(result.top_candidate_gap, 0)
        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.AMBIGUOUS)

    def test_unknown_rank_and_incomplete_metadata_do_not_crash(self):
        incomplete = candidate("exploit/incomplete", rank="future-rank", live=False)
        result = rank_module_candidates(
            "CVE-2099-1007", (incomplete,), TargetFacts(),
        )

        rank_evidence = evidence_for(result.ranked_candidates[0], "metasploit_rank")
        live_evidence = evidence_for(result.ranked_candidates[0], "live_introspection")
        self.assertFalse(rank_evidence.matched)
        self.assertEqual(rank_evidence.weight, 0)
        self.assertEqual(rank_evidence.detail, "future-rank")
        self.assertFalse(live_evidence.matched)

    def test_ranking_preserves_discovery_and_does_not_select(self):
        first = candidate("exploit/first", rank="normal")
        second = candidate("exploit/second", rank="excellent")
        discovery = DiscoveryResult(
            "CVE-2099-1008", DiscoveryStatus.FOUND, (first, second),
        )
        before = discovery.to_dict()
        result = rank_discovery_candidates(discovery, TargetFacts())

        self.assertEqual(discovery.to_dict(), before)
        self.assertEqual(discovery.candidates, (first, second))
        self.assertEqual(len(result.ranked_candidates), 2)
        self.assertNotIn("selected_module", result.to_dict())
        self.assertNotIn("confirmed_module", result.to_dict())
        json.dumps(result.to_dict(), sort_keys=True)

    def test_one_point_lead_is_still_ambiguous(self):
        live = candidate("exploit/live", live=True)
        cached = candidate("exploit/cached", live=False)
        result = rank_module_candidates(
            "CVE-2099-1009", (cached, live), TargetFacts(),
        )

        self.assertEqual(result.top_candidate_gap, 1)
        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.AMBIGUOUS)

    def test_no_candidates_has_explicit_status(self):
        result = rank_module_candidates("CVE-2099-1010", (), TargetFacts())

        self.assertEqual(result.ambiguity_status, CandidateAmbiguityStatus.NO_CANDIDATES)
        self.assertEqual(result.ranked_candidates, ())


if __name__ == "__main__":
    unittest.main()
