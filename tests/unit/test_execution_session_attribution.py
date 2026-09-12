import unittest

from kalama.execution.attempt import _attribute_sessions
from kalama.execution.executor import DockerMetasploitExecutor
from kalama.execution.models import ExecutionPlan, SessionCollectionStatus, SessionEvidence


class SessionAttributionUnitTests(unittest.TestCase):
    def plan(self):
        return ExecutionPlan(
            cve_id="CVE-2099-0001", rank=1, module="exploit/a", target_index=0,
            target_name="target", module_options=(), payload="payload/a",
            payload_options=(), run_check=True, run_exploit=True,
            session_confirmation_expected=True, precondition_commands=(),
            precondition_target=None, precondition_required=False,
            pre_attack_command=None, pre_attack_target=None)

    def evidence(self, ids, details):
        return SessionEvidence(SessionCollectionStatus.COLLECTED, post_ids=tuple(ids),
                               session_details=tuple(
                                   (sid, tuple(sorted(meta.items())))
                                   for sid, meta in details.items()))

    def test_new_session_with_matching_peer_and_module_is_attributable(self):
        result = _attribute_sessions(
            baseline=self.evidence(("1",), {}),
            post=self.evidence(("1", "2"), {"2": {"tunnel_peer": "10.0.0.5:4444",
                                                     "via_exploit": "exploit/a"}}),
            plan=self.plan(), target_facts={"ip_address": "10.0.0.5",
                                            "container_name": "victim"})
        self.assertEqual(result.attribution, "TARGET_MATCH")
        self.assertEqual(result.attributable_ids, ("2",))
        self.assertEqual(result.mismatched_ids, ())

    def test_peer_mismatch_is_not_attributable(self):
        result = _attribute_sessions(
            baseline=self.evidence((), {}),
            post=self.evidence(("2",), {"2": {"tunnel_peer": "10.0.0.9:4444",
                                                "via_exploit": "exploit/a"}}),
            plan=self.plan(), target_facts={"ip_address": "10.0.0.5"})
        self.assertEqual(result.attribution, "MISMATCH")
        self.assertEqual(result.attributable_ids, ())
        self.assertEqual(result.mismatched_ids, ("2",))

    def test_session_list_parser_keeps_peer_and_raw_line(self):
        stdout = """
Active sessions
===============

  Id  Name  Type                   Information  Connection
  --  ----  ----                   -----------  ----------
  7         meterpreter java/linux  user @ host  172.19.0.3:45555 -> 172.19.0.2:45278 (172.19.0.2)
"""
        details = dict(DockerMetasploitExecutor._parse_session_details(stdout))
        self.assertIn("7", details)
        values = dict(details["7"])
        self.assertEqual(values["tunnel_local"], "172.19.0.3:45555")
        self.assertEqual(values["tunnel_peer"], "172.19.0.2:45278")
        self.assertIn("meterpreter", values["raw_line"])


if __name__ == "__main__":
    unittest.main()
