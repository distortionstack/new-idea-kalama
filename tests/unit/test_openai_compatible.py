from __future__ import annotations

import json
import unittest
from urllib.error import HTTPError

from kalama.guidance.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleProvider


class OpenAICompatibleProviderTests(unittest.TestCase):
    def test_uses_chat_completions_shape_and_parses_json_content(self):
        requests: list[dict] = []
        proposal = {"schema": "kalama.llm-proposal/v1", "proposals": {}}

        def transport(body: bytes) -> bytes:
            requests.append(json.loads(body))
            return json.dumps({"choices": [{"message": {"content": json.dumps(proposal)}}]}).encode()

        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig("https://provider.example/v1", "test-model", "not-a-real-key"),
            transport=transport, monotonic=iter((2.0, 2.25)).__next__)
        actual, elapsed = provider.propose({"allowed_proposal_fields": []}, "digest")

        self.assertEqual(actual, proposal)
        self.assertAlmostEqual(elapsed, 0.25)
        self.assertEqual(requests[0]["model"], "test-model")
        self.assertEqual(requests[0]["response_format"]["type"], "json_schema")
        self.assertEqual(requests[0]["response_format"]["json_schema"]["name"], "kalama_guidance")
        self.assertEqual(requests[0]["temperature"], 0)

    def test_compacts_prompt_and_retries_length_with_larger_budget(self):
        requests: list[dict] = []
        proposal = {"schema": "kalama.llm-proposal/v1", "proposals": {}}

        def transport(body: bytes) -> bytes:
            requests.append(json.loads(body))
            if len(requests) == 1:
                return b'{"choices":[{"finish_reason":"length","message":{"content":"{}"}}],"usage":{"completion_tokens":384}}'
            return json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(proposal)}}],
                               "usage": {"completion_tokens": 12}}).encode()

        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig("https://provider.example/v1", "test-model", "not-a-real-key",
                                   max_tokens=384, max_tokens_limit=768), transport=transport)
        actual, _ = provider.propose({
            "run_id": "run", "cve_id": "CVE-1", "allowed_proposal_fields": ["targeturi"],
            "metasploit": {"selected_module": "auxiliary/test"},
            "resolver": {}, "field_evidence_pack": {"items": [{"facts": {"targeturi": "/"},
                                                                      "source_kind": "MSF_METADATA"}]},
            "large_unused": "x" * 10000,
        }, "digest")
        self.assertEqual(actual, proposal)
        self.assertEqual([item["max_tokens"] for item in requests], [384, 768])
        sent = json.loads(requests[0]["messages"][1]["content"])
        self.assertNotIn("large_unused", sent)
        self.assertEqual(sent["module"]["selected_module"], "auxiliary/test")
        self.assertEqual(provider.last_call_metadata["finish_reason"], "stop")

    def test_retries_transient_http_error(self):
        calls = 0
        proposal = {"schema": "kalama.llm-proposal/v1", "proposals": {}}
        def transport(_: bytes) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise HTTPError("https://provider.example", 503, "unavailable", None, None)
            return json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(proposal)}}]}).encode()
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig("https://provider.example/v1", "test-model", "not-a-real-key",
                                   retry_backoff_seconds=0), transport=transport)
        self.assertEqual(provider.propose({}, "digest")[0], proposal)
        self.assertEqual(calls, 2)

    def test_rejects_non_json_response_content(self):
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig("https://provider.example/v1", "test-model", "not-a-real-key"),
            transport=lambda _: b'{"choices":[{"message":{"content":"not json"}}]}')
        with self.assertRaises(json.JSONDecodeError):
            provider.propose({}, "digest")


if __name__ == "__main__":
    unittest.main()
