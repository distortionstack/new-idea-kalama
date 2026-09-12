import unittest
from unittest.mock import patch

from kalama.resolver import backend


class ResolverBackendTimeoutTests(unittest.TestCase):
    def test_positive_timeout_rejects_expired_deadline_before_subprocess(self):
        with self.assertRaisesRegex(RuntimeError, "deadline expired before subprocess invocation"):
            backend._positive_timeout(-1, operation="payload introspection")

        with self.assertRaisesRegex(RuntimeError, "deadline expired before subprocess invocation"):
            backend._positive_timeout(0, operation="payload introspection")

    def test_payload_introspection_never_passes_negative_timeout_to_msfconsole(self):
        observed_timeouts = []

        def fake_run(argv, **kwargs):
            observed_timeouts.append(kwargs.get("timeout"))
            class Result:
                returncode = 0
                stdout = (
                    backend.JSON_SENTINEL_START
                    + '{"options":[]}'
                    + backend.JSON_SENTINEL_END
                )
                stderr = ""
            return Result()

        with patch.object(backend, "MSF_TIMEOUT_SECONDS", 12), \
                patch.object(backend, "ensure_container_running"), \
                patch.object(backend, "get_msfconsole_binary", return_value="/msfconsole"), \
                patch.object(backend.subprocess, "run", side_effect=fake_run):
            backend.introspect_msf_payload("exploit/a", "generic/shell_reverse_tcp", "msf")

        self.assertIn(12.0, observed_timeouts)
        self.assertTrue(all(value is None or value > 0 for value in observed_timeouts))


if __name__ == "__main__":
    unittest.main()
