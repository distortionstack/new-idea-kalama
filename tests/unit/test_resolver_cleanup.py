import subprocess
import unittest
from unittest.mock import patch

from kalama.resolver import backend


class ResolverCleanupTests(unittest.TestCase):
    def test_module_query_timeout_terminates_only_operation_process(self):
        calls = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            if len(calls) == 1:  # write resource script
                return Result()
            if len(calls) == 2:  # msfconsole operation
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return Result()  # TERM/KILL cleanup and script removal

        with patch.object(backend, "MSF_TIMEOUT_SECONDS", 0.1), \
                patch.object(backend, "ensure_container_running"), \
                patch.object(backend, "get_msfconsole_binary", return_value="/msfconsole"), \
                patch.object(backend.subprocess, "run", side_effect=fake_run), \
                patch.object(backend.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "timed out after 0.1s"):
                backend.query_msfconsole_for_modules(["exploit/test"], "msf")

        cleanup_commands = [" ".join(call[0]) for call in calls[2:4]]
        self.assertTrue(any("pkill -TERM" in command for command in cleanup_commands))
        self.assertTrue(any("pkill -KILL" in command for command in cleanup_commands))
        self.assertTrue(all("exploit/test" in command or "kalama_resolver_script" in command
                            for command in cleanup_commands))

    def test_module_query_interrupt_cleans_up_before_propagating_failure(self):
        calls = []

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(argv, **kwargs):
            calls.append((tuple(argv), kwargs))
            if len(calls) == 1:
                return Result()
            if len(calls) == 2:
                raise KeyboardInterrupt()
            return Result()

        with patch.object(backend, "ensure_container_running"), \
                patch.object(backend, "get_msfconsole_binary", return_value="/msfconsole"), \
                patch.object(backend.subprocess, "run", side_effect=fake_run), \
                patch.object(backend.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "interrupted while extracting"):
                backend.query_msfconsole_for_modules(["exploit/test"], "msf")

        cleanup_commands = [" ".join(call[0]) for call in calls[2:4]]
        self.assertTrue(any("pkill -TERM" in command for command in cleanup_commands))
        self.assertTrue(any("pkill -KILL" in command for command in cleanup_commands))


if __name__ == "__main__":
    unittest.main()
