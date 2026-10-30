from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kalama.desktop.application import RuntimeDesktopApplication
from kalama.config import LLMConfig
from kalama.runtime import ProductionRuntime


class _Runtime:
    def __init__(self):
        self.config = "unchanged"

    def configure_llm(self, config):
        self.config = config


class DesktopLLMSettingsTests(unittest.TestCase):
    def test_session_configuration_is_not_returned_with_the_secret(self):
        runtime = _Runtime()
        with tempfile.TemporaryDirectory() as directory:
            app = RuntimeDesktopApplication(Path(directory), runtime=runtime)
            result = app.configure_llm({
                "provider": "openai-compatible",
                "base_url": "https://provider.example/v1",
                "model": "provider-model",
                "api_key": "not-a-real-key",
            })
        self.assertTrue(result["enabled"])
        self.assertNotIn("api_key", result)
        self.assertEqual(runtime.config.api_key, "not-a-real-key")

    def test_disabling_clears_the_session_configuration(self):
        runtime = _Runtime()
        with tempfile.TemporaryDirectory() as directory:
            app = RuntimeDesktopApplication(Path(directory), runtime=runtime)
            app.disable_llm()
        self.assertIsNone(runtime.config)

    def test_runtime_selects_the_openai_compatible_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = ProductionRuntime(Path(directory))
            runtime.configure_llm(LLMConfig(
                True, "openai-compatible", "provider-model",
                "https://provider.example/v1", "not-a-real-key"))
            service = runtime._guidance_service()
        self.assertIsNotNone(service)
        self.assertEqual(service.provider.name, "openai-compatible")


if __name__ == "__main__":
    unittest.main()
