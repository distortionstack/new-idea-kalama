import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from kalama.metasploit_fixtures import (
    FixtureConfigurationError,
    build_registry,
    registry_from_env,
)


MODULE_TEXT = "class MetasploitModule < Msf::Exploit::Remote\nend\n"


class MetasploitFixtureRegistryTests(unittest.TestCase):
    def write_module(self, root: Path, rel: str = "exploits/test/example.rb",
                     text: str = MODULE_TEXT) -> Path:
        path = root / rel
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_registry_is_disabled_by_default(self):
        registry = registry_from_env({})
        self.assertFalse(registry.enabled)
        self.assertEqual(registry.modules, {})

    def test_valid_fixture_path_discovers_module_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "modules"
            module = self.write_module(root)
            (root.parent / "manifest.json").write_text(
                json.dumps({"id": "cve-2099-fixture", "version": "1"}), encoding="utf-8")

            registry = build_registry([root])
            discovered = registry.require_module(
                "exploit/test/example", hashlib.sha256(module.read_bytes()).hexdigest())
            provenance = discovered.provenance()

        self.assertTrue(registry.enabled)
        self.assertEqual(discovered.fullname, "exploit/test/example")
        self.assertEqual(provenance["module_source"], "lab_fixture")
        self.assertEqual(provenance["fixture_manifest"]["id"], "cve-2099-fixture")
        self.assertTrue(provenance["loaded_module_path"].endswith(
            "/modules/exploits/test/example.rb"))

    def test_missing_or_empty_fixture_path_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            with self.assertRaisesRegex(FixtureConfigurationError, "not a directory"):
                build_registry([missing])
            empty = Path(tmp) / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(FixtureConfigurationError, "contains no modules"):
                build_registry([empty])

    def test_registry_from_env_uses_platform_path_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first"
            second = Path(tmp) / "second"
            self.write_module(first, "exploits/test/one.rb")
            self.write_module(second, "auxiliary/test/two.rb")
            raw = os.pathsep.join((str(first), str(second)))

            registry = registry_from_env({"KALAMA_MSF_MODULE_PATHS": raw})

        self.assertEqual(set(registry.modules), {"exploit/test/one", "auxiliary/test/two"})

    def test_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "modules"
            self.write_module(root)
            registry = build_registry([root])
            module = registry.require_module("exploit/test/example", None)
            Path(module.source_path).write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(FixtureConfigurationError, "changed after registry"):
                registry.require_module("exploit/test/example", module.sha256)


if __name__ == "__main__":
    unittest.main()
