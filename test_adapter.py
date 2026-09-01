import tempfile
import unittest
from pathlib import Path

import yaml

import adapter


class AdapterTests(unittest.TestCase):
    def test_convert_preserves_resolver_values_and_marks_gaps(self):
        item = adapter.convert({
            "cve_id": "CVE-2099-0001",
            "module": "multi/http/example",
            "params": {"RHOSTS": "{target_ip}", "PAYLOAD": "cmd/unix/generic"},
            "check_supported": True,
        }, None)
        self.assertEqual(item.output["exploit"]["module"], "multi/http/example")
        self.assertEqual(item.output["exploit"]["params"]["RHOSTS"], "{target_ip}")
        self.assertEqual(item.output["oracle"]["verdict_source"], "msf_check")
        self.assertIn("deployment", item.manual)
        self.assertIn("wait_seconds", item.manual)
        self.assertTrue(adapter.validate_shape(item))

    def test_verified_project_deployment_is_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cve_meta").mkdir()
            (root / "attack" / "known").mkdir(parents=True)
            (root / "cve_meta" / "CVE-2099-0002.yaml").write_text(yaml.safe_dump({
                "affected": [{"version_ranges": [{"verified": True, "attack_strategy": "known"}]}]
            }))
            (root / "attack" / "known" / "CVE-2099-0002.yaml").write_text(yaml.safe_dump({
                "deployment": {"mode": "single_image"}
            }))
            item = adapter.convert({
                "cve_id": "CVE-2099-0002", "module": "x/y", "params": {}
            }, root)
            self.assertEqual(item.output["deployment"], {"mode": "single_image"})
            self.assertNotIn("deployment", item.manual)
            self.assertEqual(adapter.validate_shape(item), [])

    def test_invalid_resolved_input_is_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.convert({"cve_id": "CVE-2099-0003", "params": {}}, None)

    def test_false_check_support_requires_manual_oracle(self):
        item = adapter.convert({
            "cve_id": "CVE-2099-0004",
            "module": "multi/http/example",
            "params": {},
            "check_supported": False,
        }, None)
        self.assertIsNone(item.output["oracle"]["verdict_source"])
        self.assertIn("oracle.verdict_source", item.manual)


if __name__ == "__main__":
    unittest.main()
