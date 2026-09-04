from pathlib import Path
import unittest


class BootstrapScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = Path("setup-workbench.sh").read_text(encoding="utf-8")

    def test_strict_shell_and_conditional_creation(self):
        self.assertIn("set -euo pipefail", self.text)
        self.assertIn('docker network inspect "${network_name}"', self.text)
        self.assertIn('docker network create', self.text)
        self.assertIn('docker container inspect "${container_name}"', self.text)
        self.assertIn('docker run -d', self.text)

    def test_no_destructive_cleanup(self):
        for forbidden in ("docker system prune", "docker rm", "docker rmi", "eval "):
            self.assertNotIn(forbidden, self.text)

    def test_conflicting_container_fails(self):
        self.assertIn("MSF_RESOLVER_CONTAINER_CONFLICT", self.text)
        self.assertIn("WORKBENCH_CONTAINER_CONFLICT", self.text)

    def test_workbench_scanner_architecture(self):
        self.assertIn('KALAMA_WORKBENCH_NAME:-kalama-workbench-modern', self.text)
        self.assertIn('source=/var/run/docker.sock,target=/var/run/docker.sock', self.text)
        self.assertIn('--label kalama.role=workbench', self.text)
        self.assertIn('docker exec "${workbench_name}" trivy --version', self.text)
        self.assertIn("sha256sum -c", self.text)
        self.assertIn("TRIVY_CHECKSUM_MISMATCH", self.text)

    def test_host_trivy_is_not_required(self):
        self.assertNotIn("command -v trivy", self.text.split("docker exec -e", 1)[0])

    def test_legacy_name_is_never_inspected_or_modified(self):
        self.assertNotIn('workbench_name="kalama-workbench"', self.text)
        self.assertNotIn('docker start kalama-workbench\n', self.text)
        self.assertNotIn('docker rm kalama-workbench', self.text)


if __name__ == "__main__":
    unittest.main()
