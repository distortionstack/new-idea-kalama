"""Wave 3.1 application-scope (base_path) unit tests — pure contracts.

Covers normalization, rejection, identity, provenance labels, binding
keys, multi-path signal aggregation through the unchanged
``derive_dynamic_signal``, URL validation, and app-bound execution
records. Orchestrator resume/artifact behavior lives in
``test_dynamic_shadow.py`` alongside its fakes.
"""

from __future__ import annotations

import unittest

from kalama.dynamic_probe import (
    DynamicEndpoint,
    HttpApplicationEndpoint,
    TemplatePolicyError,
    normalize_http_base_path,
)
from kalama.dynamic_probe_runtime import (
    BackendResult,
    NucleiRunnerConfig,
    execute_single_template,
    validate_probe_url,
)
from kalama.dynamic_shadow import (
    CLEAN,
    DEFAULT_ROOT_SOURCE,
    INCOMPLETE,
    MATCHED,
    REVIEWED_APP_SOURCE,
    app_path_source,
    binding_key,
    build_application_endpoints,
    derive_dynamic_signal,
    dynamic_config_from_env,
    execution_result_manifest,
    parse_app_paths,
)
from kalama.dynamic_probe import ApprovedTemplate


HELP_TEXT = """Nuclei is a fast, template based vulnerability scanner
FLAGS:
  -duc, -disable-update-check: disable automatic update check
  -dr, -disable-redirects: disable redirects
  -ni, -no-interactsh: disable interactsh server
  -dut, -disable-unsigned-templates: skip unsigned templates
  -jsonl: write output in JSONL format"""


class FakeBackend:
    def __init__(self, payload: bytes, exit_code: int = 0):
        self.payload = payload
        self.exit_code = exit_code
        self.seen: list[tuple] = []

    def run(self, argv, *, timeout=None, stdout_budget=None, stderr_budget=None):
        args = tuple(str(x) for x in argv)
        self.seen.append(args)
        if "-h" in args:
            return BackendResult(args, 0, HELP_TEXT.encode(), b"")
        return BackendResult(args, self.exit_code, self.payload, b"")


def _endpoint() -> DynamicEndpoint:
    return DynamicEndpoint("aB3x9", "victim-id-1", "victim-aB3x9",
                           "kalama-probe-aB3x9-1", "10.0.0.2", 8080,
                           "http", "READY")


class NormalizeTests(unittest.TestCase):
    def test_valid_paths_normalize_deterministically(self):
        self.assertEqual(normalize_http_base_path("/"), "/")
        self.assertEqual(normalize_http_base_path("/S2-045/"), "/S2-045/")
        self.assertEqual(normalize_http_base_path("/S2-045"), "/S2-045/")
        self.assertEqual(normalize_http_base_path("/orders/"), "/orders/")
        self.assertEqual(normalize_http_base_path("//ignored".replace("//ignored", "/a//b/")),
                         "/a/b/")
        self.assertEqual(normalize_http_base_path("  /S2-045/  "), "/S2-045/")

    def test_traversal_rejected(self):
        for bad in ("../../foo", "/../foo", "/a/../../b", "/a/..",
                    "..", "/..%2f", "/a/../"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_http_base_path(bad)

    def test_host_scheme_injection_rejected(self):
        for bad in ("//evil.com", "//evil.com/x", "http://x/", "https://x/y",
                    "javascript:alert(1)", "HTTP://x/", "ftp://x/"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_http_base_path(bad)

    def test_query_fragment_backslash_rejected(self):
        for bad in ("/a?x=1", "/a#frag", "/a?b", "/a\\b", "/a\\"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_http_base_path(bad)

    def test_missing_leading_slash_rejected(self):
        for bad in ("", "S2-045/", "S2-045", "://x"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_http_base_path(bad)


class ApplicationEndpointTests(unittest.TestCase):
    def test_same_scope_different_paths_are_distinct_identities(self):
        endpoint = _endpoint()
        root = HttpApplicationEndpoint(endpoint, "/", "default_root")
        app = HttpApplicationEndpoint(endpoint, "/S2-045/", "explicit_reviewed_binding")
        self.assertNotEqual(root.application_endpoint_key, app.application_endpoint_key)
        self.assertTrue(root.application_endpoint_key.startswith("dynamic-app-endpoint/v1:"))
        # Slash syntax is canonicalized: same scope, same key.
        again = HttpApplicationEndpoint(endpoint, "/S2-045", "explicit_reviewed_binding")
        self.assertEqual(app.application_endpoint_key, again.application_endpoint_key)
        self.assertEqual(app.base_path, "/S2-045/")

    def test_effective_target_url(self):
        app = HttpApplicationEndpoint(_endpoint(), "/S2-045/", "explicit_reviewed_binding")
        self.assertEqual(app.effective_target_url, "http://10.0.0.2:8080/S2-045/")
        root = HttpApplicationEndpoint(_endpoint(), "/", "default_root")
        self.assertEqual(root.effective_target_url, "http://10.0.0.2:8080/")

    def test_source_label_required(self):
        with self.assertRaises(ValueError):
            HttpApplicationEndpoint(_endpoint(), "/", "")
        with self.assertRaises(ValueError):
            HttpApplicationEndpoint(_endpoint(), "/../../x", "s")

    def test_provenance_records_base_path_source(self):
        app = HttpApplicationEndpoint(_endpoint(), "/S2-045/", "explicit_reviewed_binding")
        document = app.to_dict()
        self.assertEqual(document["base_path"], "/S2-045/")
        self.assertEqual(document["base_path_source"], "explicit_reviewed_binding")
        self.assertEqual(document["application_endpoint_key"],
                         app.application_endpoint_key)


class ConfigTests(unittest.TestCase):
    def test_default_is_root_only(self):
        config = dynamic_config_from_env(dynamic_scan="off", nuclei_profile="safe-cve-http",
                                         required=False, env={})
        self.assertEqual(config.app_paths, ("/",))

    def test_reviewed_paths_parsed_root_first_deduped(self):
        config = dynamic_config_from_env(
            dynamic_scan="nuclei", nuclei_profile="safe-cve-http", required=False,
            env={"KALAMA_NUCLEI_APP_PATHS": "/S2-045/,/,/orders"})
        self.assertEqual(config.app_paths, ("/", "/S2-045/", "/orders/"))

    def test_invalid_path_rejected(self):
        with self.assertRaises(ValueError) as caught:
            dynamic_config_from_env(dynamic_scan="nuclei", nuclei_profile="safe-cve-http",
                                    required=False,
                                    env={"KALAMA_NUCLEI_APP_PATHS": "/,/../../x"})
        self.assertIn("DYNAMIC_CONFIG_INVALID", str(caught.exception))

    def test_path_budget_capped(self):
        many = ",".join(f"/app{i}/" for i in range(20))
        with self.assertRaises(ValueError) as caught:
            dynamic_config_from_env(dynamic_scan="nuclei", nuclei_profile="safe-cve-http",
                                    required=False,
                                    env={"KALAMA_NUCLEI_APP_PATHS": many})
        self.assertIn("DYNAMIC_CONFIG_INVALID", str(caught.exception))

    def test_source_labels(self):
        self.assertEqual(app_path_source("/"), DEFAULT_ROOT_SOURCE)
        self.assertEqual(app_path_source("/S2-045/"), REVIEWED_APP_SOURCE)

    def test_build_application_endpoints(self):
        apps = build_application_endpoints(_endpoint(), ("/", "/S2-045/"))
        self.assertEqual([a.base_path for a in apps], ["/", "/S2-045/"])
        self.assertEqual([a.base_path_source for a in apps],
                         [DEFAULT_ROOT_SOURCE, REVIEWED_APP_SOURCE])


class AggregationTests(unittest.TestCase):
    def test_binding_key_defaults_to_root(self):
        self.assertEqual(binding_key("t1", {}), "t1@/")
        self.assertEqual(binding_key("t1", {"base_path": "/S2-045/"}), "t1@/S2-045/")

    def test_one_path_match_corrorborates(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1@/", "t1@/S2-045/"],
            outcomes={"t1@/": CLEAN, "t1@/S2-045/": MATCHED})
        self.assertEqual(signal.value, "CORROBORATED")

    def test_all_paths_clean_not_observed(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1@/", "t1@/S2-045/"],
            outcomes={"t1@/": CLEAN, "t1@/S2-045/": CLEAN})
        self.assertEqual(signal.value, "NOT_OBSERVED")

    def test_one_path_incomplete_is_inconclusive(self):
        signal = derive_dynamic_signal(
            enabled=True, applicable_templates=["t1@/", "t1@/S2-045/"],
            outcomes={"t1@/": CLEAN, "t1@/S2-045/": INCOMPLETE})
        self.assertEqual(signal.value, "INCONCLUSIVE")


class UrlValidationTests(unittest.TestCase):
    def test_app_url_must_match_approved_base_path(self):
        app = HttpApplicationEndpoint(_endpoint(), "/S2-045/", "explicit_reviewed_binding")
        self.assertEqual(validate_probe_url("http://10.0.0.2:8080/S2-045/", app),
                         "http://10.0.0.2:8080/S2-045/")
        with self.assertRaises(TemplatePolicyError):
            validate_probe_url("http://10.0.0.2:8080/", app)
        with self.assertRaises(TemplatePolicyError):
            validate_probe_url("http://10.0.0.2:8080/other/", app)
        with self.assertRaises(TemplatePolicyError):
            validate_probe_url("http://10.0.0.2:8080/S2-045/?x=1", app)

    def test_network_url_still_valid_without_app(self):
        endpoint = _endpoint()
        self.assertEqual(validate_probe_url("http://10.0.0.2:8080/", endpoint),
                         "http://10.0.0.2:8080/")


class AppExecutionTests(unittest.TestCase):
    def _run(self, app: HttpApplicationEndpoint | None):
        import tempfile
        from pathlib import Path
        import hashlib
        from kalama.dynamic_probe_runtime import NucleiRunnerConfig
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            template = ("id: x\ninfo:\n  name: x\n  severity: high\n  tags: cve\n"
                        "http:\n  - method: GET\n    path: ['{{BaseURL}}/']\n"
                        "    matchers: [{type: word, words: ['x']}]\n")
            (root / "t.yaml").write_bytes(template.encode("utf-8"))
            sha = hashlib.sha256(template.encode()).hexdigest()
            approved = ApprovedTemplate("t", "t.yaml", sha, ("CVE-2017-5638",))
            backend = FakeBackend(b"")
            result = execute_single_template(
                NucleiRunnerConfig(binary_path="nuclei", template_root=root),
                endpoint=_endpoint(), approved=approved,
                candidate_cve="CVE-2017-5638", run_id="aB3x9", attempt=1,
                backend=backend, reachability=lambda endpoint: True,
                app_endpoint=app)
            urls = [args[i + 1] for args in backend.seen
                    for i, token in enumerate(args)
                    if token == "-u" and i + 1 < len(args)]
            return result, urls

    def test_app_binding_sets_target_and_provenance(self):
        app = HttpApplicationEndpoint(_endpoint(), "/S2-045/", "explicit_reviewed_binding")
        result, urls = self._run(app)
        self.assertIn("http://10.0.0.2:8080/S2-045/", urls)
        self.assertEqual(result.base_path, "/S2-045/")
        self.assertEqual(result.base_path_source, "explicit_reviewed_binding")
        self.assertEqual(result.application_endpoint_key, app.application_endpoint_key)
        self.assertEqual(result.effective_target_url, "http://10.0.0.2:8080/S2-045/")
        document = execution_result_manifest(result, provenance={})
        self.assertEqual(document["base_path"], "/S2-045/")
        self.assertEqual(document["effective_target_url"],
                         "http://10.0.0.2:8080/S2-045/")

    def test_root_default_preserves_legacy_behavior(self):
        result, urls = self._run(None)
        self.assertIn("http://10.0.0.2:8080/", urls)
        self.assertEqual(result.base_path, "/")
        self.assertIsNone(result.application_endpoint_key)
        self.assertIsNone(result.effective_target_url)


if __name__ == "__main__":
    unittest.main()
