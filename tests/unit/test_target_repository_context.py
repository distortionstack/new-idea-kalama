from __future__ import annotations

import io
import json
import tarfile
import unittest

from kalama.remediation.discovery.contracts import RepositoryContextStatus
from kalama.remediation.discovery.codec import artifact_to_dict, repository_context_from_dict
from kalama.remediation.discovery.repository_context import (
    RepositoryContextResolver, parse_apk_installed, parse_dpkg_status,
)
from kalama.remediation.discovery.target_filesystem import TargetFilesystemReader
from kalama.remediation.discovery.service import RemediationDiscoveryService


class TrackingBytesIO(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.bytes_read = 0

    def read(self, size=-1):
        value = super().read(size)
        self.bytes_read += len(value)
        return value


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = TrackingBytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.expected_returncode = returncode
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self.expected_returncode
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.terminated = True
        self.returncode = -9


def tar_stream(path, value):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        if isinstance(value, dict):
            root = tarfile.TarInfo(path.lstrip("/"))
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            for name, content in value.items():
                item = tarfile.TarInfo(f"{path.lstrip('/')}/{name}")
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
        elif isinstance(value, tuple):
            item = tarfile.TarInfo(path.lstrip("/"))
            item.type = {"symlink": tarfile.SYMTYPE,
                         "hardlink": tarfile.LNKTYPE,
                         "fifo": tarfile.FIFOTYPE}[value[0]]
            item.linkname = value[1]
            archive.addfile(item)
        else:
            item = tarfile.TarInfo(path.lstrip("/"))
            item.size = len(value)
            archive.addfile(item, io.BytesIO(value))
    return output.getvalue()


class StreamingRunner:
    def __init__(self, files=None, errors=None):
        self.files = files or {}
        self.errors = errors or {}
        self.calls = []
        self.processes = []

    def popen(self, argv):
        self.calls.append(tuple(argv))
        source = argv[-2]
        path = source.split(":", 1)[1]
        if path in self.errors:
            code, stderr = self.errors[path]
            process = FakeProcess(stderr=stderr, returncode=code)
            self.processes.append(process)
            return process
        value = self.files.get(path)
        process = (FakeProcess(tar_stream(path, value)) if value is not None
                   else FakeProcess(stderr=b"no such file", returncode=1))
        self.processes.append(process)
        return process


class TargetFilesystemReaderTests(unittest.TestCase):
    def test_fixed_docker_cp_argv_digest_bounds_and_cleanup(self):
        runner = StreamingRunner({"/etc/os-release": b"ID=debian\n"})
        reader = TargetFilesystemReader(runner, "victim-X")
        result = reader.read_file("/etc/os-release", 1024)
        self.assertEqual(result.status, "READ")
        self.assertEqual(result.content, b"ID=debian\n")
        self.assertEqual(len(result.sha256), 64)
        argv = runner.calls[0]
        self.assertEqual(argv[:3], ("docker", "cp", "victim-X:/etc/os-release"))
        self.assertEqual(argv[-1], "-")

        too_large = reader.read_file("/etc/os-release", 2)
        self.assertEqual(too_large.status, "TOO_LARGE")
        self.assertIsNone(too_large.content)
        process = runner.processes[-1]
        self.assertTrue(process.terminated)
        self.assertLess(process.stdout.bytes_read,
                        len(tar_stream("/etc/os-release", b"ID=debian\n")))

    def test_path_traversal_symlink_and_unavailable_target_are_rejected(self):
        reader = TargetFilesystemReader(StreamingRunner(), "victim-X")
        with self.assertRaises(ValueError):
            reader.read_file("/etc/../etc/passwd", 10)
        with self.assertRaises(ValueError):
            reader.read_file("/etc/passwd", 10)
        self.assertEqual(
            TargetFilesystemReader(None, None).read_file(
                "/etc/os-release", 10).status,
            "TARGET_UNAVAILABLE",
        )
        for member_type in ("symlink", "hardlink", "fifo"):
            with self.subTest(member_type=member_type):
                reader = TargetFilesystemReader(StreamingRunner({
                    "/etc/os-release": (member_type, "/etc/passwd")}), "victim-X")
                self.assertEqual(reader.read_file(
                    "/etc/os-release", 1024).status, "UNREADABLE")

    def test_directory_suffix_file_count_and_total_size_are_bounded(self):
        runner = StreamingRunner({"/etc/apt/sources.list.d": {
            "a.list": b"deb https://a.test stable main\n",
            "b.sources": b"URIs: https://b.test\nSuites: stable\n",
            "ignored.conf": b"secret",
        }})
        reader = TargetFilesystemReader(runner, "victim-X")
        results = reader.read_directory(
            "/etc/apt/sources.list.d", (".list", ".sources"), 1, 1024)
        self.assertEqual(results[0].status, "TOO_LARGE")
        results = reader.read_directory(
            "/etc/apt/sources.list.d", (".list", ".sources"), 2, 1024)
        self.assertEqual([x.path for x in results],
                         ["/etc/apt/sources.list.d/a.list",
                          "/etc/apt/sources.list.d/b.sources"])

    def test_docker_errors_are_classified_without_echoing_stderr(self):
        cases = (
            (b"no such file or directory: secret", "MISSING"),
            (b"Could not find the file /x in container abc: secret", "MISSING"),
            (b"permission denied: secret", "UNREADABLE"),
            (b"no such container: secret", "TARGET_UNAVAILABLE"),
            (b"unexpected docker failure: secret", "UNREADABLE"),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected):
                runner = StreamingRunner(errors={"/etc/os-release": (1, stderr)})
                result = TargetFilesystemReader(
                    runner, "victim-X").read_file("/etc/os-release", 1024)
                self.assertEqual(result.status, expected)
                self.assertNotIn("secret", repr(result))
                self.assertNotIn("secret", json.dumps(result.__dict__, sort_keys=True))

        runner = StreamingRunner(errors={
            "/etc/os-release": (
                1, b"Could not find the file /secret in container abc: secret-sentinel"),
        })
        results = RemediationDiscoveryService(
            runner=runner, container_name="victim-X").discover_unified([], [{
                "canonical_cve_id": "CVE-1", "package_uid": "npm:name",
                "package_name": "name", "package_purl": "pkg:npm/name@1.0.0",
                "installed_version": "1.0.0", "fixed_versions": ["1.1.0"],
                "result_class": "lang-pkgs", "result_type": "npm",
            }], {"distro": "debian", "release": "12", "architecture": "amd64"})
        encoded = json.dumps(artifact_to_dict("docker-error-test", results), sort_keys=True)
        self.assertNotIn("secret-sentinel", encoded)
        self.assertNotIn("/secret", encoded)


class PackageMetadataParserTests(unittest.TestCase):
    def test_dpkg_installed_source_forms_and_binary_rebuilds(self):
        mappings = parse_dpkg_status(b"""
Package: binary-one
Status: install ok installed
Version: 1.2-3+b2
Architecture: amd64
Source: source-one (1.2-3)

Package: binary-two
Status: install ok installed
Version: 2.0-1+b1
Architecture: amd64
Source: source-two

Package: binary-three
Status: install ok installed
Version: 3.0-1+b2
Architecture: amd64

Package: binary-four
Status: install ok installed
Version: 2:4.0-1
Architecture: amd64
Source: source-four

Package: ignored
Status: deinstall ok config-files
Version: 9
""", "fixture:dpkg-status")
        self.assertEqual(
            [(x.binary_name, x.source_name, x.source_version) for x in mappings],
            [("binary-one", "source-one", "1.2-3"),
             ("binary-two", "source-two", None),
             ("binary-three", "binary-three", None),
             ("binary-four", "source-four", "2:4.0-1")],
        )
        self.assertTrue(all(x.provenance == "fixture:dpkg-status" for x in mappings))

    def test_apk_mapping(self):
        mappings = parse_apk_installed(
            b"P:libssl3\nV:3.1.4-r2\nA:x86_64\no:openssl\n\n",
            "fixture:apk-installed",
        )
        self.assertEqual((mappings[0].binary_name, mappings[0].source_name),
                         ("libssl3", "openssl"))

    def test_debian_context_is_partial_and_provenance_backed(self):
        runner = StreamingRunner({
            "/etc/os-release": b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n",
            "/var/lib/dpkg/status": (
                b"Package: curl\nStatus: install ok installed\n"
                b"Version: 7.0-1+b1\nArchitecture: amd64\n\n"),
            "/etc/apt/sources.list": b"deb https://deb.test bookworm main\n",
            "/etc/apt/sources.list.d": {},
        })
        context = RepositoryContextResolver(
            TargetFilesystemReader(runner, "victim-X")).resolve()
        self.assertEqual(context.status, RepositoryContextStatus.COMPLETE)
        self.assertEqual(context.architecture, "amd64")
        self.assertIn("/var/lib/dpkg/status", context.architecture_provenance)
        self.assertIsNone(context.installed_source_mappings[0].source_version)
        self.assertEqual(context.configured_repositories[0].url, "https://deb.test")

    def test_malformed_package_databases_are_partial(self):
        for distro, path, malformed in (
            ("debian", "/var/lib/dpkg/status", b"not a control paragraph\n"),
            ("alpine", "/lib/apk/db/installed", b"P:missing-version\n"),
        ):
            files = {
                "/etc/os-release": f"ID={distro}\nVERSION_ID=1\n".encode(),
                path: malformed,
                "/etc/apt/sources.list": b"deb https://deb.test stable main\n",
                "/etc/apt/sources.list.d": {},
                "/etc/apk/repositories": b"https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n",
            }
            with self.subTest(distro=distro):
                context = RepositoryContextResolver(TargetFilesystemReader(
                    StreamingRunner(files), "victim-X")).resolve(
                        {"architecture": "amd64"})
                self.assertEqual(context.status, RepositoryContextStatus.PARTIAL)
                self.assertEqual(context.installed_source_mappings, ())
                self.assertIn("installed_package_metadata", context.missing_fields)

    def test_disabled_deb822_and_repository_credentials_are_not_serialized(self):
        secret = "repository-secret-sentinel"
        raw_credential_url = f"https://signed.test/repo?X-Amz-Credential={secret}"
        runner = StreamingRunner({
            "/etc/os-release": b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n",
            "/var/lib/dpkg/status": (
                b"Package: curl\nStatus: install ok installed\n"
                b"Version: 1\nArchitecture: amd64\n\n"),
            "/etc/apt/sources.list": (
                f"deb https://user:{secret}@deb.test bookworm main\n"
                f"deb {raw_credential_url} bookworm main\n"
                f"deb https://aws.test/repo?AWSAccessKeyId={secret} bookworm main\n"
                f"deb https://other.test/repo?harmless={secret} bookworm main\n"
                "deb https://safe.test/repo bookworm main\n"
            ).encode(),
            "/etc/apt/sources.list.d": {
                "mixed.sources": (
                    b"Enabled: no\nURIs: https://disabled.test\nSuites: bookworm\n\n"
                    b"Enabled: YES\nURIs: https://enabled.test\nSuites: bookworm\n"
                ),
            },
        })
        results = RemediationDiscoveryService(
            runner=runner, container_name="victim-X").discover_unified([], [{
                "canonical_cve_id": "CVE-1", "package_uid": "npm:name",
                "package_name": "name", "package_purl": "pkg:npm/name@1.0.0",
                "installed_version": "1.0.0", "fixed_versions": ["1.1.0"],
                "result_class": "lang-pkgs", "result_type": "npm",
            }])
        encoded = json.dumps(artifact_to_dict("credential-test", results), sort_keys=True)
        context = results[0].request.repository_context
        self.assertNotIn(secret, encoded)
        self.assertNotIn(raw_credential_url, encoded)
        self.assertNotIn("user:", encoded)
        self.assertNotIn("disabled.test", encoded)
        self.assertIn("enabled.test", encoded)
        self.assertIn("https://deb.test", encoded)
        self.assertIn("https://safe.test/repo", encoded)
        self.assertNotIn("signed.test", encoded)
        self.assertNotIn("aws.test", encoded)
        self.assertNotIn("other.test", encoded)
        self.assertEqual(context.status, RepositoryContextStatus.PARTIAL)
        self.assertIn("safe_repository_urls", context.missing_fields)

    def test_missing_metadata_is_partial_and_unsupported_stops_early(self):
        missing = StreamingRunner({"/etc/os-release": b"ID=debian\nVERSION_ID=12\n"})
        context = RepositoryContextResolver(
            TargetFilesystemReader(missing, "victim-X")).resolve()
        self.assertEqual(context.status, RepositoryContextStatus.PARTIAL)
        self.assertIn("installed_package_metadata", context.missing_fields)

        unsupported = StreamingRunner({"/etc/os-release": b"ID=fedora\nVERSION_ID=40\n"})
        context = RepositoryContextResolver(
            TargetFilesystemReader(unsupported, "victim-X")).resolve()
        self.assertEqual(context.status, RepositoryContextStatus.PARTIAL)
        self.assertIn("supported_distribution", context.missing_fields)
        self.assertEqual(len(unsupported.calls), 1)

    def test_context_is_attached_to_unified_discovery_request(self):
        runner = StreamingRunner({
            "/etc/os-release": b"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n",
            "/var/lib/dpkg/status": (
                b"Package: curl\nStatus: install ok installed\n"
                b"Version: 7.0-1\nArchitecture: amd64\n\n"),
            "/etc/apt/sources.list": b"deb https://deb.test bookworm main\n",
            "/etc/apt/sources.list.d": {},
        })
        result = RemediationDiscoveryService(
            runner=runner, container_name="victim-X").discover_unified([], [{
                "canonical_cve_id": "CVE-1", "package_uid": "npm:name",
                "package_name": "name", "package_purl": "pkg:npm/name@1.0.0",
                "installed_version": "1.0.0", "fixed_versions": ["1.1.0"],
                "result_class": "lang-pkgs", "result_type": "npm",
            }])[0]
        context = result.request.repository_context
        self.assertEqual(context.distro, "debian")
        self.assertEqual(context.installed_source_mappings[0].source_name, "curl")
        self.assertEqual(context.architecture_provenance,
                         context.installed_source_mappings[0].provenance)
        restored = repository_context_from_dict(context.to_dict())
        self.assertEqual(restored, context)


if __name__ == "__main__":
    unittest.main()
