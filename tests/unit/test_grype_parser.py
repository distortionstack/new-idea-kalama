import unittest
from kalama.scan.grype import parse_grype_report

class GrypeParserTests(unittest.TestCase):
    def test_normalizes_realistic_match_shape(self):
        report = {"descriptor":{"version":"0.80.0"}, "matches":[{"vulnerability":{"id":"CVE-2020-1", "fix":{"versions":["2"]}}, "artifact":{"name":"libx", "version":"1", "type":"deb", "purl":"pkg:deb/debian/libx@1"}}]}
        result = parse_grype_report(report)
        self.assertEqual("SUCCEEDED", result.status)
        self.assertEqual(("CVE-2020-1", "pkg:deb/debian/libx@1", "deb"), result.findings[0].candidate_key)
