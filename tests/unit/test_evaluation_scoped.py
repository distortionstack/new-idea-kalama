"""Focused reusable regression tests for Task 3 scoped evaluation.

Covers the required global+scoped evidence rules without touching scanner,
patch execution, retry, resolver, or oracle semantics.
"""

import unittest

from kalama.evaluation.scoped_evidence import (
    ScopedScannerStatus,
    classify_scoped_remediation,
    derive_global_evidence,
    derive_scoped_status,
)


def occurrence(uid, purl="pkg:maven/x@y@1.0"):
    return {"package_uid": uid, "package_purl": purl, "target": "Java",
            "result_type": "jar", "installed_version": "1.0"}


def scan_entry(status, before, after):
    return {"cve_id": "CVE-2099-0001", "scanner_status": status,
            "before_occurrences": before, "after_occurrences": after}


def base_kwargs(**overrides):
    params = {
        "cve_id": "CVE-2099-0001",
        "before_disposition": "EXPLOIT_SUCCEEDED",
        "patch_status": "SUCCEEDED",
        "patch_disposition": "EXECUTE",
        "scoped_status": ScopedScannerStatus.SCOPED_NOT_FOUND.value,
        "global_status": "FOUND",
        "same_cve_found_elsewhere": True,
        "after_disposition": "EXPLOIT_FAILED",
        "after_oracle": "NOT_VULNERABLE",
        "metric_eligible": True,
        "comparable": True,
    }
    params.update(overrides)
    return params


class DeriveScopedTests(unittest.TestCase):
    def test_global_not_found_implies_scoped_not_found(self):
        value = derive_scoped_status(
            scan_entry("NOT_FOUND", [occurrence("a")], []),
            patch_action_status="SUCCEEDED")
        self.assertEqual(value["scoped_status"], "SCOPED_NOT_FOUND")
        self.assertFalse(value["same_cve_found_elsewhere"])

    def test_global_unknown_is_mapping_unknown(self):
        value = derive_scoped_status(
            scan_entry("UNKNOWN", [occurrence("a")], [occurrence("a")]),
            patch_action_status="SUCCEEDED")
        self.assertEqual(value["scoped_status"], "SCOPED_MAPPING_UNKNOWN")

    def test_removed_instances_with_succeeded_patch_is_scoped_not_found(self):
        before = [occurrence("keep"), occurrence("patched")]
        after = [occurrence("keep")]
        value = derive_scoped_status(
            scan_entry("FOUND", before, after), patch_action_status="SUCCEEDED")
        self.assertEqual(value["scoped_status"], "SCOPED_NOT_FOUND")
        self.assertTrue(value["same_cve_found_elsewhere"])

    def test_no_removed_instance_is_scoped_present(self):
        items = [occurrence("a"), occurrence("b")]
        value = derive_scoped_status(
            scan_entry("FOUND", items, list(items)), patch_action_status="SUCCEEDED")
        self.assertEqual(value["scoped_status"], "SCOPED_PRESENT")
        self.assertTrue(value["same_cve_found_elsewhere"])

    def test_unmappable_occurrences_are_unknown(self):
        value = derive_scoped_status(
            scan_entry("FOUND", [{"no": "identity"}], [{"no": "identity"}]),
            patch_action_status="SUCCEEDED")
        self.assertEqual(value["scoped_status"], "SCOPED_MAPPING_UNKNOWN")

    def test_global_evidence_preserves_residual(self):
        self.assertEqual(
            derive_global_evidence({"scanner_status": "FOUND"}),
            {"global_status": "FOUND", "residual_risk": True})
        self.assertEqual(
            derive_global_evidence({"scanner_status": "NOT_FOUND"}),
            {"global_status": "NOT_FOUND", "residual_risk": False})
        self.assertTrue(
            derive_global_evidence({"scanner_status": "UNKNOWN"})["residual_risk"])


class ClassifyScopedTests(unittest.TestCase):
    def test_scoped_not_found_with_valid_negative_validates_with_residual(self):
        result = classify_scoped_remediation(**base_kwargs())
        self.assertEqual(result["final_status"], "VERIFIED")
        self.assertTrue(result["remediation_validated"])
        self.assertTrue(result["same_cve_found_elsewhere"])
        self.assertTrue(result["residual_risk"])

    def test_scoped_present_must_not_validate(self):
        result = classify_scoped_remediation(**base_kwargs(
            scoped_status="SCOPED_PRESENT"))
        self.assertEqual(result["final_status"], "INCONCLUSIVE")
        self.assertFalse(result["remediation_validated"])

    def test_mapping_unknown_remains_inconclusive(self):
        result = classify_scoped_remediation(**base_kwargs(
            scoped_status="SCOPED_MAPPING_UNKNOWN"))
        self.assertEqual(result["final_status"], "INCONCLUSIVE")
        self.assertFalse(result["remediation_validated"])

    def test_after_environment_failure_remains_inconclusive_when_scoped_clean(self):
        for after in ({"after_disposition": "AFTER_ENVIRONMENT_UNRESOLVED",
                       "after_oracle": "NOT_EVALUATED", "metric_eligible": False},
                      {"after_disposition": "NOT_EXECUTED",
                       "after_oracle": "NOT_EVALUATED", "metric_eligible": False},
                      {"after_disposition": "INCONCLUSIVE",
                       "after_oracle": "INCONCLUSIVE", "metric_eligible": False}):
            with self.subTest(after=after):
                result = classify_scoped_remediation(**base_kwargs(**after))
                self.assertEqual(result["final_status"], "INCONCLUSIVE")
                self.assertFalse(result["remediation_validated"])

    def test_reproduced_attributable_impact_is_not_validated(self):
        result = classify_scoped_remediation(**base_kwargs(
            after_disposition="EXPLOIT_SUCCEEDED", after_oracle="VULNERABLE",
            metric_eligible=True))
        self.assertEqual(result["final_status"], "FAILED")
        self.assertFalse(result["remediation_validated"])
        self.assertTrue(result["residual_risk"])

    def test_skip_out_of_scope_is_non_evaluated_with_residual(self):
        result = classify_scoped_remediation(**base_kwargs(
            patch_disposition="SKIP_OUT_OF_SCOPE",
            patch_status="SKIP_OUT_OF_SCOPE",
            scoped_status="SCOPED_PRESENT",
            after_disposition="NOT_EXECUTED",
            after_oracle="NOT_EVALUATED",
            metric_eligible=False))
        self.assertEqual(result["final_status"], "NOT_EVALUATED")
        self.assertFalse(result["remediation_validated"])
        self.assertTrue(result["residual_risk"])

    def test_before_not_succeeded_is_not_evaluated(self):
        result = classify_scoped_remediation(**base_kwargs(
            before_disposition="EXPLOIT_FAILED"))
        self.assertEqual(result["final_status"], "NOT_EVALUATED")
        self.assertFalse(result["remediation_validated"])

    def test_patch_not_succeeded_is_inconclusive(self):
        result = classify_scoped_remediation(**base_kwargs(patch_status="FAILED"))
        self.assertEqual(result["final_status"], "INCONCLUSIVE")
        self.assertFalse(result["remediation_validated"])


if __name__ == "__main__":
    unittest.main()
