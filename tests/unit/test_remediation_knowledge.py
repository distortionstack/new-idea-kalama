import tempfile
import unittest
from pathlib import Path
from kalama.knowledge import KnowledgeStore, KnowledgeRecord, TrustState
from kalama.remediation.knowledge import KnowledgeRemediationProvider
from kalama.remediation.models import RemediationCandidate
from kalama.knowledge.writer import validated_remediation_record

class Base:
    def __init__(self, value=None): self.value=value
    def candidate(self, **kwargs): return self.value

class RemediationKnowledgeTests(unittest.TestCase):
    def test_compatible_validated_fills_only_missing_and_persists(self):
        with tempfile.TemporaryDirectory() as root:
            store=KnowledgeStore(Path(root)); occ={"canonical_cve_id":"CVE-2020-1","package_name":"libx","result_type":"deb","installed_version":"1"}
            store.upsert(KnowledgeRecord("CVE-2020-1","libx",{"package_name":"libx","ecosystem":"deb","installed_version":"1"},"remediation",{"target_version":"2","strategy":"PACKAGE_MANAGER"},TrustState.VALIDATED,"abc12",{"sha":"x"}))
            p=KnowledgeRemediationProvider(Base(RemediationCandidate(target_version="3")),store)
            result=p.candidate(package_name="libx",ecosystem="deb",installed_versions=("1",),scanner_fixed_versions=(),occurrences=(occ,))
            self.assertEqual("3",result.target_version); self.assertEqual("PACKAGE_MANAGER",result.strategy.value)
    def test_mismatch_and_nonvalidated_do_not_apply(self):
        with tempfile.TemporaryDirectory() as root:
            store=KnowledgeStore(Path(root)); store.upsert(KnowledgeRecord("CVE-2020-1","other",{"package_name":"other"},"remediation",{"target_version":"2"},TrustState.VALIDATED,"abc12",{}))
            p=KnowledgeRemediationProvider(Base(),store)
            self.assertIsNone(p.candidate(package_name="libx",ecosystem="deb",installed_versions=("1",),scanner_fixed_versions=(),occurrences=({"canonical_cve_id":"CVE-2020-1","package_name":"libx","result_type":"deb","installed_version":"1"},)))

    def test_validated_remediation_round_trip_in_fresh_store(self):
        with tempfile.TemporaryDirectory() as root:
            occ={"canonical_cve_id":"CVE-2020-1","package_name":"libx","result_type":"deb","installed_version":"1"}
            action={"action_id":"patch-001","target_cves":["CVE-2020-1"],"candidate":{"target_version":"2","fix_type":"C","strategy":"PACKAGE_MANAGER","source_authority":"repo"}}
            record=validated_remediation_record(cve_id="CVE-2020-1",occurrence=occ,action=action,run_id="abc12",evidence={"patch_action_id":"patch-001","patch_plan":{"sha256":"a"*64}})
            store=KnowledgeStore(Path(root)); store.upsert(record)
            fresh=KnowledgeStore(Path(root))
            result=KnowledgeRemediationProvider(Base(),fresh).candidate(package_name="libx",ecosystem="deb",installed_versions=("1",),scanner_fixed_versions=(),occurrences=(occ,))
            self.assertEqual("2",result.target_version)
            self.assertEqual("patch-001",result.evidence[-1]["evidence"]["patch_action_id"])

    def test_unrelated_action_or_missing_candidate_cannot_write(self):
        occ={"package_name":"libx","result_type":"deb","installed_version":"1"}
        self.assertIsNone(validated_remediation_record(cve_id="CVE-2020-1",occurrence=occ,action={"target_cves":["CVE-OTHER"]},run_id="abc12",evidence={}))
