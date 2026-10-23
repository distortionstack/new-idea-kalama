import tempfile
import unittest
from pathlib import Path
from kalama.knowledge import KnowledgeStore, TrustState, retrieve_compatible
from kalama.knowledge.retrieval import compatible
from kalama.knowledge.lab_notes import import_repository_lab_notes

class LabNoteImportTests(unittest.TestCase):
    def test_import_is_idempotent_and_provenance_is_lab_only(self):
        with tempfile.TemporaryDirectory() as root:
            store = KnowledgeStore(Path(root))
            self.assertEqual(1, import_repository_lab_notes(store))
            self.assertEqual(1, import_repository_lab_notes(store))
            rows = store.candidates("CVE-2017-9805", "org.apache.struts:struts2-rest-plugin", "remediation",
                                    trusts=(TrustState.LAB_VALIDATED,))
            self.assertEqual(1, len(rows))
            self.assertEqual(TrustState.LAB_VALIDATED, rows[0].trust)
            self.assertEqual("LAB-NOTE:docs/AGENT_README.md#YZk0S", rows[0].run_id)

    def test_compatible_reuse_requires_matching_installed_version(self):
        with tempfile.TemporaryDirectory() as root:
            store = KnowledgeStore(Path(root)); import_repository_lab_notes(store)
            records = store.candidates("CVE-2017-9805", "org.apache.struts:struts2-rest-plugin", "remediation",
                                      trusts=(TrustState.LAB_VALIDATED,))
            self.assertEqual(1, len(records))
            self.assertTrue(compatible(records[0], {"package_name":"org.apache.struts:struts2-rest-plugin",
                "ecosystem":"jar", "installed_version":"2.5.12",
                "application_path":"/orders/3", "image_family":"vulhub/struts2:2.5.12-rest-showcase"}))
            self.assertEqual((), retrieve_compatible(store,
                cve_id="CVE-2017-9805", component="org.apache.struts:struts2-rest-plugin",
                kind="remediation", context={"package_name":"org.apache.struts:struts2-rest-plugin",
                "ecosystem":"jar", "installed_version":"2.3.20.1"}))
