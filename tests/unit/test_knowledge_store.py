import tempfile
import unittest
from pathlib import Path
from kalama.knowledge import KnowledgeStore, KnowledgeRecord, TrustState, retrieve_compatible

class KnowledgeStoreTests(unittest.TestCase):
    def test_persists_validated_context_bound_records(self):
        with tempfile.TemporaryDirectory() as root:
            store = KnowledgeStore(Path(root))
            rec = KnowledgeRecord("CVE-2020-1", "pkg:a/x@1", {"package_purl":"pkg:a/x@1", "installed_version":"1"}, "attack_config", {"targeturi":"/"}, TrustState.VALIDATED, "abc12", {"sha256":"x"})
            one = store.upsert(rec); two = store.upsert(rec)
            self.assertEqual(one.record_id, two.record_id)
            self.assertEqual(1, len(retrieve_compatible(store, cve_id="CVE-2020-1", component="pkg:a/x@1", kind="attack_config", context={"package_purl":"pkg:a/x@1", "installed_version":"1"})))
            self.assertEqual((), retrieve_compatible(store, cve_id="CVE-2020-1", component="pkg:a/x@1", kind="attack_config", context={"package_purl":"pkg:a/x@1", "installed_version":"2"}))
