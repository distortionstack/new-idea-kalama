"""Structured, provenance-preserving import of repository Lab Notes."""
from __future__ import annotations
from pathlib import Path
from .models import KnowledgeRecord, TrustState

LAB_NOTE_RUN = "LAB-NOTE:docs/AGENT_README.md#YZk0S"

def import_repository_lab_notes(store) -> int:
    """Seed only explicit, human-validated notes; never mark them automated."""
    note = Path(__file__).resolve().parents[3] / "docs" / "AGENT_README.md"
    if not note.is_file() or "CVE-2017-9805" not in note.read_text(encoding="utf-8"):
        return 0
    record = KnowledgeRecord(
        "CVE-2017-9805", "org.apache.struts:struts2-rest-plugin", {
            "package_name": "org.apache.struts:struts2-rest-plugin",
            "ecosystem": "jar", "installed_version": "2.5.12",
            "application_path": "/orders/3", "image_family": "vulhub/struts2:2.5.12-rest-showcase",
        }, "remediation", {
            "target_version": "2.5.13", "fix_type": "B", "strategy": "HUMAN_COMMAND",
            "source_type": "maven_artifact", "source_authority": "repository_lab_note",
            "source_identifier": "org.apache.struts:struts2-rest-plugin:2.5.13",
            "source_url": "https://repo.maven.apache.org/maven2/org/apache/struts/struts2-rest-plugin/2.5.13/struts2-rest-plugin-2.5.13.jar",
            "checksum": "f43e8ea108811a2b9d54d342f4442cd9fdcb6a4e79ce488858477d7832a27a59",
            "same_branch": False, "notes": "Manual lab patch; not executable knowledge",
        }, TrustState.LAB_VALIDATED, LAB_NOTE_RUN, {
            "source_file": str(note), "section": "YZk0S", "validation": "human-confirmed lab evidence",
            "execution_status": "lab validated; not system validated", "context_path": "/orders/3",
        })
    store.upsert(record)
    return 1
