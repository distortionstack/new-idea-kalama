from __future__ import annotations
import json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .models import KnowledgeRecord, TrustState

class KnowledgeStore:
    def __init__(self, output_root: Path):
        self.path = Path(output_root) / "knowledge" / "kalama-knowledge.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = self._connect()
        try:
            db.execute("""CREATE TABLE IF NOT EXISTS knowledge (
              id INTEGER PRIMARY KEY, cve_id TEXT NOT NULL, component TEXT NOT NULL,
              context_json TEXT NOT NULL, kind TEXT NOT NULL, fields_json TEXT NOT NULL,
              trust TEXT NOT NULL, run_id TEXT NOT NULL, evidence_json TEXT NOT NULL,
              fingerprint TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            db.commit()
        finally:
            db.close()
    def _connect(self): return sqlite3.connect(self.path)
    @staticmethod
    def _json(value): return json.dumps(value, sort_keys=True, separators=(",", ":"))
    def upsert(self, record: KnowledgeRecord) -> KnowledgeRecord:
        if record.trust == TrustState.REVOKED: raise ValueError("revoked records cannot be inserted as reusable knowledge")
        fp = self._json([record.cve_id, record.component, record.context, record.kind, record.fields])
        now = datetime.now(timezone.utc).isoformat()
        db = self._connect()
        try:
            db.execute("""INSERT INTO knowledge(cve_id,component,context_json,kind,fields_json,trust,run_id,evidence_json,fingerprint,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET trust=excluded.trust,run_id=excluded.run_id,evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
              (record.cve_id, record.component, self._json(record.context), record.kind, self._json(record.fields), record.trust.value, record.run_id, self._json(record.evidence), fp, now, now))
            row = db.execute("SELECT id FROM knowledge WHERE fingerprint=?", (fp,)).fetchone()
            db.commit()
        finally:
            db.close()
        return KnowledgeRecord(**{**record.__dict__, "record_id": row[0]})
    def candidates(self, cve_id: str, component: str, kind: str, *, trusts=(TrustState.VALIDATED,)):
        db = self._connect()
        try:
            marks = ",".join("?" for _ in trusts)
            rows = db.execute(f"SELECT id,context_json,fields_json,trust,run_id,evidence_json FROM knowledge WHERE cve_id=? AND component=? AND kind=? AND trust IN ({marks}) ORDER BY id", (cve_id, component, kind, *[x.value for x in trusts])).fetchall()
        finally:
            db.close()
        return [KnowledgeRecord(cve_id, component, json.loads(x[1]), kind, json.loads(x[2]), TrustState(x[3]), x[4], json.loads(x[5]), x[0]) for x in rows]
