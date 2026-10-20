"""Dedicated immutable Evidence Cache; it is intentionally unrelated to KnowledgeStore."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Mapping

from .models import SourceKind, canonical_bytes


@dataclass(frozen=True)
class EvidenceCacheRecord:
    source_kind: SourceKind
    authority: str
    resource_identity: str
    retrieval_policy_version: str
    retrieved_at: str
    content_sha256: str
    source_modified_at: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    mime_type: str | None = None
    raw_snapshot_sha256: str | None = None
    normalized_snapshot_sha256: str | None = None
    cache_status: str | None = None
    freshness: Mapping[str, Any] | None = None
    record_id: int | None = None


class EvidenceCache:
    def __init__(self, output_root: Path | str):
        self.root = Path(output_root) / "evidence"
        self.raw_root = self.root / "raw"
        self.normalized_root = self.root / "normalized"
        self.path = self.root / "evidence-cache.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
        db = self._connect()
        try:
            db.execute("""CREATE TABLE IF NOT EXISTS evidence_cache (
                id INTEGER PRIMARY KEY, source_kind TEXT NOT NULL, authority TEXT NOT NULL,
                resource_identity TEXT NOT NULL, retrieval_policy_version TEXT NOT NULL,
                retrieved_at TEXT NOT NULL, source_modified_at TEXT, content_sha256 TEXT NOT NULL,
                etag TEXT, last_modified TEXT, mime_type TEXT, raw_snapshot_sha256 TEXT,
                normalized_snapshot_sha256 TEXT, cache_status TEXT, freshness_json TEXT NOT NULL)""")
            db.execute("CREATE INDEX IF NOT EXISTS evidence_cache_lookup ON evidence_cache(source_kind, resource_identity, id DESC)")
            db.commit()
        finally:
            db.close()

    def _connect(self):
        return sqlite3.connect(self.path)

    @staticmethod
    def _snapshot(root: Path, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        path = root / digest[:2] / digest
        if path.is_file():
            if path.read_bytes() != payload:
                raise RuntimeError("evidence snapshot digest collision")
            return digest
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{digest}.", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != payload:
                    raise RuntimeError("evidence snapshot digest collision")
            return digest
        finally:
            if temporary is not None:
                try: temporary.unlink()
                except FileNotFoundError: pass

    def store_raw(self, payload: bytes) -> str:
        return self._snapshot(self.raw_root, payload)

    def store_normalized(self, content: Mapping[str, Any] | str | bytes) -> str:
        payload = content if isinstance(content, bytes) else (content.encode("utf-8") if isinstance(content, str)
                                                               else canonical_bytes(content))
        return self._snapshot(self.normalized_root, payload)

    def read_raw(self, digest: str) -> bytes:
        return (self.raw_root / digest[:2] / digest).read_bytes()

    def read_normalized(self, digest: str) -> bytes:
        return (self.normalized_root / digest[:2] / digest).read_bytes()

    def record(self, record: EvidenceCacheRecord) -> EvidenceCacheRecord:
        if len(record.content_sha256) != 64:
            raise ValueError("content SHA-256 must be a 64 character digest")
        db = self._connect()
        try:
            cursor = db.execute("""INSERT INTO evidence_cache(
                source_kind,authority,resource_identity,retrieval_policy_version,retrieved_at,
                source_modified_at,content_sha256,etag,last_modified,mime_type,
                raw_snapshot_sha256,normalized_snapshot_sha256,cache_status,freshness_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                record.source_kind.value, record.authority, record.resource_identity,
                record.retrieval_policy_version, record.retrieved_at, record.source_modified_at,
                record.content_sha256, record.etag, record.last_modified, record.mime_type,
                record.raw_snapshot_sha256, record.normalized_snapshot_sha256,
                record.cache_status, json.dumps(record.freshness or {}, sort_keys=True,
                                                separators=(",", ":"))))
            db.commit()
            return EvidenceCacheRecord(**{**record.__dict__, "record_id": cursor.lastrowid})
        finally:
            db.close()

    def records(self, source_kind: SourceKind, resource_identity: str) -> tuple[EvidenceCacheRecord, ...]:
        db = self._connect()
        try:
            rows = db.execute("SELECT id,authority,retrieval_policy_version,retrieved_at,source_modified_at,content_sha256,etag,last_modified,mime_type,raw_snapshot_sha256,normalized_snapshot_sha256,cache_status,freshness_json FROM evidence_cache WHERE source_kind=? AND resource_identity=? ORDER BY id", (source_kind.value, resource_identity)).fetchall()
        finally:
            db.close()
        return tuple(EvidenceCacheRecord(source_kind, row[1], resource_identity, row[2], row[3], row[5],
            row[4], row[6], row[7], row[8], row[9], row[10], row[11], json.loads(row[12]), row[0]) for row in rows)

    def latest(self, source_kind: SourceKind, resource_identity: str,
               retrieval_policy_version: str) -> EvidenceCacheRecord | None:
        """Exact source/resource/policy lookup; deliberately not a CVE-wide cache."""
        return next((record for record in reversed(self.records(source_kind, resource_identity))
                     if record.retrieval_policy_version == retrieval_policy_version), None)
