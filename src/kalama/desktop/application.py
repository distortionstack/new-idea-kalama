"""Application layer for the desktop app.

This layer owns form snapshots, revision checks and runtime calls.  Widgets and
webview APIs never reach the pipeline, YAML files or subprocess-backed runtime.
"""

from __future__ import annotations

from copy import deepcopy
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import uuid4

import yaml

from kalama.runtime import ProductionRuntime, build_runtime
from kalama.state import ArtifactKind

from .contracts import ApplicationError, FormContext, FormDocument


class DesktopApplication(Protocol):
    def list_runs(self) -> list[dict[str, Any]]: ...
    def list_forms(self, run_id: str) -> list[dict[str, Any]]: ...
    def start_scan(self, image: str) -> dict[str, Any]: ...
    def get_job(self, job_id: str) -> dict[str, Any]: ...
    def get_form(self, context: FormContext) -> FormDocument: ...
    def save_form(self, document: FormDocument) -> FormDocument: ...
    def submit_form(self, document: FormDocument) -> dict[str, Any]: ...


class RuntimeDesktopApplication:
    """Adapter over the existing runtime and immutable form artifacts."""

    _kinds = {"attack": ArtifactKind.ATTACK_FORM, "patch": ArtifactKind.PATCH_FORM}

    def __init__(self, output_root: Path, runtime: ProductionRuntime | None = None):
        self.runtime = runtime or build_runtime(output_root)
        self._drafts: dict[tuple[str, str, str], FormDocument] = {}
        self._jobs: dict[str, Future] = {}
        self._workers = ThreadPoolExecutor(max_workers=1, thread_name_prefix="viper-desktop")

    def list_runs(self) -> list[dict[str, Any]]:
        return [{"run_id": state.run_id, "image": state.victim_image,
                 "status": state.status.value, "waiting_reason": state.waiting_reason,
                 "updated_at": state.updated_at}
                for state in self.runtime.store.discover()]

    def list_forms(self, run_id: str) -> list[dict[str, Any]]:
        state = self.runtime.store.load(run_id)
        forms: list[dict[str, Any]] = []
        for kind, artifact_kind, collection in (
            ("attack", ArtifactKind.ATTACK_FORM, "cves"),
            ("patch", ArtifactKind.PATCH_FORM, "actions"),
        ):
            artifact = state.artifact(artifact_kind)
            if artifact is None:
                continue
            raw = yaml.safe_load(Path(artifact.path).read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping) or not isinstance(raw.get(collection), Mapping):
                continue
            revision = raw.get("revision")
            if not isinstance(revision, int):
                continue
            forms.extend({"run_id": run_id, "kind": kind, "item_id": str(item_id),
                          "phase": str(raw.get("phase") or ""), "revision": revision}
                         for item_id in raw[collection])
        return forms

    def start_scan(self, image: str) -> dict[str, Any]:
        if not isinstance(image, str) or not image.strip():
            raise DesktopApplicationException("IMAGE_REQUIRED", "ระบุ Docker image ก่อนเริ่มวิเคราะห์")
        job_id = uuid4().hex
        self._jobs[job_id] = self._workers.submit(self.runtime.start, image.strip())
        return {"job_id": job_id, "status": "QUEUED"}

    def get_job(self, job_id: str) -> dict[str, Any]:
        future = self._jobs.get(job_id)
        if future is None:
            raise DesktopApplicationException("JOB_NOT_FOUND", "ไม่พบงานเบื้องหลัง")
        if not future.done():
            return {"job_id": job_id, "status": "RUNNING"}
        try:
            state = future.result()
        except Exception as exc:
            return {"job_id": job_id, "status": "FAILED", "error": str(exc)}
        return {"job_id": job_id, "status": "COMPLETED", "run_id": state.run_id,
                "run_status": state.status.value}

    def get_form(self, context: FormContext) -> FormDocument:
        key = (context.run_id, context.kind, context.item_id)
        if key in self._drafts:
            return self._drafts[key]
        try:
            artifact = self.runtime.store.load(context.run_id).artifact(self._kinds[context.kind])
            if artifact is None:
                raise ValueError("FORM_NOT_AVAILABLE")
            raw = yaml.safe_load(Path(artifact.path).read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ValueError("FORM_INVALID")
            revision = raw.get("revision")
            if not isinstance(revision, int):
                raise ValueError("FORM_INVALID_REVISION")
            data = dict(raw)
            actual = FormContext(context.run_id, context.kind, context.item_id,
                                 str(raw.get("phase") or context.phase), revision)
            return FormDocument(actual, data)
        except (OSError, ValueError, KeyError) as exc:
            raise DesktopApplicationException("FORM_LOAD_FAILED", "ไม่สามารถเปิดฟอร์มงานนี้ได้", str(exc)) from exc

    def save_form(self, document: FormDocument) -> FormDocument:
        self._assert_document(document)
        key = (document.context.run_id, document.context.kind, document.context.item_id)
        saved = FormDocument(document.context, deepcopy(dict(document.data)))
        self._drafts[key] = saved
        return saved

    def submit_form(self, document: FormDocument) -> dict[str, Any]:
        saved = self.save_form(document)
        # Infrastructure owns YAML serialization and temporary-file lifecycle;
        # the presentation layer never writes a form file itself.
        directory = self.runtime.store.output_root / ".desktop-submissions"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{saved.context.kind}-{saved.context.run_id}-{saved.context.revision}.yaml"
        path.write_text(yaml.safe_dump(dict(saved.data), sort_keys=False, allow_unicode=True), encoding="utf-8")
        state = (self.runtime.submit_attack_form(saved.context.run_id, path)
                 if saved.context.kind == "attack"
                 else self.runtime.submit_patch_form(saved.context.run_id, path))
        self._drafts.pop((saved.context.run_id, saved.context.kind, saved.context.item_id), None)
        return {"run_id": state.run_id, "status": state.status.value,
                "waiting_reason": state.waiting_reason,
                "errors": [{"code": x.code, "message": x.message} for x in state.errors]}

    @staticmethod
    def _assert_document(document: FormDocument) -> None:
        data = document.data
        if data.get("run_id") != document.context.run_id or data.get("phase") != document.context.phase:
            raise DesktopApplicationException("FORM_IDENTITY_MISMATCH", "ข้อมูลฟอร์มไม่ตรงกับงานที่เลือก")
        if data.get("revision") != document.context.revision:
            raise DesktopApplicationException("STALE_FORM", "ฟอร์มนี้ไม่ใช่ revision ล่าสุด กรุณาโหลดใหม่")
        collection = "cves" if document.context.kind == "attack" else "actions"
        if document.context.item_id not in data.get(collection, {}):
            raise DesktopApplicationException("FORM_ITEM_NOT_FOUND", "ไม่พบรายการฟอร์มที่เลือก")


class DesktopApplicationException(Exception):
    def __init__(self, code: str, message: str, diagnostic: str | None = None):
        super().__init__(message)
        self.error = ApplicationError(code, message, diagnostic)


class MockDesktopApplication:
    """Explicit development adapter; never claims its data is a real run."""

    def __init__(self):
        self._docs = _mock_documents()

    def list_runs(self) -> list[dict[str, Any]]:
        return [{"run_id": "DEMO1", "image": "demo/elasticsearch:1.4.2", "status": "WAITING_FOR_USER_INPUT",
                 "waiting_reason": "ATTACK_FORM", "updated_at": "Mock data"}]

    def list_forms(self, run_id: str) -> list[dict[str, Any]]:
        if run_id != "DEMO1":
            return []
        return [{"run_id": "DEMO1", "kind": "attack", "item_id": "CVE-2015-1427", "phase": "before", "revision": 1},
                {"run_id": "DEMO1", "kind": "patch", "item_id": "patch-001", "phase": "patch", "revision": 1}]

    def start_scan(self, image: str) -> dict[str, Any]:
        if not image.strip():
            raise DesktopApplicationException("IMAGE_REQUIRED", "ระบุ Docker image ก่อนเริ่มวิเคราะห์")
        return {"job_id": "mock-job", "status": "QUEUED"}

    def get_job(self, job_id: str) -> dict[str, Any]:
        return {"job_id": job_id, "status": "COMPLETED", "run_id": "DEMO1",
                "run_status": "WAITING_FOR_USER_INPUT", "is_mock": True}

    def get_form(self, context: FormContext) -> FormDocument:
        try:
            return deepcopy(self._docs[(context.kind, context.item_id)])
        except KeyError as exc:
            raise DesktopApplicationException("FORM_NOT_AVAILABLE", "ไม่พบฟอร์มตัวอย่าง") from exc

    def save_form(self, document: FormDocument) -> FormDocument:
        RuntimeDesktopApplication._assert_document(document)
        self._docs[(document.context.kind, document.context.item_id)] = deepcopy(document)
        return document

    def submit_form(self, document: FormDocument) -> dict[str, Any]:
        self.save_form(document)
        return {"run_id": document.context.run_id, "status": "MOCK_SUBMITTED",
                "waiting_reason": None, "errors": [], "is_mock": True}


def _mock_documents() -> dict[tuple[str, str], FormDocument]:
    attack = {"schema": "kalama.attack-form/v1", "run_id": "DEMO1", "phase": "before", "revision": 1,
              "base_resolver_sha256": "mock", "base_config_sha256": None,
              "cves": {"CVE-2015-1427": {"rank": 1, "input_reasons": ["TARGETURI_REQUIRED"],
                  "module": {"suggested": "exploit/multi/elasticsearch/search_groovy_script", "confirmed": None,
                             "candidates": [{"module_path": "exploit/multi/elasticsearch/search_groovy_script", "rank_position": 1, "score": 9}]},
                  "target": {"required": True, "index": {"suggested": 0, "confirmed": None}, "name": {"suggested": "Elasticsearch 1.4.2", "confirmed": None},
                             "available": [{"index": 0, "name": "Universal"}, {"index": 1, "name": "Elasticsearch 1.4.2"}]},
                  "targeturi": {"suggested": "/_search", "confirmed": None},
                  "module_options": {"RPORT": {"type": "port", "required": True, "suggested": 9200, "confirmed": None},
                                     "SSL": {"type": "bool", "required": False, "suggested": False, "confirmed": None}},
                  "payload": {"suggested": None, "confirmed": None, "compatible": ["cmd/unix/reverse_bash"], "options": {"LHOST": {"type": "address", "required": True, "suggested": "172.18.0.2", "confirmed": None}, "LPORT": {"type": "port", "required": True, "suggested": 4444, "confirmed": None}}},
                  "pre_attack": {"command": None, "execution_target": "victim-DEMO1", "required": False},
                  "execution_protocol": {"check_supported": True, "confirmed": None, "mode": "check-only"},
                  "environment": {"rhosts": {"confirmed": "172.18.0.3", "read_only": True}, "rport": {"suggested": 9200, "confirmed": None}}}}}
    patch = {"schema": "kalama.patch-form/v1", "run_id": "DEMO1", "phase": "patch", "revision": 1,
             "base_patch_plan_sha256": "mock", "actions": {"patch-001": {"target_cves": ["CVE-2015-1427"],
                 "package": {"name": "org.elasticsearch:elasticsearch", "ecosystem": "jar", "before_versions": ["1.4.2"], "scanner_fixed_versions": ["1.4.3"]},
                 "input_reasons": ["ARTIFACT_SOURCE_UNRESOLVED"], "fix_type": {"suggested": "B", "confirmed": None},
                 "target_version": {"scanner_candidates": ["1.4.3"], "suggested": "1.4.3", "confirmed": None},
                 "artifact": {"suggested_source": None, "confirmed_source": None, "checksum": {"suggested": None, "confirmed": None}},
                 "strategy": {"suggested": "PREBUILT_IMAGE_REPLACEMENT", "confirmed": None},
                 "command": {"confirmed": None}, "validation_command": {"confirmed": None}, "execution_target": "patch-workspace", "major_version_approved": None, "notes": None}}}
    return {("attack", "CVE-2015-1427"): FormDocument(FormContext("DEMO1", "attack", "CVE-2015-1427", "before", 1), attack, True),
            ("patch", "patch-001"): FormDocument(FormContext("DEMO1", "patch", "patch-001", "patch", 1), patch, True)}
