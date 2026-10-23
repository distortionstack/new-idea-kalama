"""pywebview presentation bridge.  No pipeline or subprocess calls live here."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

import yaml

from .application import DesktopApplication, DesktopApplicationException, MockDesktopApplication, RuntimeDesktopApplication
from .contracts import FormContext, FormDocument


class DesktopBridge:
    def __init__(self, application: DesktopApplication):
        self.application = application

    def list_runs(self) -> dict[str, Any]:
        return self._reply(lambda: self.application.list_runs())

    def list_forms(self, run_id: str) -> dict[str, Any]:
        return self._reply(lambda: self.application.list_forms(run_id))

    def start_scan(self, image: str) -> dict[str, Any]:
        return self._reply(lambda: self.application.start_scan(image))

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self._reply(lambda: self.application.get_job(job_id))

    def get_form(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        return self._reply(lambda: self._document(self.application.get_form(self._context(raw))))

    def save_form(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        return self._reply(lambda: self._document(self.application.save_form(self._document_from_raw(raw))))

    def submit_form(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        return self._reply(lambda: self.application.submit_form(self._document_from_raw(raw)))

    def apply_yaml(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        def apply() -> dict[str, Any]:
            import yaml
            text = raw.get("yaml")
            if not isinstance(text, str):
                raise DesktopApplicationException("INVALID_YAML", "YAML ต้องเป็นข้อความ")
            parsed = yaml.safe_load(text)
            if not isinstance(parsed, Mapping):
                raise DesktopApplicationException("INVALID_YAML", "YAML ต้องมี object ระดับบนสุด")
            context_raw = raw.get("context")
            context = self._context(context_raw) if isinstance(context_raw, Mapping) else self._context(raw)
            document = FormDocument(context, dict(parsed), bool(raw.get("is_mock", False)))
            return self._document(self.application.save_form(document))
        return self._reply(apply)

    def dump_yaml(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        def dump() -> str:
            data = raw.get("data")
            if not isinstance(data, Mapping):
                raise DesktopApplicationException("INVALID_FORM", "ข้อมูลฟอร์มไม่ถูกต้อง")
            return yaml.safe_dump(dict(data), sort_keys=False, allow_unicode=True)
        return self._reply(dump)

    @staticmethod
    def _context(raw: Mapping[str, Any]) -> FormContext:
        return FormContext(str(raw["run_id"]), str(raw["kind"]), str(raw["item_id"]),
                           str(raw["phase"]), int(raw["revision"]))

    def _document_from_raw(self, raw: Mapping[str, Any]) -> FormDocument:
        data = raw.get("data")
        if not isinstance(data, Mapping):
            raise DesktopApplicationException("INVALID_FORM", "ข้อมูลฟอร์มไม่ถูกต้อง")
        context_raw = raw.get("context")
        context = self._context(context_raw) if isinstance(context_raw, Mapping) else self._context(raw)
        return FormDocument(context, dict(data), bool(raw.get("is_mock", False)))

    @staticmethod
    def _document(doc: FormDocument) -> dict[str, Any]:
        return {"context": doc.context.__dict__, "data": doc.data, "is_mock": doc.is_mock}

    @staticmethod
    def _reply(action):
        try:
            return {"ok": True, "data": action()}
        except DesktopApplicationException as exc:
            return {"ok": False, "error": exc.error.to_dict()}
        except (KeyError, TypeError, ValueError) as exc:
            return {"ok": False, "error": {"code": "INVALID_REQUEST", "message": "คำขอไม่ถูกต้อง", "diagnostic": str(exc)}}


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="viper-desktop")
    parser.add_argument("--output-root", default="output")
    parser.add_argument("--mock", action="store_true", help="open clearly labelled mock data")
    args = parser.parse_args(argv)
    try:
        import webview
    except ImportError as exc:
        raise SystemExit("pywebview is required: install with pip install -e '.[desktop]'") from exc
    bridge = DesktopBridge(MockDesktopApplication() if args.mock else RuntimeDesktopApplication(Path(args.output_root)))
    html = files("kalama.desktop.web").joinpath("index.html").read_text(encoding="utf-8")
    webview.create_window("VIPER — Container Security", html=html, js_api=bridge, width=1440, height=920, min_size=(1040, 720))
    webview.start(debug=False)
    return 0
