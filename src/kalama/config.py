"""Small, secret-safe runtime configuration loader.

The loader deliberately has no dependency on python-dotenv.  A local .env is
only a convenience for development; process environment always wins.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Mapping


def _dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key and key.replace("_", "").isalnum():
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key] = value
    return values


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = "llama3.2:3b"
    base_url: str = "http://127.0.0.1:11434"
    api_key: str | None = None

    def error(self) -> str | None:
        if not self.enabled:
            return None
        if self.provider not in {"ollama", "openai-compatible"}:
            return "unsupported provider"
        if self.provider == "openai-compatible" and not self.api_key:
            return "API key missing"
        if not self.model.strip() or not self.base_url.strip():
            return "model or base URL missing"
        return None


@dataclass(frozen=True)
class EvidenceConfig:
    """Source switches for future evidence adapters; no adapter is enabled here."""
    runtime: bool = True
    knowledge: bool = True
    msf_metadata: bool = True
    msf_module_doc: bool = True
    msf_reference: bool = True
    vendor_upstream: bool = False
    nvd: bool = False
    cisa_kev: bool = True
    web_search: bool = False


def load_config(*, env: Mapping[str, str] | None = None, dotenv_path: Path | None = None) -> LLMConfig:
    file_values = _dotenv(dotenv_path or Path.cwd() / ".env")
    process = os.environ if env is None else env
    def get(name: str, default: str = "") -> str:
        return str(process.get(name, file_values.get(name, default))).strip()
    enabled = get("KALAMA_LLM_ENABLED", get("KALAMA_GUIDANCE_ENABLED", "")).casefold() in {"1", "true", "yes", "on"}
    return LLMConfig(enabled, get("KALAMA_LLM_PROVIDER", "ollama").casefold() or "ollama",
                     get("KALAMA_LLM_MODEL", get("KALAMA_OLLAMA_MODEL", "llama3.2:3b")),
                     get("KALAMA_LLM_BASE_URL", get("KALAMA_OLLAMA_URL", "http://127.0.0.1:11434")),
                     get("KALAMA_LLM_API_KEY") or None)


def load_evidence_config(*, env: Mapping[str, str] | None = None,
                         dotenv_path: Path | None = None) -> EvidenceConfig:
    """Load source switches without changing existing LLM configuration behavior."""
    file_values = _dotenv(dotenv_path or Path.cwd() / ".env")
    process = os.environ if env is None else env
    def enabled(name: str, default: bool) -> bool:
        raw = str(process.get(name, file_values.get(name, str(default)))).strip().casefold()
        return raw in {"1", "true", "yes", "on"}
    return EvidenceConfig(
        runtime=enabled("KALAMA_EVIDENCE_RUNTIME_ENABLED", True),
        knowledge=enabled("KALAMA_EVIDENCE_KNOWLEDGE_ENABLED", True),
        msf_metadata=enabled("KALAMA_EVIDENCE_MSF_METADATA_ENABLED", True),
        msf_module_doc=enabled("KALAMA_EVIDENCE_MSF_MODULE_DOC_ENABLED", True),
        msf_reference=enabled("KALAMA_EVIDENCE_MSF_REFERENCE_ENABLED", True),
        vendor_upstream=enabled("KALAMA_EVIDENCE_VENDOR_UPSTREAM_ENABLED", False),
        nvd=enabled("KALAMA_EVIDENCE_NVD_ENABLED", False),
        cisa_kev=enabled("KALAMA_EVIDENCE_CISA_KEV_ENABLED", True),
        web_search=False,
    )
