"""Typed DTOs crossing the desktop Presentation/Application boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class FormContext:
    run_id: str
    kind: str
    item_id: str
    phase: str
    revision: int


@dataclass(frozen=True)
class FormDocument:
    context: FormContext
    data: Mapping[str, Any]
    is_mock: bool = False


@dataclass(frozen=True)
class ApplicationError:
    code: str
    message: str
    diagnostic: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"code": self.code, "message": self.message, "diagnostic": self.diagnostic}
