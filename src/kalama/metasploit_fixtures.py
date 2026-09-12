
"""Approved Metasploit lab fixture module-path support.

Fixture directories are disabled by default.  Operators opt in by setting
KALAMA_MSF_MODULE_PATHS to one or more local Metasploit module roots.  A root
is the directory that contains Metasploit module type directories such as
``exploits/`` or ``auxiliary/``.  The stock Metasploit tree is never modified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol, Sequence


MODULE_TYPE_DIRS = {
    "exploits": "exploit",
    "auxiliary": "auxiliary",
    "post": "post",
    "payloads": "payload",
    "encoders": "encoder",
    "nops": "nop",
    "evasion": "evasion",
}
DEFAULT_ENV = "KALAMA_MSF_MODULE_PATHS"
CONTAINER_BASE = "/tmp/kalama-msf-lab-fixtures"


class FixtureConfigurationError(RuntimeError):
    pass


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float | None = None) -> Any: ...


@dataclass(frozen=True)
class FixtureModule:
    fullname: str
    source_path: str
    sha256: str
    modules_root: str
    root_sha256: str
    namespace: str
    manifest: Mapping[str, Any] | None = None

    @property
    def container_modules_root(self) -> str:
        return f"{CONTAINER_BASE}/{self.namespace}/modules"

    @property
    def container_module_path(self) -> str:
        rel = Path(self.source_path).resolve().relative_to(Path(self.modules_root).resolve())
        return f"{self.container_modules_root}/{rel.as_posix()}"

    def provenance(self) -> dict[str, Any]:
        return {
            "module_source": "lab_fixture",
            "fixture_source_path": self.source_path,
            "fixture_sha256": self.sha256,
            "fixture_manifest": dict(self.manifest) if isinstance(self.manifest, Mapping) else None,
            "fixture_modules_root": self.modules_root,
            "fixture_namespace": self.namespace,
            "loaded_module_path": self.container_module_path,
        }


@dataclass(frozen=True)
class ApprovedFixtureRegistry:
    roots: tuple[str, ...]
    modules: Mapping[str, FixtureModule]

    @property
    def enabled(self) -> bool:
        return bool(self.roots)

    def module(self, fullname: str) -> FixtureModule | None:
        return self.modules.get(fullname)

    def require_module(self, fullname: str, expected_sha256: str | None) -> FixtureModule:
        module = self.module(fullname)
        if module is None:
            raise FixtureConfigurationError(
                f"fixture module {fullname!r} is not present in approved KALAMA_MSF_MODULE_PATHS"
            )
        actual = _sha256(Path(module.source_path))
        if actual != module.sha256:
            raise FixtureConfigurationError(
                f"fixture module {fullname!r} changed after registry construction: "
                f"expected {module.sha256}, got {actual}"
            )
        if expected_sha256 is not None and expected_sha256 != module.sha256:
            raise FixtureConfigurationError(
                f"fixture module {fullname!r} SHA-256 mismatch: expected artifact "
                f"{expected_sha256}, approved path has {module.sha256}"
            )
        return module

    def ensure_container_roots_subprocess(self, container: str, *, timeout: float) -> tuple[str, ...]:
        import subprocess
        roots = []
        for root in self.roots:
            root_path = Path(root)
            root_digest = _root_digest(root_path)
            namespace = root_digest[:16]
            dest = f"{CONTAINER_BASE}/{namespace}/modules"
            parent = f"{CONTAINER_BASE}/{namespace}"
            mkdir = subprocess.run(["docker", "exec", container, "mkdir", "-p", parent],
                                   capture_output=True, text=True, timeout=timeout)
            if mkdir.returncode != 0:
                raise FixtureConfigurationError(
                    f"failed to prepare fixture path in {container}: {mkdir.stderr.strip()[:500]}"
                )
            copied = subprocess.run(["docker", "cp", f"{root_path.resolve()}{os.sep}.",
                                     f"{container}:{dest}"],
                                    capture_output=True, text=True, timeout=timeout)
            if copied.returncode != 0:
                raise FixtureConfigurationError(
                    f"failed to copy fixture modules into {container}: {copied.stderr.strip()[:500]}"
                )
            roots.append(dest)
        return tuple(roots)

    def ensure_container_roots_runner(self, runner: CommandRunner, container: str, *,
                                      timeout: float) -> tuple[str, ...]:
        roots = []
        for root in self.roots:
            root_path = Path(root)
            root_digest = _root_digest(root_path)
            namespace = root_digest[:16]
            dest = f"{CONTAINER_BASE}/{namespace}/modules"
            parent = f"{CONTAINER_BASE}/{namespace}"
            mkdir = runner.run(("docker", "exec", container, "mkdir", "-p", parent),
                               timeout=timeout)
            if mkdir.exit_code != 0:
                raise FixtureConfigurationError(
                    f"failed to prepare fixture path in {container}: {mkdir.stderr.strip()[:500]}"
                )
            copied = runner.run(("docker", "cp", f"{root_path.resolve()}{os.sep}.",
                                 f"{container}:{dest}"), timeout=timeout)
            if copied.exit_code != 0:
                raise FixtureConfigurationError(
                    f"failed to copy fixture modules into {container}: {copied.stderr.strip()[:500]}"
                )
            roots.append(dest)
        return tuple(roots)


def registry_from_env(env: Mapping[str, str] | None = None,
                      variable: str = DEFAULT_ENV) -> ApprovedFixtureRegistry:
    env = os.environ if env is None else env
    raw = env.get(variable, "") or ""
    parts = [item.strip().strip('"') for item in raw.split(os.pathsep) if item.strip()]
    return build_registry(parts)


def build_registry(paths: Iterable[str | os.PathLike[str]]) -> ApprovedFixtureRegistry:
    roots: list[str] = []
    modules: dict[str, FixtureModule] = {}
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        if not root.is_dir():
            raise FixtureConfigurationError(f"configured Metasploit fixture path is not a directory: {root}")
        discovered = _discover_modules(root)
        if not discovered:
            raise FixtureConfigurationError(f"configured Metasploit fixture path contains no modules: {root}")
        manifest = _read_manifest(root)
        root_digest = _root_digest(root)
        namespace = root_digest[:16]
        roots.append(str(root))
        for fullname, path in discovered.items():
            if fullname in modules:
                raise FixtureConfigurationError(f"duplicate fixture module fullname: {fullname}")
            modules[fullname] = FixtureModule(
                fullname=fullname,
                source_path=str(path),
                sha256=_sha256(path),
                modules_root=str(root),
                root_sha256=root_digest,
                namespace=namespace,
                manifest=manifest,
            )
    return ApprovedFixtureRegistry(tuple(roots), modules)


def module_fullname(root: Path, module_file: Path) -> str | None:
    try:
        rel = module_file.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    parts = rel.with_suffix("").parts
    if not parts:
        return None
    kind = MODULE_TYPE_DIRS.get(parts[0])
    if kind is None:
        return None
    return "/".join((kind, *parts[1:]))


def _discover_modules(root: Path) -> dict[str, Path]:
    output: dict[str, Path] = {}
    for path in sorted(root.rglob("*.rb")):
        fullname = module_fullname(root, path)
        if fullname:
            output[fullname] = path.resolve()
    return output


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root_digest(root: Path) -> str:
    records = []
    for path in sorted(root.rglob("*.rb")):
        fullname = module_fullname(root, path)
        if fullname:
            records.append({
                "fullname": fullname,
                "relative_path": path.resolve().relative_to(root.resolve()).as_posix(),
                "sha256": _sha256(path),
            })
    payload = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_manifest(root: Path) -> Mapping[str, Any] | None:
    candidates = (root / "manifest.json", root.parent / "manifest.json")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FixtureConfigurationError(f"fixture manifest is invalid JSON: {path}: {exc}") from exc
        if not isinstance(value, Mapping):
            raise FixtureConfigurationError(f"fixture manifest must be an object: {path}")
        return dict(value)
    return None
