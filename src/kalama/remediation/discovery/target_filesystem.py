"""Bounded, read-only access to approved target-container metadata."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
import tarfile
import threading
from typing import BinaryIO, Callable, Sequence


_ALLOWED_FILES = {
    "/etc/os-release", "/var/lib/dpkg/status", "/etc/apt/sources.list",
    "/lib/apk/db/installed", "/etc/apk/repositories",
}
_ALLOWED_DIRECTORIES = {"/etc/apt/sources.list.d"}
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_TAR_OVERHEAD_PER_MEMBER = 10 * 1024


@dataclass(frozen=True)
class TargetFile:
    path: str
    content: bytes | None
    status: str
    sha256: str | None = None
    provenance: str | None = None


class _LimitExceeded(Exception):
    pass


class _BoundedStream:
    def __init__(self, source: BinaryIO, limit: int):
        self.source = source
        self.remaining = limit

    def read(self, size: int = -1) -> bytes:
        requested = self.remaining + 1 if size < 0 else min(size, self.remaining + 1)
        chunk = self.source.read(requested)
        if len(chunk) > self.remaining:
            raise _LimitExceeded
        self.remaining -= len(chunk)
        return chunk


class TargetFilesystemReader:
    def __init__(self, runner, container_name: str | None, *, timeout: float = 10.0,
                 process_factory: Callable | None = None):
        self.runner = runner
        self.container_name = container_name
        self.timeout = timeout
        self.process_factory = process_factory or getattr(runner, "popen", None)

    @staticmethod
    def _safe_path(path: str, *, directory: bool = False) -> str:
        parsed = PurePosixPath(path)
        normalized = str(parsed)
        allowed = _ALLOWED_DIRECTORIES if directory else _ALLOWED_FILES
        if not path.startswith("/") or ".." in parsed.parts or normalized not in allowed:
            raise ValueError("target metadata path is not allowed")
        return normalized

    def _available(self) -> bool:
        return (callable(self.process_factory) and isinstance(self.container_name, str)
                and _CONTAINER_NAME.fullmatch(self.container_name) is not None)

    @staticmethod
    def _member_path(name: str, requested_path: str, directory: bool) -> str | None:
        parts = PurePosixPath(name.lstrip("./")).parts
        if not parts or ".." in parts:
            raise ValueError("unsafe TAR member path")
        relative = "/".join(parts)
        full = requested_path.lstrip("/")
        base = PurePosixPath(requested_path).name
        if relative in {full, base}:
            return requested_path
        if directory:
            for prefix in (full, base):
                if relative.startswith(prefix + "/"):
                    return requested_path.rstrip("/") + relative[len(prefix):]
        return None

    @staticmethod
    def _error_status(stderr: bytes, return_code: int) -> str:
        text = stderr.decode("utf-8", "replace").casefold()
        if any(x in text for x in ("no such file", "not found",
                                   "could not find the file")):
            return "MISSING"
        if any(x in text for x in ("permission denied", "operation not permitted",
                                   "read-only file system", "cannot open")):
            return "UNREADABLE"
        if any(x in text for x in ("no such container", "is not running",
                                   "cannot connect to the docker daemon")):
            return "TARGET_UNAVAILABLE"
        return "UNREADABLE" if return_code else "MISSING"

    @staticmethod
    def _stop(process) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except Exception:
                process.kill()
                process.wait(timeout=1)

    def _stream(self, path: str, suffixes: tuple[str, ...], max_files: int,
                max_total_bytes: int) -> tuple[TargetFile, ...]:
        if not self._available():
            return (TargetFile(path, None, "TARGET_UNAVAILABLE"),)
        argv = ("docker", "cp", f"{self.container_name}:{path}", "-")
        try:
            process = self.process_factory(argv)
        except Exception:
            return (TargetFile(path, None, "TARGET_UNAVAILABLE"),)
        timer = threading.Timer(self.timeout, self._stop, (process,))
        timer.daemon = True
        timer.start()
        output = []
        total = 0
        stream_limit = max_total_bytes + _TAR_OVERHEAD_PER_MEMBER * (max_files + 2)
        try:
            if process.stdout is None:
                return (TargetFile(path, None, "TARGET_UNAVAILABLE"),)
            stream = _BoundedStream(process.stdout, stream_limit)
            try:
                archive = tarfile.open(fileobj=stream, mode="r|*")
                for member in archive:
                    member_path = self._member_path(
                        member.name, path, bool(suffixes))
                    if member.isdir():
                        continue
                    if member_path is None or not member.isreg():
                        return (TargetFile(path, None, "UNREADABLE"),)
                    if suffixes and PurePosixPath(member_path).suffix not in suffixes:
                        continue
                    if len(output) >= max_files or member.size > max_total_bytes - total:
                        raise _LimitExceeded
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        return (TargetFile(member_path, None, "UNREADABLE"),)
                    content = extracted.read(member.size + 1)
                    if len(content) != member.size:
                        return (TargetFile(member_path, None, "UNREADABLE"),)
                    digest = hashlib.sha256(content).hexdigest()
                    output.append(TargetFile(
                        member_path, content, "READ", digest,
                        f"docker cp:{member_path};sha256:{digest}"))
                    total += len(content)
            except _LimitExceeded:
                self._stop(process)
                return (TargetFile(path, None, "TOO_LARGE"),)
            except (tarfile.TarError, ValueError, OSError):
                pass
            return_code = process.wait(timeout=max(1.0, self.timeout))
            stderr = process.stderr.read(4096) if process.stderr is not None else b""
            if return_code != 0:
                return (TargetFile(path, None,
                                   self._error_status(stderr, return_code)),)
            return tuple(output) or (TargetFile(path, None, "UNREADABLE"),)
        finally:
            timer.cancel()
            self._stop(process)
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()

    def read_file(self, path: str, max_bytes: int) -> TargetFile:
        safe_path = self._safe_path(path)
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        return self._stream(safe_path, (), 1, max_bytes)[0]

    def read_directory(self, path: str, allowed_suffixes: Sequence[str],
                       max_files: int, max_total_bytes: int) -> tuple[TargetFile, ...]:
        safe_path = self._safe_path(path, directory=True)
        suffixes = tuple(x for x in allowed_suffixes if x.startswith("."))
        if not suffixes or max_files <= 0 or max_total_bytes <= 0:
            raise ValueError("directory read bounds must be positive")
        return self._stream(safe_path, suffixes, max_files, max_total_bytes)
