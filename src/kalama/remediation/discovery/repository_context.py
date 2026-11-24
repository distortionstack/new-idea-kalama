"""Resolve repository and installed-package facts from bounded target reads."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .contracts import (
    InstalledSourceMapping, RepositoryContext, RepositoryContextStatus,
    RepositoryReference,
)
from .target_filesystem import TargetFile, TargetFilesystemReader


def _safe_repository_url(value: str) -> str | None:
    from .codec import sanitize_url
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    if parts.query or "?" in value.partition("#")[0]:
        return None
    if parts.username is not None or parts.password is not None:
        return sanitize_url(value)
    return value


def _paragraphs(content: bytes) -> list[dict[str, str]]:
    records = []
    for paragraph in re.split(r"\n\s*\n", content.decode("utf-8", "replace")):
        record: dict[str, str] = {}
        current = None
        for line in paragraph.splitlines():
            if line[:1].isspace() and current:
                record[current] += "\n" + line.strip()
            elif ":" in line:
                current, value = line.split(":", 1)
                record[current] = value.strip()
        if record:
            records.append(record)
    return records


def parse_dpkg_status(content: bytes, provenance: str) -> tuple[InstalledSourceMapping, ...]:
    mappings = []
    for record in _paragraphs(content):
        if record.get("Status") != "install ok installed":
            continue
        name, version = record.get("Package"), record.get("Version")
        if not name or not version:
            continue
        source = record.get("Source", name)
        match = re.fullmatch(r"([^\s(]+)(?:\s+\(([^)]+)\))?", source)
        if not match:
            continue
        source_name = match.group(1)
        explicit_source_version = match.group(2)
        source_version = (explicit_source_version if explicit_source_version is not None
                          else None if re.search(r"\+b\d+$", version) else version)
        mappings.append(InstalledSourceMapping(
            name, version, source_name, source_version, provenance))
    return tuple(mappings)


def parse_apk_installed(content: bytes, provenance: str) -> tuple[InstalledSourceMapping, ...]:
    mappings = []
    for paragraph in re.split(r"\n\s*\n", content.decode("utf-8", "replace")):
        fields = dict(line.split(":", 1) for line in paragraph.splitlines()
                      if len(line) > 2 and line[1] == ":")
        name, version = fields.get("P"), fields.get("V")
        if name and version:
            source_name = fields.get("o") or name
            mappings.append(InstalledSourceMapping(
                name, version, source_name, version, provenance))
    return tuple(mappings)


def _os_release(content: bytes) -> dict[str, str]:
    values = {}
    for line in content.decode("utf-8", "replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip("\"'")
    return values


def _apt_repositories(files: Sequence[TargetFile]
                      ) -> tuple[tuple[RepositoryReference, ...], bool]:
    repositories = []
    rejected = False
    for item in files:
        if item.content is None:
            continue
        text = item.content.decode("utf-8", "replace")
        if item.path.endswith(".sources"):
            for record in _paragraphs(item.content):
                if record.get("Enabled", "yes").casefold() == "no":
                    continue
                uris = record.get("URIs", "").split()
                suites = record.get("Suites", "").split() or [None]
                components = record.get("Components", "").split() or [None]
                for uri in uris:
                    safe_uri = _safe_repository_url(uri)
                    if safe_uri is None:
                        rejected = True
                        continue
                    for suite in suites:
                        for component in components:
                            repositories.append(RepositoryReference(
                                safe_uri, item.provenance or item.path, suite, component))
        else:
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                fields = line.split()
                if not fields or fields[0] not in {"deb", "deb-src"}:
                    continue
                if len(fields) > 1 and fields[1].startswith("["):
                    close = next((i for i, value in enumerate(fields[1:], 1)
                                  if value.endswith("]")), None)
                    fields = [fields[0]] + fields[(close + 1 if close else 1):]
                if len(fields) >= 3:
                    safe_uri = _safe_repository_url(fields[1])
                    if safe_uri is None:
                        rejected = True
                        continue
                    for component in fields[3:] or [None]:
                        repositories.append(RepositoryReference(
                            safe_uri, item.provenance or item.path, fields[2], component))
    return tuple(repositories), rejected


class RepositoryContextResolver:
    def __init__(self, reader: TargetFilesystemReader):
        self.reader = reader

    def resolve(self, target_facts: Mapping[str, Any] | None = None) -> RepositoryContext:
        facts = target_facts or {}
        os_file = self.reader.read_file("/etc/os-release", 64 * 1024)
        os_values = _os_release(os_file.content) if os_file.content else {}
        distro = str(os_values.get("ID") or facts.get("distro") or
                     facts.get("image_distro") or facts.get("os") or "").casefold() or None
        release = os_values.get("VERSION_ID") or facts.get("distro_version") or facts.get("release")
        codename = os_values.get("VERSION_CODENAME") or facts.get("codename")
        architecture = facts.get("architecture") or facts.get("arch")
        architecture_provenance = "container_platform" if architecture else None
        platform = facts.get("platform")
        if not architecture and isinstance(platform, str) and "/" in platform:
            architecture = platform.rsplit("/", 1)[-1]
            architecture_provenance = "container_platform"
        repositories: tuple[RepositoryReference, ...] = ()
        mappings: tuple[InstalledSourceMapping, ...] = ()
        manager = None
        missing = []
        if distro in {"debian", "ubuntu"}:
            manager = "apt"
            status = self.reader.read_file("/var/lib/dpkg/status", 32 * 1024 * 1024)
            sources = [self.reader.read_file("/etc/apt/sources.list", 1024 * 1024)]
            sources.extend(self.reader.read_directory(
                "/etc/apt/sources.list.d", (".list", ".sources"), 128, 4 * 1024 * 1024))
            if status.content:
                mappings = parse_dpkg_status(status.content, status.provenance or status.path)
                if not mappings:
                    missing.append("installed_package_metadata")
                if not architecture:
                    records = _paragraphs(status.content)
                    architecture = next((x.get("Architecture") for x in records
                                         if x.get("Status") == "install ok installed"
                                         and x.get("Architecture")), None)
                    architecture_provenance = status.provenance if architecture else None
            else:
                missing.append("installed_package_metadata")
            repositories, rejected_repositories = _apt_repositories(sources)
            if rejected_repositories:
                missing.append("safe_repository_urls")
            if not repositories:
                missing.append("configured_repositories")
        elif distro == "alpine":
            manager = "apk"
            installed = self.reader.read_file("/lib/apk/db/installed", 32 * 1024 * 1024)
            repo_file = self.reader.read_file("/etc/apk/repositories", 1024 * 1024)
            if installed.content:
                mappings = parse_apk_installed(
                    installed.content, installed.provenance or installed.path)
                if not mappings:
                    missing.append("installed_package_metadata")
                if not architecture:
                    architecture = next((line[2:] for line in
                                         installed.content.decode("utf-8", "replace").splitlines()
                                         if line.startswith("A:")), None)
                    architecture_provenance = installed.provenance if architecture else None
            else:
                missing.append("installed_package_metadata")
            if repo_file.content:
                parsed_repositories = []
                for line in repo_file.content.decode("utf-8", "replace").splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    url = _safe_repository_url(line.strip())
                    if url is None:
                        missing.append("safe_repository_urls")
                        continue
                    parsed_repositories.append(RepositoryReference(
                        url, repo_file.provenance or repo_file.path))
                repositories = tuple(parsed_repositories)
            if not repositories:
                missing.append("configured_repositories")
        else:
            missing.append("supported_distribution")
        for field, value in (("distro", distro), ("release", release),
                             ("architecture", architecture)):
            if not value:
                missing.append(field)
        populated = any((distro, release, codename, architecture, repositories, mappings))
        context_status = (RepositoryContextStatus.COMPLETE if not missing
                          else RepositoryContextStatus.PARTIAL if populated
                          else RepositoryContextStatus.UNKNOWN)
        return RepositoryContext(
            distro, str(release) if release else None, str(codename) if codename else None,
            str(architecture) if architecture else None, manager, repositories, mappings,
            tuple(sorted(set(missing))), context_status, architecture_provenance)
