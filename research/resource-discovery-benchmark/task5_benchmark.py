#!/usr/bin/env python3
"""Live Task 5 benchmark. Offline tests consume its committed sanitized output."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "task5-fixtures"
CASES = (
    ("maven", "pkg:maven/org.apache.commons/commons-lang3@3.12.0", "maven", "org.apache.commons:commons-lang3:3.12.0"),
    ("npm", "pkg:npm/lodash@4.17.21", "npm", "lodash/4.17.21"),
    ("pypi", "pkg:pypi/requests@2.31.0", "pypi", "requests/2.31.0"),
    ("cargo", "pkg:cargo/serde@1.0.197", "crates", "serde/1.0.197"),
    ("go", "pkg:golang/github.com/gorilla/mux@v1.8.0", "go", "github.com/gorilla/mux/v1.8.0"),
    ("nuget", "pkg:nuget/Newtonsoft.Json@13.0.3", "nuget", "Newtonsoft.Json/13.0.3"),
    ("composer", "pkg:composer/monolog/monolog@3.5.0", "packagist", "monolog/monolog/3.5.0"),
    ("rubygems", "pkg:gem/rake@13.2.1", "rubygems", "rake/13.2.1"),
    ("hex", "pkg:hex/plug@1.16.0", "hex", "plug/1.16.0"),
)


def _run(
    command: list[str], *, env: dict[str, str] | None = None, timeout: float = 25, max_output_bytes: int = 256 * 1024
) -> dict[str, object]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "PROVIDER_ERROR", "errors": [{"kind": "TIMEOUT", "message": "provider process timed out"}]}
    if len(completed.stdout.encode()) > max_output_bytes:
        return {"status": "PROVIDER_ERROR", "errors": [{"kind": "TOO_LARGE", "message": "provider output exceeded limit"}]}
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "PROVIDER_ERROR", "errors": [{"kind": "MALFORMED_RESPONSE", "message": "provider returned invalid JSON"}]}


def _sanitize(value: object) -> object:
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items() if key.lower() not in {"authorization", "credential", "password", "token"}}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        split = urlsplit(value)
        host = split.hostname or ""
        if split.port:
            host = f"{host}:{split.port}"
        return urlunsplit((split.scheme, host, split.path, "", ""))
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-resolver", required=True)
    parser.add_argument("--id2url-wheel", required=True)
    args = parser.parse_args()
    env = dict(os.environ)
    env["PYTHONPATH"] = args.id2url_wheel
    results: list[dict[str, object]] = []
    for ecosystem, purl, registry, origin_id in CASES:
        results.append({"case": ecosystem, "registries": _run([args.go_resolver, purl])})
        results.append({"case": ecosystem, "id2url": _run([sys.executable, str(ROOT / "id2url_probe.py"), registry, origin_id], env=env)})
    results.extend((
        {"case": "composer-v-prefix", "id2url": _run([sys.executable, str(ROOT / "id2url_probe.py"), "packagist", "monolog/monolog/v3.5.0"], env=env)},
        {"case": "nonexistent-version", "registries": _run([args.go_resolver, "pkg:npm/lodash@9999.9999.9999"])},
        {"case": "nonexistent-version", "id2url": _run([sys.executable, str(ROOT / "id2url_probe.py"), "npm", "lodash/9999.9999.9999"], env=env)},
        {"case": "unsupported", "id2url": _run([sys.executable, str(ROOT / "id2url_probe.py"), "unsupported", "package/1.0.0"], env=env)},
        {"case": "malformed", "registries": _run([args.go_resolver, "not-a-purl"])},
        {"case": "malformed", "id2url": _run([sys.executable, str(ROOT / "id2url_probe.py"), "npm", "malformed"], env=env)},
    ))
    FIXTURES.mkdir(exist_ok=True)
    destination = FIXTURES / "provider-results.json"
    destination.write_text(json.dumps(_sanitize(results), indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(results), "fixture": str(destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
