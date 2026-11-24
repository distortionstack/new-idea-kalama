#!/usr/bin/env python3
"""Isolated JSON probe for id2url; intentionally not imported by production."""

from __future__ import annotations

import json
import sys

import id2url


SOURCE_ARCHIVE_REGISTRIES = {"go", "maven", "packagist"}


def probe(registry: str, origin_id: str) -> dict[str, object]:
    result: dict[str, object] = {
        "provider": "id2url 0.1.2",
        "registry": registry,
        "origin_id": origin_id,
        "artifact_kind": "SOURCE_ARCHIVE" if registry.lower() in SOURCE_ARCHIVE_REGISTRIES else "DISTRIBUTION_ARTIFACT",
        "buildable_source_tree": False,
        "status": "PROVIDER_ERROR",
        "errors": [],
    }
    try:
        package, version, url = id2url.get_download_url(registry, origin_id)
    except ValueError as error:
        message = str(error)
        lowered = message.lower()
        if "unsupported" in lowered:
            status = "UNSUPPORTED"
        elif "not found" in lowered or "does not exist" in lowered:
            status = "NOT_FOUND"
        else:
            status = "PROVIDER_ERROR"
        result["status"] = status
        result["errors"] = [{"kind": status, "message": message}]
    except Exception as error:  # provider boundary: preserve the provider error type/message
        result["errors"] = [{"kind": "PROVIDER_ERROR", "message": f"{type(error).__name__}: {error}"}]
    else:
        result.update(package=package, requested_version=version, resolved_version=version, artifact_url=url, status="FOUND")
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"provider": "id2url 0.1.2", "status": "PROVIDER_ERROR", "errors": [{"kind": "MALFORMED", "message": "registry and origin_id are required"}]}))
        return 2
    result = probe(sys.argv[1], sys.argv[2])
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "FOUND" else 1


if __name__ == "__main__":
    raise SystemExit(main())
