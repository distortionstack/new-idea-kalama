"""Bounded, read-only diagnostic for the production payload introspector.

This invokes the same adapter used by Attack Form validation and records only
its timing and returned schema.  It does not submit a form or contact a victim.
"""
from __future__ import annotations

import json
import time
import traceback

from kalama.resolver.backend import introspect_msf_payload


def main() -> None:
    started = time.time()
    report = {
        "started_at_epoch": started,
        "container": "msf-resolver-host",
        "module": "exploit/multi/http/struts2_content_type_ognl",
        "payload": "cmd/unix/reverse_bash",
        "adapter": "kalama.resolver.backend.introspect_msf_payload",
    }
    try:
        evidence = introspect_msf_payload(
            report["module"], report["payload"], report["container"]
        )
        report["outcome"] = "success"
        report["options"] = [
            {"name": option.name, "type": option.type,
             "required": option.required, "default": option.default}
            for option in evidence.options
        ]
    except Exception as exc:  # diagnostic must preserve the production error
        report["outcome"] = "error"
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    finally:
        report["ended_at_epoch"] = time.time()
        report["elapsed_seconds"] = round(report["ended_at_epoch"] - started, 3)
        print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
