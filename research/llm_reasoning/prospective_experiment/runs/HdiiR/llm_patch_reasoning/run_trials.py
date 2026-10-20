from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHECKPOINT = ROOT.parent / "checkpoints" / "PATCH_REASONING_INPUT"
FROZEN = CHECKPOINT / "frozen_evidence"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    schema_bytes = (ROOT / "schema.json").read_bytes()
    schema = json.loads(schema_bytes)
    base = (ROOT / "prompt.txt").read_text(encoding="utf-8")
    parts = []
    for rel in config["model_visible_files"]:
        path = CHECKPOINT / rel
        parts.append(f"\n--- BEGIN {rel} ---\n{path.read_text(encoding='utf-8')}\n--- END {rel} ---")
    evidence = "".join(parts)
    evidence_sha = sha(evidence.encode("utf-8"))
    prompt_sha = sha(base.encode("utf-8"))
    (ROOT / "prompt_sha256.txt").write_text(prompt_sha + "\n", encoding="utf-8")
    (ROOT / "evidence_pack_sha256.txt").write_text(evidence_sha + "\n", encoding="utf-8")
    payload = {
        "model": config["model"], "prompt": base + evidence, "stream": False,
        "think": config["think"], "format": schema,
        "options": {"temperature": config["temperature"], "num_predict": config["num_predict"],
                    "num_ctx": config["num_ctx"]},
    }
    request_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for index in range(1, config["repetitions"] + 1):
        rep = ROOT / "runs" / f"rep_{index}"
        rep.mkdir(parents=True, exist_ok=False)
        started = time.time()
        request = urllib.request.Request(config["endpoint"], data=request_bytes,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=config["timeout_seconds"]) as response:
                envelope = json.loads(response.read())
            raw = str(envelope.get("response", ""))
            (rep / "raw_response.txt").write_text(raw, encoding="utf-8")
            parsed = json.loads(raw)
            (rep / "parsed_proposal.json").write_text(
                json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            metrics = {k: envelope.get(k) for k in ("done_reason", "total_duration", "load_duration",
                       "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration")}
            metrics.update({"latency_seconds": round(time.time() - started, 3), "timeout_seconds": config["timeout_seconds"],
                            "json_parse": "success", "prompt_sha256": prompt_sha,
                            "evidence_pack_sha256": evidence_sha})
            (rep / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception as exc:
            (rep / "metrics.json").write_text(json.dumps({"latency_seconds": round(time.time() - started, 3),
                "timeout_seconds": config["timeout_seconds"], "json_parse": "failed",
                "error_type": type(exc).__name__, "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
            raise


if __name__ == "__main__":
    main()
