from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHECKPOINT = ROOT.parent / "checkpoints" / "PATCH_REASONING_INPUT"
LABELS = ("rep_1_replacement", "rep_2", "rep_3")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
    base_bytes = (ROOT / "prompt.txt").read_bytes()
    base = base_bytes.decode("utf-8")
    evidence_parts = []
    for rel in config["model_visible_files"]:
        evidence_parts.append(
            f"\n--- BEGIN {rel} ---\n{(CHECKPOINT / rel).read_text(encoding='utf-8')}\n--- END {rel} ---"
        )
    evidence = "".join(evidence_parts)
    prompt_sha = digest(base_bytes)
    evidence_sha = digest(evidence.encode("utf-8"))
    if prompt_sha != (ROOT / "prompt_sha256.txt").read_text().strip():
        raise RuntimeError("FROZEN_PROMPT_HASH_MISMATCH")
    if evidence_sha != (ROOT / "evidence_pack_sha256.txt").read_text().strip():
        raise RuntimeError("FROZEN_EVIDENCE_HASH_MISMATCH")
    payload = {
        "model": config["model"], "prompt": base + evidence, "stream": False,
        "think": config["think"], "format": schema,
        "options": {"temperature": config["temperature"], "num_predict": config["num_predict"],
                    "num_ctx": config["num_ctx"]},
    }
    request_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request_sha = digest(request_bytes)
    for label in LABELS:
        rep = ROOT / "runs" / label
        if rep.exists():
            if (rep / "raw_response.txt").is_file() and (rep / "metrics.json").is_file():
                continue
            raise RuntimeError(f"INCOMPLETE_EXISTING_REPETITION:{label}")
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
            metrics = {k: envelope.get(k) for k in ("model", "created_at", "done", "done_reason",
                       "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration",
                       "eval_count", "eval_duration")}
            metrics.update({"label": label, "latency_seconds": round(time.time() - started, 3),
                            "timeout_seconds": config["timeout_seconds"], "json_parse": "success",
                            "prompt_sha256": prompt_sha, "evidence_pack_sha256": evidence_sha,
                            "request_sha256": request_sha, "model_digest": config["model_digest"],
                            "think": config["think"], "temperature": config["temperature"],
                            "num_predict": config["num_predict"], "num_ctx": config["num_ctx"]})
            (rep / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps({"label": label, "status": "complete", "latency_seconds": metrics["latency_seconds"],
                              "eval_count": metrics.get("eval_count")}), flush=True)
        except Exception as exc:
            (rep / "metrics.json").write_text(json.dumps({"label": label,
                "latency_seconds": round(time.time() - started, 3), "timeout_seconds": config["timeout_seconds"],
                "json_parse": "failed", "request_sha256": request_sha,
                "error_type": type(exc).__name__, "error": str(exc)}, indent=2) + "\n", encoding="utf-8")
            raise


if __name__ == "__main__":
    main()
