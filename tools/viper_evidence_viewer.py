"""Local read-only evidence viewer for a VIPER run.

Usage: python tools/viper_evidence_viewer.py --run-id X40Ks --output-root output
Then open http://127.0.0.1:8765/ in a normal browser and use the browser's
native screenshot tool. The viewer only reads canonical state and artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


STAGES = [
    ("01", "Environment Doctor and Readiness", None),
    ("02", "Target Preparation", "STEP_2_TARGET_SCAN"),
    ("03", "Trivy BEFORE Scan", "STEP_2_TARGET_SCAN"),
    ("04", "Top-N Prioritization", "STEP_3_PRIORITIZATION"),
    ("05", "Resolver and Attack Form", "STEP_4_RESOLVER"),
    ("06", "BEFORE Exploit", "STEP_4_BEFORE_EXPLOIT"),
    ("07", "Remediation Discovery and Patch Form", "STEP_5_PATCH_PLAN"),
    ("08", "Patch Plan and Execution", "STEP_5_PATCH_EXECUTION"),
    ("09", "Trivy AFTER Scan", "STEP_6_AFTER_SCAN"),
    ("10", "AFTER Re-exploitation", "STEP_7_REEXPLOIT"),
    ("11", "Final Evaluation", "STEP_8_EVALUATION"),
]


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_run(root: Path, run_id: str) -> dict:
    state_path = root / "state" / f"run_{run_id}.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    artifacts = []
    for kind, ref in (state.get("artifacts") or {}).items():
        path = Path(ref.get("path", ""))
        artifacts.append({
            "kind": kind, "path": str(path), "schema": ref.get("schema"),
            "created_at": ref.get("created_at"), "sha256": ref.get("sha256"),
            "exists": path.is_file(), "actual_sha256": sha256(path),
        })
    stages = []
    for number, title, key in STAGES:
        if key is None:
            status = "READY" if state.get("status") else "UNKNOWN"
            started = completed = None
        else:
            item = (state.get("stages") or {}).get(key, {})
            status = item.get("status", "NOT_STARTED")
            started, completed = item.get("started_at"), item.get("completed_at")
        stages.append({"number": number, "title": title, "stage": key,
                       "status": status, "started_at": started, "completed_at": completed})
    return {"run_id": run_id, "state_path": str(state_path), "state": state,
            "stages": stages, "artifacts": artifacts}


HTML = r'''<!doctype html><html><head><meta charset="utf-8"><title>VIPER Evidence Viewer</title>
<style>body{font:14px system-ui;margin:24px;background:#111827;color:#e5e7eb}h1{color:#93c5fd}.meta,.card{background:#1f2937;border:1px solid #374151;border-radius:8px;padding:14px;margin:10px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}.done{border-left:5px solid #22c55e}.wait{border-left:5px solid #f59e0b}.bad{border-left:5px solid #ef4444}.pending{border-left:5px solid #6b7280}code,pre{white-space:pre-wrap;word-break:break-word;color:#bfdbfe}small{color:#9ca3af}</style></head>
<body><h1>VIPER Evidence Viewer</h1><div id="app">Loading canonical evidence…</div>
<script>
const q=new URLSearchParams(location.search);const run=q.get('run')||'X40Ks';
function esc(v){return String(v??'').replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]))}
function cls(s){s=String(s);return /SUCCEEDED|READY|COMPLETED/.test(s)?'done':/WAIT|RUNNING/.test(s)?'wait':/FAIL/.test(s)?'bad':'pending'}
fetch('/api/run/'+encodeURIComponent(run)).then(r=>r.json()).then(d=>{let s=d.state||{};let h=`<div class="meta"><b>Run:</b> ${esc(d.run_id)} &nbsp; <b>Status:</b> ${esc(s.status)} &nbsp; <b>Current:</b> ${esc(s.current_stage)}<br><b>Image:</b> ${esc(s.target?.image_identity?.canonical_identity||s.request?.victim_image)}<br><b>Target:</b> ${esc(s.target?.facts?.container_name)} / ${esc(s.target?.facts?.ip_address)}<br><small>State: ${esc(d.state_path)} | Updated: ${esc(s.updated_at)}</small></div><h2>11 Pipeline Stages</h2><div class="grid">`;
d.stages.forEach(x=>h+=`<div class="card ${cls(x.status)}"><b>${x.number} — ${esc(x.title)}</b><br>Status: <code>${esc(x.status)}</code><br><small>Started: ${esc(x.started_at)}<br>Completed: ${esc(x.completed_at)}</small></div>`);h+='</div><h2>Canonical Artifacts</h2>';
d.artifacts.forEach(a=>h+=`<div class="card ${a.exists?'done':'bad'}"><b>${esc(a.kind)}</b><br>${esc(a.path)}<br>Declared SHA-256: <code>${esc(a.sha256)}</code><br>Actual SHA-256: <code>${esc(a.actual_sha256)}</code><br>Exists: ${esc(a.exists)} | Created: ${esc(a.created_at)}</div>`);h+=`<h2>Screenshot workflow</h2><p>Use the browser's native screenshot command on this page. These are <b>evidence-viewer screenshots</b>, not live terminal screenshots. The page is read-only and shows only canonical evidence; missing stages remain pending.</p>`;document.querySelector('#app').innerHTML=h}).catch(e=>document.querySelector('#app').innerHTML='<div class="card bad">Viewer error: '+esc(e)+'</div>');
</script></body></html>'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", type=Path, default=Path("output"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    root = args.output_root.resolve()
    run_id = args.run_id

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/" or parsed.path == "/index.html":
                body = HTML.replace("X40Ks", run_id).encode()
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            elif parsed.path.startswith("/api/run/"):
                requested = parsed.path.rsplit("/", 1)[-1]
                body = json.dumps(load_run(root, requested), indent=2, default=str).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
            else:
                self.send_error(404); return
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, fmt, *args):  # noqa: N802
            print("[viewer]", fmt % args)

    print(f"VIPER Evidence Viewer: http://{args.host}:{args.port}/?run={run_id}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
