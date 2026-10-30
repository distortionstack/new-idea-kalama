"""Read-only VIPER presentation adapter over canonical state and artifacts."""
from __future__ import annotations
import argparse, hashlib, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
try:
    import yaml
except ImportError:
    yaml = None

STEPS = (
    ("สแกน", (("สแกน target", "STEP_2_TARGET_SCAN"),)),
    ("จัดลำดับ", (("จัดลำดับ CVE", "STEP_3_PRIORITIZATION"),)),
    ("ทดสอบ", (("เตรียมทดสอบ", "STEP_4_RESOLVER"), ("ดำเนินการทดสอบ", "STEP_4_BEFORE_EXPLOIT"))),
    ("อัปเดต", (("วางแผนแก้", "STEP_5_PATCH_PLAN"), ("ดำเนินการแก้", "STEP_5_PATCH_EXECUTION"),
                ("แก้ไข (stage เดิม)", "STEP_5_PATCH"))),
    ("สแกนซ้ำ", (("สแกนหลังแก้", "STEP_6_AFTER_SCAN"),)),
    ("ทดสอบซ้ำ", (("ทดสอบหลังแก้", "STEP_7_REEXPLOIT"),)),
)

def read(path):
    try:
        text = path.read_text()
        return yaml.safe_load(text) if path.suffix in (".yaml", ".yml") and yaml else json.loads(text)
    except (OSError, ValueError):
        return None

def digest(path):
    if not path.is_file(): return None
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): value.update(chunk)
    return value.hexdigest()

def scan_findings(scan):
    return [{"cve": item.get("VulnerabilityID"), "package": item.get("PkgName"),
             "installed": item.get("InstalledVersion"), "fixed": item.get("FixedVersion"),
             "severity": item.get("Severity"), "target": result.get("Target")}
            for result in (scan or {}).get("Results", []) for item in result.get("Vulnerabilities", [])]

def view(root, run_id):
    state_path = root / "state" / ("run_" + run_id + ".json")
    state = read(state_path)
    if not isinstance(state, dict): raise FileNotFoundError("No canonical state for run " + run_id)
    artifacts, raw = [], {}
    for kind, ref in (state.get("artifacts") or {}).items():
        path = Path(ref.get("path", "")); raw[kind] = read(path)
        sha = ref.get("sha256")
        artifacts.append({"kind": kind, "path": str(path), "schema": ref.get("schema"),
          "sha": sha, "short_sha": sha if not sha or len(sha) < 20 else sha[:10] + "…" + sha[-7:],
          "exists": path.is_file(), "actual_sha": digest(path)})
    scan = scan_findings(raw.get("TRIVY_BEFORE")); cves = []
    for cve, item in (state.get("cves") or {}).items():
        hits = [row for row in scan if row["cve"] == cve]; first = hits[0] if hits else {}
        cves.append({"id": cve + "|" + (first.get("package") or "") + "|" + (first.get("target") or ""),
          "cve": cve, "rank": item.get("rank"), "resolver": item.get("resolver_status"),
          "patch": item.get("patch_action_status"), "after_scan": item.get("after_scan_status"),
          "retest": item.get("after_exploit_disposition"), "remediation": item.get("remediation_status"),
          "occurrences": len(hits), **first})
    cves.sort(key=lambda row: (row["rank"] is None, row["rank"] or 999, row["cve"]))
    attack, plan = raw.get("ATTACK_BEFORE") or {}, raw.get("PATCH_PLAN") or {}
    return {"run_id": run_id, "state_path": str(state_path), "state": state, "artifacts": artifacts,
      "scan": scan, "cves": cves, "stages": [{"label": label, "details": [{"label": name, "key": key,
      "status": (state.get("stages") or {}).get(key, {}).get("status", "NOT_STARTED")}
      for name, key in details]} for label, details in STEPS],
      "attack": {"summary": attack.get("summary", {}), "cves": attack.get("cves", []) or []},
      "patch": {"summary": plan.get("summary", {}), "actions": plan.get("actions", []) or []},
      "forms": {"attack": raw.get("ATTACK_FORM"), "patch": raw.get("PATCH_FORM")}}

HTML = """<!doctype html><html lang="th"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VIPER</title>
<style>:root{--g:#16835e;--p:#e8f5ed;--i:#16342a;--m:#61736b;--l:#dbe7e0;--b:#f5f8f6}*{box-sizing:border-box}body{margin:0;background:var(--b);color:var(--i);font:14px/1.45 system-ui,-apple-system,"Noto Sans Thai",sans-serif}.app{max-width:1480px;margin:auto;padding:18px 26px}.top{display:flex;justify-content:space-between;gap:14px}.ey{color:var(--g);font-size:12px;font-weight:700;letter-spacing:.08em}h1{font-size:30px;margin:2px 0}h2{font-size:18px;margin:20px 0 9px}.muted,small{color:var(--m)}.run,.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.pill{display:inline-flex;gap:5px;border:1px solid var(--l);background:#fff;border-radius:999px;padding:4px 9px;font-size:12px}.ok{color:var(--g);background:var(--p)}.warn{color:#a66000;background:#fff5e5}.bad{color:#b42318;background:#fff0ee}.steps{display:flex;flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;max-width:100%;padding:17px 0 11px}.step{position:relative;flex:0 0 140px;width:140px;padding-right:0}.step:after{content:"";height:2px;background:var(--l);position:absolute;top:15px;left:16px;width:140px;z-index:0}.step:last-child:after{display:none}.dot{position:relative;z-index:1;width:32px;height:32px;display:grid;place-items:center;border:2px solid var(--l);border-radius:50%;background:#fff;font-weight:700}.step.ok .dot{background:var(--g);color:#fff;border-color:var(--g)}.step.bad .dot{border-color:#b42318}.step.warn .dot{border-color:#e5a33b}.tabs{display:flex;overflow-x:auto;border-bottom:1px solid var(--l)}button,input{font:inherit}button{cursor:pointer}.tab{border:0;background:transparent;padding:11px 14px;color:var(--m);white-space:nowrap;border-bottom:3px solid transparent}.tab.active{color:var(--g);font-weight:700;border-color:var(--g)}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}.card,details{background:#fff;border:1px solid var(--l);border-radius:10px;padding:13px}.metric{font-size:26px;font-weight:750}.notice{border-left:4px solid var(--g);background:var(--p);padding:10px;margin:10px 0}.table{overflow:auto;background:#fff;border:1px solid var(--l);border-radius:10px}table{border-collapse:collapse;width:100%;min-width:720px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #edf2ee;vertical-align:top}th{font-size:12px;color:var(--m);background:#fbfdfc}tr:last-child td{border:0}.link{color:var(--g);font-weight:700;border:0;background:none;padding:0}.tools input{padding:8px;border:1px solid var(--l);border-radius:7px}.bar{height:10px;display:flex;border-radius:99px;overflow:hidden;background:#e9eeeb;margin:9px 0}.empty{padding:22px;text-align:center;color:var(--m);background:#fff;border:1px dashed var(--l);border-radius:10px}summary{font-weight:700;cursor:pointer}pre{white-space:pre-wrap;word-break:break-word;font-size:12px;background:#f7faf8;padding:8px}dialog{border:0;border-radius:12px;width:min(720px,calc(100% - 30px));box-shadow:0 18px 70px #1234}.close{float:right;border:0;background:none;font-size:22px}@media(max-width:700px){.app{padding:14px}.top{display:block}h1{font-size:28px}}</style>
<main class="app"><header class="top"><div><div class="ey">VIPER · Evidence viewer</div><h1>รายละเอียดงาน</h1><div id="identity" class="muted"></div></div><div id="run" class="run"></div></header><div id="steps" class="steps"></div><nav id="tabs" class="tabs"></nav><section id="panel"></section></main><dialog id="modal"><button class="close" onclick="modal.close()">×</button><div id="modalBody"></div></dialog>
<script>
const run=new URLSearchParams(location.search).get("run")||"X40Ks",E=x=>String(x??"—").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c])),T={COMPLETED:"เสร็จแล้ว",SUCCEEDED:"เสร็จแล้ว",RUNNING:"กำลังทำงาน",PAUSED:"รอข้อมูล",WAITING:"รอข้อมูล",WAITING_FOR_USER_INPUT:"รอข้อมูล",FAILED:"ล้มเหลว",FAILED_FATAL:"ล้มเหลว",NOT_STARTED:"ยังไม่เริ่ม",SKIPPED:"ข้าม"},tabs={overview:"ภาพรวม",vulnerabilities:"ช่องโหว่",scan:"การสแกน",test:"การทดสอบ",patch:"การอัปเดต",rescan:"การสแกนซ้ำ",retest:"ทดสอบซ้ำ",log:"บันทึก"};let D,A="overview",F="";
const label=s=>T[s]||s||"ไม่มีข้อมูล",cl=s=>/SUCCEEDED|COMPLETED/.test(s||"")?"ok":/FAIL/.test(s||"")?"bad":/RUNNING|WAITING|PAUSED|RETRY/.test(s||"")?"warn":"",badge=s=>"<span class=\\"pill "+cl(s)+"\\">"+E(label(s))+" <small>"+E(s)+"</small></span>";
function table(rows,cols){if(!rows.length)return "<div class=\\"empty\\">ไม่มีข้อมูลสำหรับ run นี้</div>";return "<div class=\\"table\\"><table><thead><tr>"+cols.map(x=>"<th>"+x[0]+"</th>").join("")+"</tr></thead><tbody>"+rows.map((r,i)=>"<tr>"+cols.map(x=>"<td>"+x[1](r,i)+"</td>").join("")+"</tr>").join("")+"</tbody></table></div>"}
function tech(){return "<details><summary>รายละเอียดทางเทคนิคและ artifact ("+D.artifacts.length+")</summary>"+table(D.artifacts,[["Artifact",x=>E(x.kind)],["สถานะ",x=>x.exists?"พร้อมอ่าน":"ไม่พบไฟล์"],["Hash",x=>"<code>"+E(x.short_sha)+"</code>"],["Schema",x=>E(x.schema)]])+"<p class=\\"muted\\">State: "+E(D.state_path)+"</p></details>"}
function header(){let s=D.state,img=s.target?.image_identity?.canonical_identity||s.request?.victim_image||s.victim_image;identity.innerHTML="Image: <b>"+E(img)+"</b> · Run ID: <b>"+E(D.run_id)+"</b>";runEl.innerHTML=badge(s.status)+"<span class=\\"pill\\">กำลังดู revision ล่าสุดของ run นี้</span>";steps.innerHTML=D.stages.map((x,i)=>{let statuses=x.details.map(y=>y.status),q=statuses.includes("FAILED")?"FAILED":statuses.includes("WAITING")?"WAITING":statuses.includes("RUNNING")?"RUNNING":statuses.every(y=>y==="SUCCEEDED")?"SUCCEEDED":"NOT_STARTED";return "<div class=\\"step "+cl(q)+"\\"><div class=\\"dot\\">"+(i+1)+"</div><b>"+x.label+"</b><br><small>"+label(q)+"</small><details><summary>ขั้นย่อย</summary>"+x.details.map(y=>"<div>"+E(y.label)+" · "+E(label(y.status))+" <small>"+E(y.key)+"</small></div>").join("")+"</details></div>"}).join("");tabsEl.innerHTML=Object.entries(tabs).map(([k,v])=>"<button class=\\"tab "+(A===k?"active":"")+"\\" onclick=\\"A='"+k+"';draw()\\">"+v+"</button>").join("")}
function overview(){let c={};D.cves.forEach(x=>c[x.resolver||"UNKNOWN"]=(c[x.resolver||"UNKNOWN"]||0)+1);let v=D.cves.filter(x=>x.remediation==="VERIFIED").length;return "<h2>สรุปผลที่ต้องรู้</h2><div class=\\"summary\\"><div class=\\"card\\"><span class=\\"muted\\">กระบวนการ</span><div class=\\"metric\\">"+E(label(D.state.status))+"</div><small>"+E(D.state.current_stage)+"</small></div><div class=\\"card\\"><span class=\\"muted\\">CVE ที่ถูกเลือก</span><div class=\\"metric\\">"+D.cves.length+"</div><small>นับ CVE ไม่ซ้ำ</small></div><div class=\\"card\\"><span class=\\"muted\\">ผลการแก้ไข</span><div class=\\"metric\\">ยืนยันได้ "+v+" / "+D.cves.length+"</div><small>ไม่สรุปหากไม่มีผลหลังแก้</small></div><div class=\\"card\\"><span class=\\"muted\\">รอยืนยันแผน</span><div class=\\"metric\\">"+(D.patch.summary.waiting_actions||0)+"</div></div></div><div class=\\"notice\\">สถานะกระบวนการแยกจากผลด้านช่องโหว่: stage ที่เสร็จแล้วไม่เท่ากับแก้ช่องโหว่สำเร็จ</div><h2>สถานะ resolver</h2>"+Object.entries(c).map(([k,v])=>"<span class=\\"pill\\">"+E(k)+": "+v+"</span>").join(" ")+tech()}
function vulns(){let r=D.cves.filter(x=>JSON.stringify(x).toLowerCase().includes(F.toLowerCase()));return "<h2>ช่องโหว่ที่จัดลำดับแล้ว</h2><p class=\\"muted\\">CVE ไม่ซ้ำจาก state; occurrences มาจาก scanner ของ run นี้</p><div class=\\"tools\\"><input value=\\""+E(F)+"\\" placeholder=\\"ค้นหา CVE หรือ package\\" oninput=\\"F=this.value;draw()\\"><span>"+r.length+" / "+D.cves.length+"</span></div>"+table(r,[["อันดับ",x=>x.rank??"—"],["CVE",x=>"<b>"+E(x.cve)+"</b>"],["Package / version",x=>E(x.package)+"<br><small>"+E(x.installed)+" → "+E(x.fixed)+"</small>"],["Severity",x=>badge(x.severity)],["สถานะ",x=>badge(x.resolver)],["Occurrences",x=>x.occurrences],["เปิด",x=>"<button class=\\"link\\" onclick=\\"cve('"+E(x.id)+"')\\">รายละเอียด</button>"]])+tech()}
function scan(){return "<h2>ผลการสแกนก่อนอัปเดต</h2><div class=\\"summary\\"><div class=\\"card\\"><span class=\\"muted\\">Image ที่สแกน</span><br><b>"+E(D.state.request?.victim_image||D.state.victim_image)+"</b></div><div class=\\"card\\"><span class=\\"muted\\">รายการที่พบ</span><div class=\\"metric\\">"+D.scan.length+"</div><small>occurrences จาก scanner</small></div></div>"+table(D.scan,[["CVE",x=>E(x.cve)],["Package",x=>E(x.package)],["เวอร์ชัน",x=>E(x.installed)+" → "+E(x.fixed)],["Severity",x=>badge(x.severity)],["Target",x=>E(x.target)]])+tech()}
function test(){let g={};D.attack.cves.forEach(x=>g[x.disposition||"NOT_EXECUTED"]=(g[x.disposition||"NOT_EXECUTED"]||0)+1);let n=D.attack.cves.length||D.cves.length,r=D.attack.cves.filter(x=>!F||JSON.stringify(x).includes(F));return "<h2>ผลการทดสอบก่อนอัปเดต</h2><p class=\\"muted\\">ไม่ตีความ EXPLOIT_FAILED ว่าปลอดภัย และแยก resolver จากผล execution</p><div class=\\"bar\\">"+Object.entries(g).map(([k,v],i)=>"<span style=\\"width:"+(100*v/n)+"%;background:"+["#16835e","#b42318","#d97706","#61736b"][i%4]+"\\" title=\\""+E(k)+" "+v+"\\"></span>").join("")+"</div>"+Object.entries(g).map(([k,v])=>"<button class=\\"pill\\" onclick=\\"F='"+E(k)+"';draw()\\">"+E(k)+" · "+v+"</button>").join(" ")+"<div class=\\"tools\\"><button onclick=\\"F='';draw()\\">ล้างตัวกรอง</button><span class=\\"muted\\">ตัวหาร: "+D.attack.cves.length+" CVE</span></div>"+table(r,[["CVE",x=>E(x.cve_id)],["อันดับ",x=>x.rank??"—"],["ผล execution",x=>badge(x.disposition)],["Oracle",x=>E(x.oracle?.verdict)],["การเตรียม",x=>E(x.config_status)],["เปิด",x=>"<button class=\\"link\\" onclick=\\"attack('"+E(x.cve_id)+"')\\">ฟอร์ม/หลักฐาน</button>"]])+tech()}
function patch(){return "<h2>แผนการอัปเดต</h2><div class=\\"summary\\"><div class=\\"card\\"><span class=\\"muted\\">Action สำเร็จ / ทั้งหมด</span><div class=\\"metric\\">0 / "+D.patch.actions.length+"</div><small>ไม่มี PATCH_RESULT จึงไม่มี action ที่ยืนยันว่าดำเนินการแล้ว</small></div><div class=\\"card\\"><span class=\\"muted\\">รอยืนยันแผน</span><div class=\\"metric\\">"+(D.patch.summary.waiting_actions||0)+"</div></div></div>"+table(D.patch.actions,[["Action ID",x=>E(x.action_id)],["Package",x=>E(x.package_name)+"<br><small>"+E((x.before_versions||[]).join(", "))+" → "+E(x.candidate?.target_version)+"</small>"],["CVE ที่เกี่ยวข้อง",x=>E((x.target_cves||[]).join(", "))],["สถานะ",x=>badge(x.status)],["เปิด",x=>"<button class=\\"link\\" onclick=\\"patchForm('"+E(x.action_id)+"')\\">Patch form</button>"]])+tech()}
function after(kind){let stage=kind==="rescan"?"STEP_6_AFTER_SCAN":"STEP_7_REEXPLOIT",field=kind==="rescan"?"after_scan":"retest",name=kind==="rescan"?"สแกนซ้ำ":"ทดสอบซ้ำ";return "<h2>"+name+"</h2><div class=\\"notice\\">"+(D.state.stages?.[stage]?.status==="SUCCEEDED"?"มีผลตามหลักฐานด้านล่าง":"ยังไม่มี artifact ผลหลังแก้ — ไม่ถือว่า “ไม่พบ” หรือ “ปลอดภัย”")+"</div>"+table(D.cves,[["CVE",x=>E(x.cve)],["ก่อน",x=>E(x.resolver)],["หลัง",x=>E(x[field])],["ข้อสรุป remediation",x=>E(x.remediation||"ยังยืนยันไม่ได้")]])+tech()}
function logs(){let r=[...(D.state.errors||[]).map(x=>({...x,level:"ERROR"})),...(D.state.warnings||[]).map(x=>({...x,level:"WARNING"}))].sort((a,b)=>String(a.timestamp).localeCompare(String(b.timestamp)));return "<h2>บันทึกเหตุการณ์</h2>"+table(r,[["เวลา",x=>E(x.timestamp)],["ขั้นตอน",x=>E(x.stage)],["ระดับ",x=>badge(x.level)],["ข้อความ",x=>E(x.message)],["รหัส",x=>E(x.code)]])+tech()}
function draw(){header();panel.innerHTML=A==="overview"?overview():A==="vulnerabilities"?vulns():A==="scan"?scan():A==="test"?test():A==="patch"?patch():A==="rescan"?after("rescan"):A==="retest"?after("retest"):logs()}
function open(x){modalBody.innerHTML=x;modal.showModal()}function cve(id){let x=D.cves.find(x=>x.id===id);open("<h2>"+E(x.cve)+"</h2><p><b>"+E(x.package)+"</b> · "+E(x.installed)+" → "+E(x.fixed)+"</p><p>Identity: <code>"+E(x.id)+"</code></p><p>"+badge(x.resolver)+"</p>")}function rows(o){return Object.entries(o||{}).map(([k,v])=>"<p><b>"+E(k)+"</b><br><code>"+E(typeof v==="object"?JSON.stringify(v):v)+"</code></p>").join("")}function attack(c){let x=D.forms.attack?.cves?.[c];open(x?"<h2>AttackForm · "+E(c)+"</h2><div class=\\"notice\\">อ่านอย่างเดียว: ค่าแนะนำไม่ถือว่ายืนยัน และ viewer นี้ไม่รันคำสั่ง</div>"+rows({module:x.module?.confirmed||x.module?.suggested,target:x.target?.name?.confirmed,targeturi:x.targeturi?.confirmed,options:x.module_options}):"<h2>"+E(c)+"</h2><p>ไม่มี AttackForm</p>")}function patchForm(id){let x=D.forms.patch?.actions?.[id];open(x?"<h2>PatchForm · "+E(id)+"</h2><div class=\\"notice\\">อ่านอย่างเดียว: การยืนยันฟอร์มไม่ใช่การรัน patch</div>"+rows(x):"<h2>"+E(id)+"</h2><p>ไม่มี PatchForm</p>")}
const identity=document.querySelector("#identity"),runEl=document.querySelector("#run"),steps=document.querySelector("#steps"),tabsEl=document.querySelector("#tabs"),panel=document.querySelector("#panel"),modal=document.querySelector("#modal"),modalBody=document.querySelector("#modalBody");fetch("/api/run/"+encodeURIComponent(run)).then(r=>r.ok?r.json():r.json().then(Promise.reject.bind(Promise))).then(x=>{D=x;draw()}).catch(e=>panel.innerHTML="<div class=\\"empty\\">โหลดข้อมูลไม่สำเร็จ: "+E(e.error||e)+"</div>");
</script>"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True); parser.add_argument("--output-root", type=Path, default=Path("output"))
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            request = urlparse(self.path)
            if request.path in ("/", "/index.html"): body, kind, code = HTML.encode(), "text/html; charset=utf-8", 200
            elif request.path.startswith("/api/run/"):
                try: body, kind, code = json.dumps(view(args.output_root.resolve(), request.path.rsplit("/", 1)[-1]), default=str).encode(), "application/json", 200
                except FileNotFoundError as error: body, kind, code = json.dumps({"error": str(error)}).encode(), "application/json", 404
            else: self.send_error(404); return
            self.send_response(code); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, fmt, *args): print("[viewer]", fmt % args)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()

if __name__ == "__main__": main()
