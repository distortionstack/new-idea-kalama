#!/usr/bin/env python3
"""Bounded, non-executing package resource benchmark."""
from __future__ import annotations
import hashlib, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from packageurl import PackageURL

ROOT=Path(__file__).resolve().parent; RAW=ROOT/"raw"; TIMEOUT=float(os.getenv("BENCHMARK_TIMEOUT","20")); MAX_BYTES=int(os.getenv("BENCHMARK_MAX_BYTES","2000000")); UA="VIPER-resource-discovery-benchmark/0.2"
SUPPORTED_DEPS={"maven":"MAVEN","npm":"NPM","pypi":"PYPI","cargo":"CARGO","golang":"GO","gem":"RUBYGEMS","nuget":"NUGET"}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None
OPENER=urllib.request.build_opener(NoRedirect())

def parse_purl(value):
    p=PackageURL.from_string(value)
    if not p or not p.type or not p.name or not p.version: raise ValueError("PURL must include type, name and version")
    return {"type":p.type,"namespace":p.namespace,"name":p.name,"version":p.version,"qualifiers":dict(p.qualifiers or {}),"subpath":p.subpath}

def _get(url,accept="*/*"):
    started=time.monotonic(); chain=[]; current=url; result={"url":url,"method":"GET","status":None,"redirect_chain":chain,"final_url":None,"error":None}
    for _ in range(8):
        try:
            with OPENER.open(urllib.request.Request(current,headers={"User-Agent":UA,"Accept":accept}),timeout=TIMEOUT) as r:
                body=r.read(MAX_BYTES+1); result.update(status=r.status,final_url=current,body_bytes=body[:MAX_BYTES],body=body[:MAX_BYTES].decode("utf-8","replace"),truncated=len(body)>MAX_BYTES); break
        except urllib.error.HTTPError as e:
            if e.code in {301,302,303,307,308} and e.headers.get("Location"):
                nxt=urllib.parse.urljoin(current,e.headers["Location"]); chain.append({"status":e.code,"from":current,"to":nxt}); current=nxt; continue
            result.update(status=e.code,final_url=current,error=str(e),body=e.read(MAX_BYTES).decode("utf-8","replace")); break
        except Exception as e: result["error"]=f"{type(e).__name__}: {e}"; break
    result["elapsed_seconds"]=round(time.monotonic()-started,3)
    if result["error"] and any(x in result["error"] for x in ("resolve","Name or service","Network is unreachable")): result["category"]="BLOCKED_NETWORK"
    elif result["status"]==404: result["category"]="NOT_FOUND"
    elif result["error"]: result["category"]="PROVIDER_ERROR"
    return result

def _resource(url,provider,kind,version):
    r=_get(url); raw=r.get("body_bytes",b""); computed=hashlib.sha256(raw).hexdigest() if raw and not r.get("truncated") else None
    return {"provider":provider,"type":kind,"url":url,"version":version,"download_method":"GET","http":{k:r.get(k) for k in ("status","final_url","redirect_chain","elapsed_seconds","error","category")},"checksum":{"algorithm":"sha256" if computed else None,"expected":None,"computed":computed,"scope":"complete_response_body" if computed else "NOT_COMPUTED_TRUNCATED"},"verification":{"availability":"PASS" if r.get("status") in {200,206} else "NOT_CHECKED","identity":"NOT_CHECKED","version":"NOT_CHECKED","integrity":"LOCAL_HASH_ONLY" if computed else "NOT_CHECKED","authenticity":"NOT_CHECKED","provenance":"NOT_CHECKED"},"raw_body":r.get("body","")}

def direct_resources(p):
    t,n,v=p["type"],p["name"],p["version"]; out=[]
    if t=="maven":
        if not p["namespace"]: return []
        group,artifact=p["namespace"],n; enc=urllib.parse.quote(v,safe=".+-"); path=f"{group.replace('.', '/')}/{artifact}/{enc}/{artifact}-{enc}"
        for suffix,kind in ((".pom","package-metadata"),(".jar","binary-artifact"),("-sources.jar","package-source-artifact")): out.append((f"https://repo1.maven.org/maven2/{path}{suffix}",kind))
    elif t=="npm": out.append((f"https://registry.npmjs.org/{urllib.parse.quote(n,safe='@/')}/{urllib.parse.quote(v,safe='+.-_')}","package-metadata"))
    elif t=="pypi": out.append((f"https://pypi.org/pypi/{urllib.parse.quote(n)}/{urllib.parse.quote(v)}/json","package-metadata"))
    elif t=="cargo": out.append((f"https://crates.io/api/v1/crates/{urllib.parse.quote(n)}/{urllib.parse.quote(v)}","package-metadata"))
    elif t=="deb":
        # Snapshot distinguishes binary identity from source identity. The binary
        # endpoint is keyed by binary name/version; source name/version must be
        # obtained from Debian Packages/Sources metadata before calling srcfiles.
        base=f"https://snapshot.debian.org/mr/binary/{urllib.parse.quote(n)}/{urllib.parse.quote(v,safe='.+-')}"
        out.append((base+"/binfiles","debian-binary-metadata"))
    return out

def provider_queries(p):
    t,n,v=p["type"],p["name"],p["version"]; out=[]
    if t in SUPPORTED_DEPS:
        package=f"{p['namespace']}:{n}" if t=="maven" and p["namespace"] else n; out.append(("deps.dev",f"https://api.deps.dev/v3/systems/{SUPPORTED_DEPS[t]}/packages/{urllib.parse.quote(package,safe='')}/versions/{urllib.parse.quote(v,safe='.+-')}"))
    if t in {"maven","npm","pypi","cargo"}:
        eco={"maven":"Maven","npm":"npm","pypi":"PyPI","cargo":"crates.io"}[t]; out.append(("OSV","https://api.osv.dev/v1/query",{"package":{"ecosystem":eco,"name":n if t!="maven" else f"{p['namespace']}:{n}"},"version":v}))
    return out

def post_osv(url,payload):
    req=urllib.request.Request(url,data=json.dumps(payload).encode(),headers={"User-Agent":UA,"Content-Type":"application/json","Accept":"application/json"},method="POST"); started=time.monotonic(); result={"url":url,"method":"POST","status":None,"redirect_chain":[],"final_url":url,"error":None}
    try:
        with urllib.request.urlopen(req,timeout=TIMEOUT) as r: body=r.read(MAX_BYTES+1); result.update(status=r.status,body=body[:MAX_BYTES].decode("utf-8","replace"),truncated=len(body)>MAX_BYTES)
    except urllib.error.HTTPError as e: result.update(status=e.code,error=str(e),body=e.read(MAX_BYTES).decode("utf-8","replace"))
    except Exception as e: result["error"]=f"{type(e).__name__}: {e}"
    result["elapsed_seconds"]=round(time.monotonic()-started,3); return result

def main():
    cases=json.loads((ROOT/"test_cases.json").read_text())["cases"]; run={"schema":"viper.resource-discovery-benchmark/v2","tool_versions":{"python":sys.version,"packageurl-python":"0.17.6"},"cases":[]}; RAW.mkdir(exist_ok=True)
    for case in cases:
        item={"id":case["id"],"input_purl":case["purl"],"resources":[],"providers":[],"warnings":[]}
        try: p=parse_purl(case["purl"]); item["parsed"]=p
        except Exception as e: item.update(status="INVALID_INPUT",parse_error=str(e)); run["cases"].append(item); (RAW/f"{case['id']}.json").write_text(json.dumps(item,indent=2)+"\n"); continue
        if p["type"] not in {"maven","deb","npm","pypi","cargo"}: item["status"]="UNSUPPORTED"
        for u,k in direct_resources(p): item["resources"].append(_resource(u,"direct-registry",k,p["version"]))
        for q in provider_queries(p):
            if len(q)==2:
                name,u=q; hr=_get(u,"application/json"); hr.pop("body_bytes",None); item["providers"].append({"provider":name,"url":u,"http":hr})
            else: name,u,payload=q; item["providers"].append({"provider":name,"url":u,"http":post_osv(u,payload)})
        if item.get("status") is None: item["status"]="QUERIED"
        run["cases"].append(item); (RAW/f"{case['id']}.json").write_text(json.dumps(item,indent=2,ensure_ascii=False)+"\n")
    (ROOT/"results.json").write_text(json.dumps(run,indent=2,ensure_ascii=False)+"\n"); print(f"wrote {len(cases)} cases to {ROOT/'results.json'}")
if __name__=="__main__": main()
