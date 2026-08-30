#!/usr/bin/env python3
"""ECDAT backend — serves the dashboard, canned demo scans, and live GitHub-repo scans."""
import os, json, re, tempfile, subprocess, shutil, io, zipfile
from collections import Counter
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, FileResponse, Response, StreamingResponse
import urllib.request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ecdat

if getattr(sys, "frozen", False):          # running inside a PyInstaller bundle
    HERE = os.path.join(sys._MEIPASS, "app")
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="ECDAT", version="0.1")

# Local-folder scanning is enabled only when you run ECDAT on your own machine
# (set ECDAT_LOCAL=1). The public hosted demo keeps it off for safety.
LOCAL = os.environ.get("ECDAT_LOCAL") == "1"

TIER_LABEL = {"BROKEN_Q":"Quantum-broken","WEAK":"Weak today","SAFE":"Safe","PQC":"Post-quantum"}
DEMOS = {
    "aion": {"label":"AION (our own PQC product)","note":"Our shipped ML-KEM / ML-DSA system. Even it has classical crypto to migrate."},
    "pyca": {"label":"pyca/cryptography","note":"A large open-source crypto library we did not write. Used to measure precision (95%)."},
}

def summarise(res):
    hi = [f for f in res["findings"] if f.get("confidence")=="high"]
    # dedupe identical (file, line, algorithm) hits so the table/counts are clean
    seen=set(); dedup=[]
    for f in hi:
        k=(f["rel_file"], f["line"], f["algorithm"])
        if k in seen: continue
        seen.add(k); dedup.append(f)
    hi = dedup
    tc = Counter(f["tier"] for f in hi)
    total = len(hi)
    vuln = tc["BROKEN_Q"] + tc["WEAK"]
    # top findings: broken first, then urgent, then weak
    order = {"BROKEN_Q":0,"WEAK":1,"SAFE":2,"PQC":3}
    top = sorted(hi, key=lambda f:(order.get(f["tier"],9), not f.get("mosca_urgent"), f["rel_file"]))
    return {
        "target": res["target"],
        "files_scanned": res["files_scanned"],
        "total": total,
        "counts": {k:tc.get(k,0) for k in ("BROKEN_Q","WEAK","SAFE","PQC")},
        "vulnerable": vuln,
        "pct_vulnerable": round(100*vuln/total,1) if total else 0.0,
        "urgent": sum(1 for f in hi if f.get("mosca_urgent")),
        "findings": [{
            "file": f["rel_file"], "line": f["line"], "algorithm": f["algorithm"],
            "tier": f["tier"], "tier_label": TIER_LABEL[f["tier"]],
            "recommendation": f["recommendation"], "why": f["why"],
            "urgent": bool(f.get("mosca_urgent")), "snippet": f.get("snippet","")[:140],
        } for f in top[:80]],
    }

@app.get("/api/mode")
def mode():
    return {"local": LOCAL}

class LocalReq(BaseModel):
    path: str

@app.post("/api/scan_local")
def scan_local(req: LocalReq):
    if not LOCAL:
        raise HTTPException(403, "Scanning a folder on this computer is only available when you run ECDAT on your own machine. Download it from github.com/ArockiaRajamanickam/ecdat and run it locally.")
    p = os.path.abspath(os.path.expanduser(req.path.strip()))
    if not os.path.isdir(p):
        raise HTTPException(400, f"No folder found at: {p}")
    res = ecdat.analyze(p, os.path.basename(p.rstrip("/")) or p)
    s = summarise(res); s["cbom"] = ecdat.cbom(res)
    return JSONResponse(s)

@app.get("/api/demos")
def demos():
    out=[]
    for k,meta in DEMOS.items():
        res=json.load(open(os.path.join(DATA,f"{k}.json")))
        s=summarise(res)
        out.append({"id":k, **meta, "files":s["files_scanned"], "vulnerable":s["vulnerable"], "total":s["total"]})
    return out

@app.get("/api/scan/{demo}")
def scan_demo(demo:str):
    p=os.path.join(DATA,f"{demo}.json")
    if not os.path.exists(p): raise HTTPException(404,"unknown demo")
    return JSONResponse(summarise(json.load(open(p))))

@app.get("/api/cbom/{demo}")
def cbom(demo:str):
    p=os.path.join(DATA,f"{demo}_cbom.json")
    if not os.path.exists(p): raise HTTPException(404,"no cbom")
    return FileResponse(p, media_type="application/json", filename=f"ecdat-cbom-{demo}.json")

class ScanReq(BaseModel):
    repo_url: str

GITHUB_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/?$")
@app.post("/api/scan")
def scan_live(req:ScanReq):
    url=req.repo_url.strip().rstrip("/")
    if not GITHUB_RE.match(url+"/"):
        raise HTTPException(400,"Please paste a public GitHub repo URL like https://github.com/owner/repo")
    tmp=tempfile.mkdtemp(prefix="ecdat_")
    try:
        r=subprocess.run(["git","clone","--depth","1","--single-branch",url+".git",tmp],
                         capture_output=True,text=True,timeout=90)
        if r.returncode!=0:
            raise HTTPException(400,"Could not clone that repo (private, huge, or not found).")
        res=ecdat.analyze(tmp, url.split("/")[-1])
        # attach cbom inline
        s=summarise(res); s["cbom"]=ecdat.cbom(res)
        return JSONResponse(s)
    except subprocess.TimeoutExpired:
        raise HTTPException(408,"Repo too large to scan in time. Try a smaller one.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

RUN_SH = """#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
echo "ECDAT is starting — open http://localhost:8000"
ECDAT_LOCAL=1 uvicorn app.server:app --port 8000
"""
RUN_BAT = """@echo off
cd /d %~dp0
python -m venv .venv
call .venv\\Scripts\\activate
pip install -r requirements.txt
set ECDAT_LOCAL=1
echo ECDAT is starting - open http://localhost:8000
uvicorn app.server:app --port 8000
"""

@app.get("/api/download")
def download():
    """Package the tool as a zip so a visitor can run it on their own machine."""
    root = os.path.dirname(HERE)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for folder, dirs, files in os.walk(HERE):
            dirs[:] = [d for d in dirs if d not in ("__pycache__",)]
            for fn in files:
                if fn.endswith((".pyc",)): continue
                full = os.path.join(folder, fn)
                z.write(full, os.path.join("ecdat", "app", os.path.relpath(full, HERE)))
        for fn in ("requirements.txt", "README.md", ".python-version"):
            p = os.path.join(root, fn)
            if os.path.exists(p): z.write(p, os.path.join("ecdat", fn))
        z.writestr("ecdat/run.sh", RUN_SH)
        z.writestr("ecdat/run.bat", RUN_BAT)
    buf.seek(0)
    return Response(buf.read(), media_type="application/zip",
                    headers={"Content-Disposition": "attachment; filename=ecdat.zip"})

OS_ASSET = {"windows": "ECDAT-windows.exe", "macos": "ECDAT-macos", "linux": "ECDAT-linux"}
RELEASE_BASE = "https://github.com/ArockiaRajamanickam/ecdat/releases/latest/download/"

@app.get("/download/{os_name}")
def download_binary(os_name: str):
    """Stream the prebuilt one-click binary through this site (not a redirect to GitHub),
    so the download comes from our own domain."""
    asset = OS_ASSET.get(os_name)
    if not asset:
        raise HTTPException(404, "unknown platform")
    req = urllib.request.Request(RELEASE_BASE + asset, headers={"User-Agent": "ECDAT"})
    try:
        upstream = urllib.request.urlopen(req, timeout=30)   # follows the redirect to the asset
    except Exception:
        raise HTTPException(502, "Could not fetch the build. Try again in a moment.")
    headers = {"Content-Disposition": f'attachment; filename="{asset}"'}
    clen = upstream.headers.get("Content-Length")
    if clen:
        headers["Content-Length"] = clen
    def stream():
        try:
            while True:
                chunk = upstream.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            upstream.close()
    return StreamingResponse(stream(), media_type="application/octet-stream", headers=headers)

app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
