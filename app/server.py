#!/usr/bin/env python3
"""ECDAT backend — serves the dashboard, canned demo scans, and live GitHub-repo scans."""
import os, json, re, tempfile, subprocess, shutil
from collections import Counter
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ecdat

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
STATIC = os.path.join(HERE, "static")

app = FastAPI(title="ECDAT", version="0.1")

TIER_LABEL = {"BROKEN_Q":"Quantum-broken","WEAK":"Weak today","SAFE":"Safe","PQC":"Post-quantum"}
DEMOS = {
    "aion": {"label":"AION (our own PQC product)","note":"Our shipped ML-KEM / ML-DSA system. Even it has classical crypto to migrate."},
    "pyca": {"label":"pyca/cryptography","note":"A large open-source crypto library we did not write. Used to measure precision (95%)."},
}

def summarise(res):
    hi = [f for f in res["findings"] if f.get("confidence")=="high"]
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

app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
