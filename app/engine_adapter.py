"""Adapt the v3 engine's ScanResult to the dashboard's summary shape.

The UI speaks tiers (BROKEN_Q/WEAK/SAFE/PQC) and a flat findings list; the engine
speaks assets with severity and provenance. This maps one to the other without
changing either.
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.pipeline import scan as _scan
from engine.policy import Policy
from engine.serializers import cbom as _cbom

_TIER = {"shor_broken": "BROKEN_Q", "legacy_broken": "WEAK", "grover_weakened": "WEAK",
         "quantum_safe": "SAFE", "pqc": "PQC", "unknown": "SAFE"}
_LABEL = {"BROKEN_Q": "Quantum-broken", "WEAK": "Weak today", "SAFE": "Safe", "PQC": "Post-quantum"}
_ORDER = {"BROKEN_Q": 0, "WEAK": 1, "SAFE": 2, "PQC": 3}


def scan_to_summary(root: str, target: str | None = None) -> dict:
    root_abs = os.path.abspath(os.path.expanduser(root))
    res = _scan(root, Policy.load(None), target=target)

    def rel(path: str) -> str:
        """Show paths relative to the scan root; absolute paths are unreadable in a table."""
        try:
            if path.startswith(root_abs):
                return os.path.relpath(path, root_abs)
        except Exception:
            pass
        return path
    findings, counts = [], {k: 0 for k in ("BROKEN_Q", "WEAK", "SAFE", "PQC")}
    for a in res.artefacts:
        tier = _TIER.get(a.threat.value, "SAFE")
        if a.threat.value == "pqc":
            tier = "PQC"
        for o in a.occurrences:
            counts[tier] += 1
            findings.append({
                "file": rel(o.file), "line": o.line or 0, "algorithm": a.name,
                "tier": tier, "tier_label": _LABEL[tier],
                "recommendation": a.recommendation or "no change needed",
                "why": a.threat_reason or "", "urgent": bool(a.mosca_act_now) and tier in ("BROKEN_Q", "WEAK"),
                "snippet": (o.evidence or "")[:140],
                "severity": a.severity.value, "has_fix": bool(a.fix_patch),
            })
    findings.sort(key=lambda f: (_ORDER[f["tier"]], not f["urgent"], f["file"]))
    total = len(findings)
    vuln = counts["BROKEN_Q"] + counts["WEAK"]
    return {
        "target": res.target, "files_scanned": res.files_scanned,
        "total": total, "counts": counts, "vulnerable": vuln,
        "pct_vulnerable": round(100 * vuln / total, 1) if total else 0.0,
        "urgent": sum(1 for f in findings if f["urgent"]),
        "assets": len(res.artefacts),
        "fixes_available": sum(1 for a in res.artefacts if a.fix_patch),
        "findings": findings[:80],
        "cbom": _cbom.to_cbom(res),
        "engine": "v3-semantic",
    }
