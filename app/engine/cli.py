#!/usr/bin/env python3
"""ECDAT command line.

    ecdat scan    PATH [--policy P] [--json F] [--cbom F] [--sarif F]
    ecdat report  PATH [--policy P] [--out F]
    ecdat ci      PATH [--policy P] [--fail-on SEV] [--cbom F] [--sarif F] [--report F]
    ecdat tls     HOST [--port 443]
    ecdat history [--db F] [--target T]
    ecdat serve   [--path P] [--port 8000]

Exit codes: 0 ok, 1 gate failed, 2 usage/runtime error.
"""
from __future__ import annotations
import argparse, json, os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_APP = os.path.dirname(_HERE)
for _p in (_APP, os.path.dirname(_APP)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(policy_path):
    from engine.policy import Policy
    return Policy.load(policy_path)


def _scan(path, policy_path):
    from engine.pipeline import scan
    return scan(path, _load(policy_path))


def _write(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=1) if isinstance(data, (dict, list)) else fh.write(data)
    print(f"  wrote {path}")


def _summary_line(res):
    from engine.models import Severity
    counts = {}
    for a in res.artefacts:
        counts[a.severity.value] = counts.get(a.severity.value, 0) + 1
    parts = [f"{counts.get(s.value, 0)} {s.value}" for s in Severity if counts.get(s.value)]
    return f"{res.files_scanned} files · {len(res.artefacts)} assets · " + (", ".join(parts) or "nothing flagged")


def cmd_scan(a) -> int:
    res = _scan(a.path, a.policy)
    print(f"ECDAT scan: {res.target}")
    print("  " + _summary_line(res))
    for art in res.artefacts[:20]:
        occ = art.occurrences[0] if art.occurrences else None
        where = f"{occ.file}:{occ.line}" if occ else "-"
        print(f"  [{art.severity.value:8}] {art.name:24} {where}")
    if len(res.artefacts) > 20:
        print(f"  ... and {len(res.artefacts) - 20} more")
    if a.json:
        _write(a.json, res.to_dict())
    if a.cbom:
        from engine.serializers.cbom import to_cbom
        _write(a.cbom, to_cbom(res))
    if a.sarif:
        from engine.serializers.sarif import to_sarif
        _write(a.sarif, to_sarif(res))
    return 0


def cmd_report(a) -> int:
    from engine.serializers.report import to_markdown
    res = _scan(a.path, a.policy)
    md = to_markdown(res, _load(a.policy))
    if a.out:
        _write(a.out, md)
    else:
        print(md)
    return 0


def cmd_ci(a) -> int:
    from engine.gate import evaluate
    res = _scan(a.path, a.policy)
    if a.cbom:
        from engine.serializers.cbom import to_cbom
        _write(a.cbom, to_cbom(res))
    if a.sarif:
        from engine.serializers.sarif import to_sarif
        _write(a.sarif, to_sarif(res))
    if a.report:
        from engine.serializers.report import to_markdown
        _write(a.report, to_markdown(res, _load(a.policy)))
    code, summary = evaluate(res, _load(a.policy), a.fail_on)
    print(summary)
    return 1 if code else 0


def cmd_tls(a) -> int:
    from engine.detectors.tls import scan_endpoint
    arts, errs = scan_endpoint(a.host, a.port)
    for e in errs:
        print(f"  ! {e}")
    if not arts:
        print("  no TLS artefacts recovered")
        return 0
    for art in arts:
        print(f"  {art.name:28} {art.kind}")
    return 0


def cmd_history(a) -> int:
    from engine import store
    fn = getattr(store, "list_scans", None)
    if not callable(fn):
        print("  scan history unavailable"); return 2
    for row in fn(a.db, a.target) if a.target else fn(a.db):
        print("  " + str(row))
    return 0


def cmd_serve(a) -> int:
    os.environ["ECDAT_LOCAL"] = "1"
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed: pip install -r requirements.txt", file=sys.stderr)
        return 2
    print(f"ECDAT dashboard on http://localhost:{a.port}  (scanning stays on this machine)")
    uvicorn.run("app.server:app", host="127.0.0.1", port=a.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ecdat", description="Cryptographic discovery and quantum-risk analysis.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a path and print a summary")
    s.add_argument("path"); s.add_argument("--policy"); s.add_argument("--json")
    s.add_argument("--cbom"); s.add_argument("--sarif"); s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("report", help="markdown risk report")
    r.add_argument("path"); r.add_argument("--policy"); r.add_argument("--out")
    r.set_defaults(fn=cmd_report)

    c = sub.add_parser("ci", help="gate a build on quantum-vulnerable crypto")
    c.add_argument("path"); c.add_argument("--policy")
    c.add_argument("--fail-on", dest="fail_on", default="critical")
    c.add_argument("--cbom"); c.add_argument("--sarif"); c.add_argument("--report")
    c.set_defaults(fn=cmd_ci)

    t = sub.add_parser("tls", help="scan a live TLS endpoint")
    t.add_argument("host"); t.add_argument("--port", type=int, default=443)
    t.set_defaults(fn=cmd_tls)

    h = sub.add_parser("history", help="previous scans")
    h.add_argument("--db", default="scans.db"); h.add_argument("--target")
    h.set_defaults(fn=cmd_history)

    v = sub.add_parser("serve", help="run the dashboard locally")
    v.add_argument("--path", default="."); v.add_argument("--port", type=int, default=8000)
    v.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"ecdat: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
