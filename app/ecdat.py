#!/usr/bin/env python3
"""
ECDAT - Enterprise Cryptographic Discovery & Analysis Tool (v0.2, semantic engine)

Discovers cryptographic usage in source code and X.509 certificates using
tree-sitter syntax-tree analysis (Python / JavaScript / TypeScript / Java) with a
regex fallback for other languages. Classifies each finding by quantum risk,
scores urgency with Mosca's theorem, prescribes a NIST PQC replacement, and emits
a CycloneDX-style CBOM.

The syntax tree is used to judge *context*: a match inside a comment or an
error-message string is not a real usage, while a crypto-API argument, an
identifier, or a config constant is. This gives high precision without losing
recall.
"""
import ast, os, re, json, sys, argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------- risk model
RULES = [
    ("rsa",   r"\bRSA\b|rsa\.(generate_private_key|RSAPrivateKey|RSAPublicKey|encrypt|sign)|generateKeyPair\w*\(\s*['\"]rsa['\"]", "RSA", "BROKEN_Q", "Public-key factoring broken by Shor's algorithm", "ML-KEM-768 (encryption) / ML-DSA-65 (signatures), hybrid"),
    ("ecdsa", r"\bECDSA\b|ec\.ECDSA|SigningKey|['\"]ES256['\"]|['\"]secp256k1['\"]|['\"]P-256['\"]", "ECDSA", "BROKEN_Q", "Elliptic-curve DLP broken by Shor's algorithm", "ML-DSA-65 (signatures)"),
    ("ecdh",  r"\bECDH\b|X25519|x25519|Curve25519|ec\.ECDH|deriveBits|[dD]iffieHellman", "ECDH/X25519", "BROKEN_Q", "Elliptic-curve DH broken by Shor's algorithm", "ML-KEM-768 (hybrid key exchange)"),
    ("dh",    r"\bDiffie[- ]?Hellman\b|\bDHParameter", "Diffie-Hellman", "BROKEN_Q", "Discrete-log broken by Shor's algorithm", "ML-KEM-768 (hybrid)"),
    ("md5",   r"\bMD5\b|hashlib\.md5|createHash\(\s*['\"]md5['\"]", "MD5", "WEAK", "Collision-broken since 2004", "SHA-256 / SHA-3"),
    ("sha1",  r"\bSHA-?1\b|hashlib\.sha1|createHash\(\s*['\"]sha1['\"]", "SHA-1", "WEAK", "Collision-broken (SHAttered, 2017)", "SHA-256 / SHA-3"),
    ("des",   r"\b3?DES\b|DES3|pyDes|createCipher\w*\(\s*['\"]des", "DES/3DES", "WEAK", "64-bit block / small key, deprecated", "AES-256-GCM"),
    ("rc4",   r"\bRC4\b|ARC4|createCipher\w*\(\s*['\"]rc4", "RC4", "WEAK", "Biased keystream, broken", "AES-256-GCM"),
    ("aes",   r"\bAES-?256\b|AES\.new|createCipheriv\(\s*['\"]aes-256|algorithms\.AES", "AES-256", "SAFE", "128-bit quantum security (Grover-resistant at 256)", "No change needed"),
    ("sha256",r"\bSHA-?256\b|\bSHA-?384\b|\bSHA-?512\b|\bSHA-?3\b|hashlib\.sha(256|384|512|3)|createHash\(\s*['\"]sha(256|384|512)", "SHA-256+", "SAFE", "Grover only halves preimage; 256 stays safe", "No change needed"),
    ("mlkem", r"\bML-?KEM\b|\bKyber\b|ml_kem|mlkem", "ML-KEM", "PQC", "NIST FIPS 203 lattice KEM", "Already quantum-safe"),
    ("mldsa", r"\bML-?DSA\b|\bDilithium\b|ml_dsa|mldsa", "ML-DSA", "PQC", "NIST FIPS 204 lattice signature", "Already quantum-safe"),
    ("slhdsa",r"\bSLH-?DSA\b|SPHINCS", "SLH-DSA", "PQC", "NIST FIPS 205 hash signature", "Already quantum-safe"),
]
COMPILED = [(rid, re.compile(rx, re.IGNORECASE), alg, tier, why, rec) for rid, rx, alg, tier, why, rec in RULES]

TIER_META = {
    "BROKEN_Q": ("QUANTUM-BROKEN (Shor)", "critical"),
    "WEAK":     ("WEAK / BROKEN TODAY", "high"),
    "SAFE":     ("SAFE", "none"),
    "PQC":      ("PQC / quantum-safe", "none"),
}
Z_QDAY = 10
def mosca(x_years, y_years=3, z=Z_QDAY):
    return (x_years + y_years) > z, x_years + y_years

# ---------------------------------------------------------------- tree-sitter
_PARSERS = {}
_TS_OK = True
def _get_parser(ext):
    if not _TS_OK:
        return None
    if ext in _PARSERS:
        return _PARSERS[ext]
    try:
        from tree_sitter import Parser, Language
        mod = {
            ".py": "tree_sitter_python",
            ".js": "tree_sitter_javascript", ".jsx": "tree_sitter_javascript",
            ".ts": "tree_sitter_javascript", ".tsx": "tree_sitter_javascript",
            ".mjs": "tree_sitter_javascript", ".cjs": "tree_sitter_javascript",
            ".java": "tree_sitter_java",
        }.get(ext)
        if not mod:
            _PARSERS[ext] = None; return None
        m = __import__(mod)
        parser = Parser(Language(m.language()))
        _PARSERS[ext] = parser
        return parser
    except Exception:
        _PARSERS[ext] = None
        return None

_CRYPTO_API = re.compile(
    r"crypto\.subtle|subtle\.|generateKey|generateKeyPair|importKey|exportKey|deriveBits|deriveKey|"
    r"createCipher\w*|createDecipher\w*|createHash|createHmac|createSign|createVerify|diffieHellman|"
    r"\.encrypt|\.decrypt|\.sign|\.verify|Cipher\.getInstance|MessageDigest\.getInstance|KeyPairGenerator")

def _collect_context(root, src):
    """Walk the tree once; return comment byte-ranges and a classifier for string ranges."""
    comments = []          # (start,end)
    strings = []           # (start,end, kind)  kind in {'code','msg'}
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type
        if "comment" in t:
            comments.append((node.start_byte, node.end_byte))
            continue  # don't descend into comments
        if "string" in t or t == "string_literal":
            kind = _classify_string(node, src)
            strings.append((node.start_byte, node.end_byte, kind))
        for i in range(node.child_count):
            stack.append(node.children[i])
    comments.sort(); strings.sort()
    return comments, strings

def _classify_string(node, src):
    """A string is 'code' if it is a crypto-API argument or an assignment/config value;
    otherwise it is a 'msg' (error text, docstring, log line…)."""
    p = node.parent
    hops = 0
    call_types = {"call", "call_expression", "method_invocation", "new_expression", "object_creation_expression"}
    assign_types = {"assignment", "variable_declarator", "pair", "augmented_assignment",
                    "field_declaration", "assignment_expression", "keyword_argument"}
    raise_types = {"raise_statement", "throw_statement"}
    while p is not None and hops < 6:
        pt = p.type
        if pt in raise_types:
            return "msg"
        if pt in call_types:
            txt = src[p.start_byte:p.end_byte].decode("utf-8", "ignore")
            return "code" if _CRYPTO_API.search(txt) else "msg"
        if pt in assign_types:
            return "code"
        p = p.parent; hops += 1
    return "msg"

def _in_ranges(off, ranges):
    lo, hi = 0, len(ranges)
    while lo < hi:
        mid = (lo + hi) // 2
        s, e = ranges[mid][0], ranges[mid][1]
        if off < s: hi = mid
        elif off >= e: lo = mid + 1
        else: return ranges[mid]
    return None

# ---------------------------------------------------------------- fallback (regex, line-based)
_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|\"\"\"|''')")
_APIISH = re.compile(r"[.(\[]|import |require\(|createHash|createCipher|generateKey|new [A-Z]|algorithms\.|hashlib\.|crypto\.|=\s*\w|Private|Public|Key|OID|register|isinstance")
_RAISE = re.compile(r"\braise\b|\bTypeError|\bValueError|\bError\(|throw ")
_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')

def _fallback_confidence(line, rx):
    if _COMMENT.match(line): return "low"
    if _CRYPTO_API.search(line): return "high"
    if _RAISE.search(line): return "low"
    stripped = _QUOTED.sub("", line)
    if rx is not None and not rx.search(stripped):
        if re.search(r"[=:]\s*[\[{(]?\s*['\"]", line):
            q = _QUOTED.findall(line)
            if q and rx.search(q[0]): return "high"
        return "low"
    return "high" if _APIISH.search(line) else "low"

# ---------------------------------------------------------------- scanning
def scan_file(path):
    findings = []
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return findings
    if len(raw) > 2_000_000:
        return findings
    src_text = raw.decode("utf-8", "ignore")
    parser = _get_parser(ext)

    if parser is not None:
        try:
            tree = parser.parse(raw)
            comments, strings = _collect_context(tree.root_node, raw)
            engine = "ast"
        except Exception:
            parser = None
    if parser is not None:
        for rid, rx, alg, tier, why, rec in COMPILED:
            for m in rx.finditer(src_text):
                off = len(src_text[:m.start()].encode("utf-8", "ignore"))  # byte offset
                if _in_ranges(off, comments):
                    conf = "low"
                else:
                    sr = _in_ranges(off, strings)
                    if sr is not None:
                        conf = "high" if sr[2] == "code" else "low"
                    else:
                        conf = "high"   # bare code token (identifier / API name)
                line_no = src_text.count("\n", 0, m.start()) + 1
                line_txt = src_text.splitlines()[line_no-1] if line_no-1 < len(src_text.splitlines()) else ""
                findings.append(_finding(path, line_no, rid, alg, tier, why, rec, conf, line_txt, "ast"))
    else:
        # regex fallback, line-based
        for i, line in enumerate(src_text.splitlines(), 1):
            if len(line) > 400: continue
            for rid, rx, alg, tier, why, rec in COMPILED:
                if rx.search(line):
                    conf = _fallback_confidence(line, rx)
                    findings.append(_finding(path, i, rid, alg, tier, why, rec, conf, line, "regex"))
    return findings

def _finding(path, line, rid, alg, tier, why, rec, conf, snippet, engine):
    return {"file": path, "line": line, "rule": rid, "algorithm": alg, "tier": tier,
            "why": why, "recommendation": rec, "confidence": conf,
            "snippet": snippet.strip()[:160], "engine": engine}

SRC_EXT = (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".go", ".c", ".cc", ".cpp", ".rb", ".php")
SKIP_DIR = {"node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__", ".claude", "vendor", "site-packages"}

def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIR]
        for fn in fns:
            if fn.endswith(SRC_EXT):
                yield os.path.join(dp, fn)

def sensitivity_horizon(path):
    p = path.lower()
    if any(k in p for k in ("auth", "identity", "session", "key", "secret", "login", "token")): return 25
    if any(k in p for k in ("payment", "bank", "pii", "user")): return 10
    return 5

def analyze(root, label):
    all_f, nfiles = [], 0
    for path in walk(root):
        nfiles += 1
        all_f.extend(scan_file(path))
    for f in all_f:
        x = sensitivity_horizon(f["file"])
        urgent, _ = mosca(x)
        f["mosca_x"] = x
        f["mosca_urgent"] = urgent and f["tier"] in ("BROKEN_Q", "WEAK") and f["confidence"] == "high"
        f["rel_file"] = os.path.relpath(f["file"], root)
    counts = {t: 0 for t in TIER_META}
    for f in all_f:
        counts[f["tier"]] += 1
    total = len(all_f); vuln = counts["BROKEN_Q"] + counts["WEAK"]
    ast_files = sum(1 for f in all_f if f.get("engine") == "ast")
    return {"target": label, "root": root, "files_scanned": nfiles, "total_findings": total,
            "counts": counts, "vulnerable": vuln,
            "pct_vulnerable": round(100 * vuln / total, 1) if total else 0.0,
            "urgent": sum(1 for f in all_f if f["mosca_urgent"]),
            "semantic": _TS_OK, "findings": all_f}

def cbom(result):
    comps, seen = [], set()
    for f in result["findings"]:
        if f.get("confidence") == "low": continue
        key = (f["algorithm"], f["tier"])
        if key in seen: continue
        seen.add(key)
        comps.append({"type": "cryptographic-asset", "name": f["algorithm"],
            "cryptoProperties": {"assetType": "algorithm",
                "quantumRisk": TIER_META[f["tier"]][0], "recommendation": f["recommendation"]}})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                     "tools": [{"name": "ECDAT", "version": "0.2-semantic"}],
                     "component": {"name": result["target"], "type": "application"}},
        "components": comps}

def print_report(result):
    print(f"\n=== ECDAT scan: {result['target']} ===")
    print(f"files scanned      : {result['files_scanned']}")
    print(f"total findings     : {result['total_findings']}")
    for t, (label, _) in TIER_META.items():
        print(f"  {label:28} {result['counts'][t]}")
    print(f"vulnerable (Q+weak): {result['vulnerable']}  ({result['pct_vulnerable']}%)")
    print(f"Mosca-urgent       : {result['urgent']}   semantic-engine: {result['semantic']}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("root"); ap.add_argument("--label", default=None)
    ap.add_argument("--json", default=None); ap.add_argument("--cbom", default=None)
    ap.add_argument("--top", type=int, default=12)
    a = ap.parse_args()
    res = analyze(a.root, a.label or os.path.basename(a.root.rstrip("/")))
    print_report(res)
    print("\nTop findings:")
    hi = [f for f in res["findings"] if f["confidence"] == "high"]
    for f in sorted(hi, key=lambda f: (f["tier"] != "BROKEN_Q", not f["mosca_urgent"]))[:a.top]:
        flag = "!" if f["mosca_urgent"] else " "
        print(f" [{flag}] {f['rel_file']}:{f['line']:<4} {f['algorithm']:14} {TIER_META[f['tier']][0]:24} -> {f['recommendation']}")
    if a.json: json.dump(res, open(a.json, "w"), indent=1)
    if a.cbom: json.dump(cbom(res), open(a.cbom, "w"), indent=1)
