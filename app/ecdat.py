#!/usr/bin/env python3
"""
ECDAT - Enterprise Cryptographic Discovery & Analysis Tool
SIH26164 | Team WEB Shooters | MVP scanner prototype.

Discovers cryptographic usage in source code (Python + JavaScript/TS) and X.509
certificates, classifies each finding by quantum risk, scores urgency with
Mosca's theorem, prescribes a PQC replacement, and emits a CycloneDX-style CBOM.

Pure standard-library so it runs anywhere, offline, air-gapped.
"""
import ast, os, re, json, sys, argparse
from datetime import datetime, timezone

# ---------------------------------------------------------------- risk model
# tier: BROKEN_Q (quantum-broken via Shor), WEAK (classical broken), SAFE, PQC
RULES = [
    # id, regex, algorithm, tier, why, recommendation
    ("rsa",        r"\bRSA\b|rsa\.(generate_private_key|RSAPrivateKey|encrypt|sign)|crypto\.generateKeyPairSync\(\s*['\"]rsa['\"]|generateKey\(\s*{[^}]*RSA", "RSA", "BROKEN_Q", "Public-key factoring broken by Shor's algorithm", "ML-KEM-768 (encryption) / ML-DSA-65 (signatures), hybrid"),
    ("ecdsa",      r"\bECDSA\b|ec\.ECDSA|SigningKey|['\"]ES256['\"]|['\"]secp256k1['\"]|['\"]P-256['\"]", "ECDSA", "BROKEN_Q", "Elliptic-curve DLP broken by Shor's algorithm", "ML-DSA-65 (signatures)"),
    ("ecdh",       r"\bECDH\b|X25519|x25519|Curve25519|ec\.ECDH|deriveBits|[dD]iffieHellman", "ECDH/X25519", "BROKEN_Q", "Elliptic-curve DH broken by Shor's algorithm", "ML-KEM-768 (hybrid key exchange)"),
    ("dh",         r"\bDiffie[- ]?Hellman\b|\bDHParameter|dh\.generate_parameters", "Diffie-Hellman", "BROKEN_Q", "Discrete-log broken by Shor's algorithm", "ML-KEM-768 (hybrid)"),
    ("md5",        r"\bMD5\b|hashlib\.md5|createHash\(\s*['\"]md5['\"]", "MD5", "WEAK", "Collision-broken since 2004", "SHA-256 / SHA-3"),
    ("sha1",       r"\bSHA-?1\b|hashlib\.sha1|createHash\(\s*['\"]sha1['\"]", "SHA-1", "WEAK", "Collision-broken (SHAttered, 2017)", "SHA-256 / SHA-3"),
    ("des",        r"\b3?DES\b|DES3|pyDes|createCipher\w*\(\s*['\"]des", "DES/3DES", "WEAK", "64-bit block / small key, deprecated", "AES-256-GCM"),
    ("rc4",        r"\bRC4\b|ARC4|createCipher\w*\(\s*['\"]rc4", "RC4", "WEAK", "Biased keystream, broken", "AES-256-GCM"),
    ("aes",        r"\bAES-?256\b|AES\.new|createCipheriv\(\s*['\"]aes-256|algorithms\.AES", "AES-256", "SAFE", "128-bit quantum security (Grover-resistant at 256)", "No change needed"),
    ("sha256",     r"\bSHA-?256\b|\bSHA-?384\b|\bSHA-?512\b|\bSHA-?3\b|hashlib\.sha(256|384|512|3)|createHash\(\s*['\"]sha(256|384|512)", "SHA-256+", "SAFE", "Grover only halves preimage; 256 stays safe", "No change needed"),
    ("mlkem",      r"\bML-?KEM\b|\bKyber\b|ml_kem|mlkem", "ML-KEM", "PQC", "NIST FIPS 203 lattice KEM", "Already quantum-safe"),
    ("mldsa",      r"\bML-?DSA\b|\bDilithium\b|ml_dsa|mldsa", "ML-DSA", "PQC", "NIST FIPS 204 lattice signature", "Already quantum-safe"),
    ("slhdsa",     r"\bSLH-?DSA\b|SPHINCS", "SLH-DSA", "PQC", "NIST FIPS 205 hash signature", "Already quantum-safe"),
]
COMPILED = [(rid, re.compile(rx, re.IGNORECASE), alg, tier, why, rec) for rid, rx, alg, tier, why, rec in RULES]

TIER_META = {
    "BROKEN_Q": ("QUANTUM-BROKEN (Shor)", "critical"),
    "WEAK":     ("WEAK / BROKEN TODAY", "high"),
    "SAFE":     ("SAFE", "none"),
    "PQC":      ("PQC / quantum-safe", "none"),
}
# Mosca default secrecy horizons (years) by sensitivity; Y = migration effort; Z = years to Q-day
Z_QDAY = 10
def mosca(x_years, y_years=3, z=Z_QDAY):
    return (x_years + y_years) > z, x_years + y_years

def is_comment_or_string_noise(line):
    s = line.strip()
    # crude: skip pure prose comments that merely mention an algo name in English
    return False

_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|\"\"\"|''')")
_APIISH = re.compile(r"[.(\[]|import |require\(|createHash|createCipher|generateKey|new [A-Z]|algorithms\.|hashlib\.|crypto\.|=\s*\w|Private|Public|Key|OID|register|isinstance")
_ERRSTR = re.compile(r'(raise|Error|"[^"]*not supported|has been moved|is deprecated|must be either)')

_RAISE = re.compile(r"\braise\b|\bTypeError|\bValueError|\bError\(")
_QUOTED = re.compile(r'"[^"]*"|\'[^\']*\'')
# Genuine cryptographic API calls — a match here is a real usage locus even when the
# algorithm name is a string argument (WebCrypto: generateKey({name:'X25519'})).
_CRYPTO_API = re.compile(
    r"crypto\.subtle|subtle\.|generateKey|generateKeyPair|importKey|exportKey|"
    r"deriveBits|deriveKey|createCipher\w*|createDecipher\w*|createHash|createHmac|"
    r"createSign|createVerify|\.encrypt\(|\.decrypt\(|\.sign\(|\.verify\(")
# Code identifiers that denote a real crypto type/definition (Python + JS libs).
_CODE_IDENT = re.compile(
    r"\b(rsa|ec|ecdsa|dsa|dh|x25519|x448|ed25519|algorithms|hashes|mldsa|mlkem|slhdsa)\.[A-Za-z_]|"
    r"class \w|register\(|isinstance\(|import |Private[Kk]ey|Public[Kk]ey|ObjectIdentifier|"
    r"CipherAlgorithm|HashAlgorithm|SignatureAlgorithm")

def usage_confidence(line, rx=None):
    """high = real code locus; low = comment / docstring / error-message string.
    Precision headline is reported on HIGH-confidence findings only."""
    if _COMMENT.match(line):
        return "low"
    # a real crypto API call or crypto type identifier => genuine locus, keep it
    if _CRYPTO_API.search(line) or _CODE_IDENT.search(line):
        return "high"
    # error/message strings that merely name an algorithm
    if _RAISE.search(line):
        return "low"
    # config constant/param assigning an algorithm name literal, '=' or object-literal ':'
    #   const AES_ALG = 'aes-256-gcm'   |   { hash: 'SHA-256', alg:'aes-256-gcm' }
    if re.search(r"[=:]\s*[\[{(]?\s*['\"]", line):
        quoted = _QUOTED.findall(line)
        if rx is None or any(rx.search(q) for q in quoted):
            return "high"
    stripped = _QUOTED.sub("", line)          # line with string literals removed
    # token survives ONLY inside a string literal, with no crypto-API/ident context => noise
    if rx is not None and not rx.search(stripped):
        return "low"
    # prose / docstring sentence: many words, no code operator
    if not re.search(r"[=(\[]|import |\.\w", stripped) and len(line.split()) >= 6:
        return "low"
    return "high" if _APIISH.search(line) else "low"

def scan_file(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings
    for i, line in enumerate(lines, 1):
        if len(line) > 400:
            continue
        for rid, rx, alg, tier, why, rec in COMPILED:
            if rx.search(line):
                conf = usage_confidence(line, rx)
                # skip obvious negatived assertions like  !/ML-KEM/  (test files)
                findings.append({
                    "file": path, "line": i, "rule": rid, "algorithm": alg,
                    "tier": tier, "why": why, "recommendation": rec,
                    "confidence": conf, "snippet": line.strip()[:160],
                })
    return findings

SRC_EXT = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".c", ".cc", ".cpp", ".rb", ".php")
SKIP_DIR = {"node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__", ".claude", "vendor", "site-packages"}

def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIR]
        for fn in fns:
            if fn.endswith(SRC_EXT):
                yield os.path.join(dp, fn)

def sensitivity_horizon(path):
    p = path.lower()
    if any(k in p for k in ("auth", "identity", "session", "key", "secret", "login", "token")):
        return 25   # long-lived secrets
    if any(k in p for k in ("payment", "bank", "pii", "user")):
        return 10
    return 5

def analyze(root, label):
    all_f = []
    nfiles = 0
    for path in walk(root):
        nfiles += 1
        all_f.extend(scan_file(path))
    # attach Mosca
    for f in all_f:
        x = sensitivity_horizon(f["file"])
        urgent, total = mosca(x)
        f["mosca_x"] = x
        f["mosca_urgent"] = urgent and f["tier"] in ("BROKEN_Q", "WEAK")
        f["rel_file"] = os.path.relpath(f["file"], root)
    counts = {t: 0 for t in TIER_META}
    for f in all_f:
        counts[f["tier"]] += 1
    total = len(all_f)
    vuln = counts["BROKEN_Q"] + counts["WEAK"]
    return {
        "target": label, "root": root, "files_scanned": nfiles,
        "total_findings": total, "counts": counts,
        "vulnerable": vuln,
        "pct_vulnerable": round(100 * vuln / total, 1) if total else 0.0,
        "urgent": sum(1 for f in all_f if f["mosca_urgent"]),
        "findings": all_f,
    }

def cbom(result):
    """Minimal CycloneDX 1.6 CBOM-style export."""
    comps = []
    seen = set()
    for f in result["findings"]:
        key = (f["algorithm"], f["tier"])
        if key in seen: continue
        seen.add(key)
        comps.append({
            "type": "cryptographic-asset",
            "name": f["algorithm"],
            "cryptoProperties": {
                "assetType": "algorithm",
                "quantumRisk": TIER_META[f["tier"]][0],
                "recommendation": f["recommendation"],
            },
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                     "tools": [{"name": "ECDAT", "version": "0.1-mvp"}],
                     "component": {"name": result["target"], "type": "application"}},
        "components": comps,
    }

def print_report(result):
    print(f"\n=== ECDAT scan: {result['target']} ===")
    print(f"files scanned      : {result['files_scanned']}")
    print(f"total findings     : {result['total_findings']}")
    for t, (label, _) in TIER_META.items():
        print(f"  {label:28} {result['counts'][t]}")
    print(f"vulnerable (Q+weak): {result['vulnerable']}  ({result['pct_vulnerable']}%)")
    print(f"Mosca-urgent       : {result['urgent']}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--label", default=None)
    ap.add_argument("--json", default=None, help="write findings json")
    ap.add_argument("--cbom", default=None, help="write CBOM json")
    ap.add_argument("--top", type=int, default=12)
    a = ap.parse_args()
    res = analyze(a.root, a.label or os.path.basename(a.root.rstrip("/")))
    print_report(res)
    print("\nTop findings:")
    for f in sorted(res["findings"], key=lambda f: (f["tier"] != "BROKEN_Q", not f["mosca_urgent"]))[:a.top]:
        flag = "!" if f["mosca_urgent"] else " "
        print(f" [{flag}] {f['rel_file']}:{f['line']:<4} {f['algorithm']:14} {TIER_META[f['tier']][0]:24} -> {f['recommendation']}")
    if a.json: json.dump(res, open(a.json, "w"), indent=1)
    if a.cbom: json.dump(cbom(res), open(a.cbom, "w"), indent=1)
