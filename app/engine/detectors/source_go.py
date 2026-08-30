"""Go cryptographic-asset detector.

``tree_sitter_go`` is *not* part of the ECDAT dependency set, so this detector
uses the AST-lite machinery in :mod:`._srcutil`: a real tokenizer masks every
comment, string body, and raw (backtick) string first, so identifier matching
can never fire inside a comment or an unrelated literal, and call sites are then
extracted with balanced-paren argument splitting.  Import paths and composite
literals (``tls.Config{...}``) are read from the string-preserving view.

Covered surfaces
----------------
* ``crypto/rsa``      -- ``GenerateKey(rand.Reader, 2048)``, OAEP/PKCS1v15/PSS.
* ``crypto/ecdsa``    -- ``GenerateKey(elliptic.P256(), ...)``, ``crypto/ecdh``.
* ``crypto/ed25519``, ``golang.org/x/crypto/curve25519``.
* ``crypto/md5|sha1|sha256|sha512``, ``x/crypto/{md4,ripemd160,blake2b,sha3}``.
* ``crypto/des`` (incl. ``NewTripleDESCipher``), ``crypto/rc4``.
* ``crypto/aes`` + ``crypto/cipher`` mode constructors -- the block variable is
  tracked so ``cipher.NewGCM(block)`` lands on the right AES artefact, and the
  key length is recovered from ``make([]byte, 32)``.
* ``crypto/x509`` certificate handling and signature-algorithm constants.
* ``crypto/tls`` -- ``tls.Config`` MinVersion/MaxVersion/InsecureSkipVerify/
  CipherSuites, and unpinned ``tls.Dial``/``tls.Listen``.
* KDFs (pbkdf2, bcrypt, scrypt, argon2), HMAC, ChaCha20-Poly1305, JWT signing
  methods, and post-quantum packages (crypto/mlkem, CIRCL, liboqs, kyber...).

``detect(root_path, policy) -> (artefacts, files_scanned, errors)``
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._srcutil import (
    Collector,
    Masked,
    PolicyView,
    hash_info,
    iter_calls,
    iter_composites,
    iter_source_files,
    lit_int,
    mask_source,
    normalize_curve,
    obj_prop,
    parse_jwt_alg,
    pqc_info,
    tls_version,
)

__all__ = ["detect", "FILE_EXTS", "DETECTOR"]

DETECTOR = "source_go"
FILE_EXTS = (".go",)

_HASH_PKGS = {"md5", "sha1", "sha256", "sha512", "sha3", "md4", "ripemd160", "blake2b", "blake2s"}
_HASH_CTORS = ("New", "Sum", "NewLegacyKeccak", "NewShake", "NewCShake", "Checksum")

_BLOCK_CTORS = {
    "aes.NewCipher": ("AES", None),
    "des.NewCipher": ("DES", 56),
    "des.NewTripleDESCipher": ("3DES", 168),
    "rc4.NewCipher": ("RC4", None),
    "blowfish.NewCipher": ("Blowfish", None),
    "cast5.NewCipher": ("CAST5", None),
    "twofish.NewCipher": ("Twofish", None),
    "sm4.NewCipher": ("SM4", 128),
}

_MODE_CTORS = {
    "NewGCM": "GCM",
    "NewGCMWithNonceSize": "GCM",
    "NewGCMWithTagSize": "GCM",
    "NewCBCEncrypter": "CBC",
    "NewCBCDecrypter": "CBC",
    "NewCTR": "CTR",
    "NewOFB": "OFB",
    "NewCFBEncrypter": "CFB",
    "NewCFBDecrypter": "CFB",
}

_RSA_PADDING = {
    "EncryptOAEP": "OAEP",
    "DecryptOAEP": "OAEP",
    "EncryptPKCS1v15": "PKCS1-v1_5",
    "DecryptPKCS1v15": "PKCS1-v1_5",
    "DecryptPKCS1v15SessionKey": "PKCS1-v1_5",
    "SignPKCS1v15": "PKCS1-v1_5",
    "VerifyPKCS1v15": "PKCS1-v1_5",
    "SignPSS": "PSS",
    "VerifyPSS": "PSS",
}

# import path -> (family, canonical name) for algorithm packages
_IMPORT_ALGOS = {
    "crypto/md5": ("MD5", "MD5"),
    "crypto/sha1": ("SHA-1", "SHA-1"),
    "crypto/sha256": ("SHA-2", "SHA-256"),
    "crypto/sha512": ("SHA-2", "SHA-512"),
    "crypto/des": ("DES", "DES"),
    "crypto/rc4": ("RC4", "RC4"),
    "crypto/aes": ("AES", "AES"),
    "crypto/rsa": ("RSA", "RSA"),
    "crypto/dsa": ("DSA", "DSA"),
    "crypto/ecdsa": ("ECDSA", "ECDSA"),
    "crypto/ecdh": ("ECDH", "ECDH"),
    "crypto/ed25519": ("Ed25519", "Ed25519"),
    "crypto/hmac": ("HMAC", "HMAC"),
    "golang.org/x/crypto/md4": ("MD4", "MD4"),
    "golang.org/x/crypto/ripemd160": ("RIPEMD", "RIPEMD-160"),
    "golang.org/x/crypto/blowfish": ("Blowfish", "Blowfish"),
    "golang.org/x/crypto/cast5": ("CAST5", "CAST5"),
    "golang.org/x/crypto/twofish": ("Twofish", "Twofish"),
    "golang.org/x/crypto/tea": ("TEA", "TEA"),
    "golang.org/x/crypto/xtea": ("XTEA", "XTEA"),
    "golang.org/x/crypto/curve25519": ("X25519", "X25519"),
    "golang.org/x/crypto/ed25519": ("Ed25519", "Ed25519"),
    "golang.org/x/crypto/chacha20poly1305": ("ChaCha20-Poly1305", "ChaCha20-Poly1305"),
    "golang.org/x/crypto/salsa20": ("Salsa20", "Salsa20"),
    "golang.org/x/crypto/bcrypt": ("bcrypt", "bcrypt"),
    "golang.org/x/crypto/scrypt": ("scrypt", "scrypt"),
    "golang.org/x/crypto/argon2": ("Argon2", "Argon2"),
    "golang.org/x/crypto/pbkdf2": ("PBKDF2", "PBKDF2"),
    "golang.org/x/crypto/sha3": ("SHA-3", "SHA-3"),
    "golang.org/x/crypto/blake2b": ("BLAKE2", "BLAKE2b"),
    "golang.org/x/crypto/blake2s": ("BLAKE2", "BLAKE2s"),
    "crypto/mlkem": ("ML-KEM", "ML-KEM"),
}

# families that count as "already covered" for an import-derived artefact
_IMPORT_COVER = {
    "crypto/des": {"DES", "3DES"},
    "crypto/ecdh": {"ECDH", "X25519"},
    "crypto/aes": {"AES"},
    "crypto/sha256": {"SHA-2"},
    "crypto/sha512": {"SHA-2"},
    "crypto/ed25519": {"Ed25519"},
    "golang.org/x/crypto/curve25519": {"X25519"},
    "golang.org/x/crypto/sha3": {"SHA-3"},
    "golang.org/x/crypto/blake2b": {"BLAKE2"},
    "golang.org/x/crypto/blake2s": {"BLAKE2"},
}

_IMPORT_LIBS = (
    ("github.com/cloudflare/circl", "Library", "CIRCL"),
    ("github.com/open-quantum-safe", "PQC", "liboqs-go"),
    ("github.com/golang-jwt/jwt", "Library", "golang-jwt"),
    ("github.com/dgrijalva/jwt-go", "Library", "jwt-go (unmaintained)"),
    ("github.com/lestrrat-go/jwx", "Library", "jwx"),
    ("golang.org/x/crypto/openpgp", "Library", "x/crypto/openpgp (deprecated)"),
    ("golang.org/x/crypto/ssh", "Library", "x/crypto/ssh"),
    ("golang.org/x/crypto/nacl", "Library", "x/crypto/nacl"),
    ("filippo.io/edwards25519", "Library", "edwards25519"),
    ("github.com/miekg/pkcs11", "Library", "pkcs11"),
    ("software.sslmate.com/src/go-pkcs12", "Library", "go-pkcs12"),
)

_X509_FUNCS = {
    "ParseCertificate", "ParseCertificates", "CreateCertificate", "ParseCRL",
    "CreateCertificateRequest", "ParseCertificateRequest", "MarshalPKCS1PrivateKey",
    "ParsePKCS1PrivateKey", "MarshalPKCS8PrivateKey", "ParsePKCS8PrivateKey",
    "MarshalPKIXPublicKey", "ParsePKIXPublicKey", "ParseECPrivateKey",
    "MarshalECPrivateKey", "DecryptPEMBlock", "EncryptPEMBlock",
}

_IMPORT_BLOCK_RE = re.compile(r"^[ \t]*import[ \t]*\(", re.M)
_IMPORT_SINGLE_RE = re.compile(r"^[ \t]*import[ \t]+(?:[A-Za-z_.][A-Za-z0-9_]*[ \t]+)?\"", re.M)
_STRING_RE = re.compile(r"\"([^\"\n]{1,200})\"")
_MAKE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*make\s*\(\s*\[\s*\]\s*byte\s*,\s*([0-9]+)")
_ARRAY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(?:\[\s*([0-9]+)\s*\]\s*byte)")
_TLS_VERSION_ASSIGN_RE = re.compile(
    r"\b(MinVersion|MaxVersion)\s*[:=]\s*(tls\.Version[A-Za-z0-9]+|[A-Za-z0-9_.]+)"
)
_INSECURE_RE = re.compile(r"\bInsecureSkipVerify\s*[:=]\s*true\b")
_TLS_SUITE_RE = re.compile(r"\btls\.(TLS_[A-Z0-9_]+)")
_X509_SIGALG_RE = re.compile(r"\bx509\.([A-Za-z0-9]*(?:WithRSA|WithECDSA|WithRSAPSS|PureEd25519)[A-Za-z0-9]*)")
_CRYPTO_HASH_RE = re.compile(r"\bcrypto\.(MD5|MD4|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_224|SHA3_256|SHA3_384|SHA3_512|RIPEMD160|BLAKE2b_256|BLAKE2b_512|MD5SHA1)\b")
_JWT_METHOD_RE = re.compile(r"\bSigningMethod([A-Za-z0-9]+)\b")
_ELLIPTIC_RE = re.compile(r"\belliptic\.(P224|P256|P384|P521)\b")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WEAK_SUITE_RE = re.compile(r"_RC4_|_3DES_|_DES_|_NULL_|EXPORT|_MD5|_anon_", re.I)


@dataclass
class _Block:
    """A block-cipher handle waiting for its mode constructor."""

    family: str
    key_size: int | None
    line: int
    evidence: str
    mode: str | None = None
    extra: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def detect(root_path: str | Path, policy: Any = None) -> tuple[list, int, list[str]]:
    """Scan ``root_path`` for Go cryptographic assets."""
    pv = PolicyView(policy)
    col = Collector(DETECTOR)
    errors: list[str] = []
    files_scanned = 0

    for _path, rel, src in iter_source_files(root_path, FILE_EXTS, pv, errors):
        files_scanned += 1
        try:
            masked = mask_source(src, "go")
        except Exception as exc:  # pragma: no cover
            errors.append(f"{rel}: tokenizer failed ({type(exc).__name__}: {exc})")
            continue
        try:
            seen_families = _scan_file(col, masked, rel)
            _scan_imports(col, masked, rel, seen_families)
        except Exception as exc:
            errors.append(f"{rel}: scan error ({type(exc).__name__}: {exc})")

    return col.artefacts(), files_scanned, errors


# --------------------------------------------------------------------------
# per-file analysis
# --------------------------------------------------------------------------
def _scan_file(col: Collector, masked: Masked, rel: str) -> set[str]:
    code = masked.code
    seen: set[str] = set()
    sizes = _byte_sizes(code)
    blocks: dict[str, _Block] = {}
    anonymous_blocks: list[_Block] = []

    def note(family: str) -> None:
        seen.add(family)

    try:
        calls = iter_calls(masked)
    except Exception:
        calls = []

    for site in calls:
        callee = site.callee
        base = site.base
        pkg = site.receiver.rsplit(".", 1)[-1]
        line, ev = site.line, site.evidence

        # ---- block ciphers ------------------------------------------
        block_key = f"{pkg}.{base}"
        if block_key in _BLOCK_CTORS:
            family, default_size = _BLOCK_CTORS[block_key]
            key_size = default_size
            if family in ("AES", "Blowfish", "CAST5", "Twofish", "RC4"):
                hint = sizes.get(_first_ident(site.arg(0)) or "")
                if hint:
                    key_size = hint * 8
            record = _Block(family=family, key_size=key_size, line=line, evidence=ev,
                            extra={"api": block_key})
            if site.assigned_to:
                blocks[site.assigned_to] = record
            else:
                anonymous_blocks.append(record)
            note(family)
            continue

        if base in _MODE_CTORS and pkg in ("cipher", ""):
            mode = _MODE_CTORS[base]
            target = None
            for arg in site.args:
                ident = _first_ident(arg)
                if ident and ident in blocks:
                    target = blocks[ident]
                    break
            if target is None and anonymous_blocks:
                target = anonymous_blocks[-1]
            if target is not None:
                target.mode = mode
                target.extra["mode_api"] = f"cipher.{base}"
            else:
                col.add(family="Unknown", name=f"UNKNOWN (cipher.{base})", file=rel, line=line,
                        evidence=ev, extra={"api": f"cipher.{base}", "mode": mode},
                        confidence="low")
            continue

        # ---- public-key algorithms ----------------------------------
        if pkg == "rsa":
            if base in ("GenerateKey", "GenerateMultiPrimeKey"):
                bits = lit_int(site.arg(2) if base == "GenerateMultiPrimeKey" else site.arg(1))
                col.add(family="RSA", key_size=bits, file=rel, line=line, evidence=ev,
                        extra={"api": f"rsa.{base}"})
                note("RSA")
                continue
            if base in _RSA_PADDING:
                col.add(family="RSA", padding=_RSA_PADDING[base], file=rel, line=line, evidence=ev,
                        extra={"api": f"rsa.{base}"})
                note("RSA")
                continue

        if pkg == "ecdsa":
            curve = _curve_from_args(site.args)
            if base == "GenerateKey":
                col.add(family="ECDSA", curve=curve, file=rel, line=line, evidence=ev,
                        extra={"api": "ecdsa.GenerateKey"})
                note("ECDSA")
                continue
            if base in ("Sign", "Verify", "SignASN1", "VerifyASN1"):
                col.add(family="ECDSA", curve=curve, file=rel, line=line, evidence=ev,
                        extra={"api": f"ecdsa.{base}"}, confidence="medium")
                note("ECDSA")
                continue

        if pkg == "ecdh":
            curve = normalize_curve(base) if base in ("P224", "P256", "P384", "P521") else None
            if base == "X25519":
                col.add(family="X25519", name="X25519", file=rel, line=line, evidence=ev,
                        extra={"api": "ecdh.X25519"})
                note("X25519")
                continue
            if curve:
                col.add(family="ECDH", curve=curve, file=rel, line=line, evidence=ev,
                        extra={"api": f"ecdh.{base}"})
                note("ECDH")
                continue

        if pkg == "ed25519" and base in ("GenerateKey", "Sign", "Verify", "NewKeyFromSeed"):
            col.add(family="Ed25519", name="Ed25519", file=rel, line=line, evidence=ev,
                    extra={"api": f"ed25519.{base}"})
            note("Ed25519")
            continue

        if pkg == "curve25519" and base in ("X25519", "ScalarMult", "ScalarBaseMult"):
            col.add(family="X25519", name="X25519", file=rel, line=line, evidence=ev,
                    extra={"api": f"curve25519.{base}"})
            note("X25519")
            continue

        if pkg == "dsa" and base in ("GenerateKey", "GenerateParameters", "Sign", "Verify"):
            size = None
            match = re.search(r"L(\d+)N\d+", site.arg_text)
            if match:
                size = int(match.group(1))
            col.add(family="DSA", key_size=size, file=rel, line=line, evidence=ev,
                    extra={"api": f"dsa.{base}"})
            note("DSA")
            continue

        # ---- hashes / MACs ------------------------------------------
        if pkg in _HASH_PKGS and base.startswith(_HASH_CTORS):
            info = _go_hash(pkg, base)
            if info:
                col.add(family=info[0], name=info[1], file=rel, line=line, evidence=ev,
                        extra={"api": f"{pkg}.{base}",
                               "note": "Keccak (legacy) permutation" if "Keccak" in base else None})
                note(info[0])
            continue

        if pkg == "hmac" and base == "New":
            info = _hash_from_expr(site.arg(0))
            col.add(family="HMAC", name=f"HMAC-{info[1]}" if info else "HMAC",
                    file=rel, line=line, evidence=ev,
                    extra={"api": "hmac.New", "hash": info[1] if info else None})
            note("HMAC")
            if info:
                col.add(family=info[0], name=info[1], file=rel, line=line, evidence=ev,
                        extra={"api": "hmac.New"}, confidence="medium")
            continue

        # ---- KDFs and AEADs -----------------------------------------
        if pkg == "pbkdf2" and base == "Key":
            info = _hash_from_expr(site.arg(4)) or _hash_from_expr(site.arg_text)
            col.add(family="PBKDF2", name="PBKDF2", file=rel, line=line, evidence=ev,
                    extra={"api": "pbkdf2.Key", "iterations": lit_int(site.arg(2)),
                           "prf": info[1] if info else None})
            note("PBKDF2")
            continue
        if pkg == "bcrypt" and base in ("GenerateFromPassword", "CompareHashAndPassword"):
            col.add(family="bcrypt", name="bcrypt", file=rel, line=line, evidence=ev,
                    extra={"api": f"bcrypt.{base}", "cost": lit_int(site.arg(1))})
            note("bcrypt")
            continue
        if pkg == "scrypt" and base == "Key":
            col.add(family="scrypt", name="scrypt", file=rel, line=line, evidence=ev,
                    extra={"api": "scrypt.Key", "N": lit_int(site.arg(2))})
            note("scrypt")
            continue
        if pkg == "argon2" and base in ("IDKey", "Key"):
            col.add(family="Argon2", name="Argon2id" if base == "IDKey" else "Argon2i",
                    file=rel, line=line, evidence=ev, extra={"api": f"argon2.{base}"})
            note("Argon2")
            continue
        if pkg == "chacha20poly1305" and base in ("New", "NewX"):
            col.add(family="ChaCha20-Poly1305", name="ChaCha20-Poly1305", key_size=256,
                    mode="AEAD", file=rel, line=line, evidence=ev,
                    extra={"api": f"chacha20poly1305.{base}"})
            note("ChaCha20-Poly1305")
            continue

        # ---- X.509 / TLS --------------------------------------------
        if pkg == "x509" and base in _X509_FUNCS:
            col.add(family="X.509", name="X.509 certificate handling", kind="library",
                    file=rel, line=line, evidence=ev, extra={"api": f"x509.{base}"},
                    confidence="medium")
            note("X.509")
            continue

        if pkg == "tls" and base in ("Dial", "DialWithDialer", "Client", "Server", "Listen",
                                     "NewListener", "LoadX509KeyPair", "X509KeyPair"):
            if base in ("LoadX509KeyPair", "X509KeyPair"):
                col.add(family="X.509", name="X.509 certificate handling", kind="library",
                        file=rel, line=line, evidence=ev, extra={"api": f"tls.{base}"},
                        confidence="medium")
            else:
                col.add(family="TLS", name="TLS (version not pinned at call site)",
                        kind="protocol", mode="unpinned", file=rel, line=line, evidence=ev,
                        extra={"api": f"tls.{base}"}, confidence="medium")
                note("TLS")
            continue

        # ---- post-quantum -------------------------------------------
        info = pqc_info(callee)
        if info:
            col.add(family=info["family"], name=info["name"], file=rel, line=line, evidence=ev,
                    extra={"api": callee, "matched": info["matched"],
                           "standardised": info["standardised"]})
            note(info["family"])
            continue

    for record in list(blocks.values()) + anonymous_blocks:
        col.add(
            family=record.family,
            key_size=record.key_size,
            mode=record.mode,
            file=rel,
            line=record.line,
            evidence=record.evidence,
            extra=record.extra,
        )

    _scan_tls(col, masked, rel, seen)
    _scan_constants(col, masked, rel, seen)
    return seen


def _first_ident(text: str) -> str | None:
    match = _IDENT_RE.search(text or "")
    return match.group(0) if match else None


def _byte_sizes(code: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for regex in (_MAKE_RE, _ARRAY_RE):
        for m in regex.finditer(code):
            try:
                sizes[m.group(1)] = int(m.group(2))
            except Exception:
                continue
    return sizes


def _curve_from_args(args: list[str]) -> str | None:
    for arg in args:
        match = _ELLIPTIC_RE.search(arg)
        if match:
            return normalize_curve(match.group(1))
    return None


def _go_hash(pkg: str, func: str) -> tuple[str, str] | None:
    digits = re.sub(r"[^0-9_]", "", func)
    digits = digits.strip("_")
    if "Shake" in func:
        return hash_info("shake" + (digits or "128"))
    if pkg in ("md5", "sha1", "md4", "ripemd160"):
        return hash_info(pkg)
    if pkg == "sha3":
        return hash_info("sha3-" + digits) if digits else None
    if pkg in ("sha256", "sha512"):
        return hash_info("sha" + digits) if digits else hash_info(pkg)
    if pkg in ("blake2b", "blake2s"):
        return hash_info(pkg + digits) if digits else hash_info(pkg)
    return hash_info(pkg)


def _hash_from_expr(text: str) -> tuple[str, str] | None:
    if not text:
        return None
    match = re.search(r"\b(md5|md4|sha1|sha256|sha512|sha3|ripemd160|blake2b|blake2s)\s*\.\s*([A-Za-z0-9_]+)", text)
    if match:
        return _go_hash(match.group(1), match.group(2))
    match = _CRYPTO_HASH_RE.search(text)
    if match:
        return hash_info(match.group(1))
    return None


# --------------------------------------------------------------------------
# TLS configuration
# --------------------------------------------------------------------------
def _scan_tls(col: Collector, masked: Masked, rel: str, seen: set[str]) -> None:
    handled: set[int] = set()

    for body, line, evidence, body_start in iter_composites(masked, r"(?:&\s*)?tls\.Config"):
        handled.update(range(line, line + body.count("\n") + 2))
        _tls_body(col, body, body_start, masked, rel, line, evidence, "tls.Config", seen)

    for m in _TLS_VERSION_ASSIGN_RE.finditer(masked.code):
        line = masked.line_of(m.start())
        if line in handled:
            continue
        version = tls_version(m.group(2))
        if not version:
            continue
        col.add(
            family="TLS",
            name=version if version[:3] in ("TLS", "SSL") else f"TLS-{version}",
            kind="protocol", mode=version, file=rel, line=line,
            evidence=masked.evidence(m.start()),
            extra={"api": "tls.Config", "option": m.group(1), "version": version},
        )
        seen.add("TLS")

    for m in _INSECURE_RE.finditer(masked.code):
        line = masked.line_of(m.start())
        if line in handled:
            continue
        col.add(
            family="TLS", name="TLS (certificate validation disabled)", kind="protocol",
            mode="InsecureSkipVerify=true", file=rel, line=line,
            evidence=masked.evidence(m.start()),
            extra={"api": "tls.Config", "InsecureSkipVerify": True},
        )
        seen.add("TLS")


def _tls_body(
    col: Collector,
    body: str,
    body_start: int,
    masked: Masked,
    rel: str,
    line: int,
    evidence: str,
    api: str,
    seen: set[str],
) -> None:
    def at(offset_in_body: int) -> tuple[int, str]:
        offset = body_start + offset_in_body
        return masked.line_of(offset), masked.evidence(offset)

    for option in ("MinVersion", "MaxVersion"):
        raw = obj_prop(body, option)
        version = tls_version(raw) if raw else None
        if version:
            match = re.search(r"\b" + option + r"\b", body)
            opt_line, opt_ev = at(match.start()) if match else (line, evidence)
            col.add(
                family="TLS",
                name=version if version[:3] in ("TLS", "SSL") else f"TLS-{version}",
                kind="protocol", mode=version, file=rel, line=opt_line, evidence=opt_ev,
                extra={"api": api, "option": option, "version": version},
            )
            seen.add("TLS")
    insecure = re.search(r"\bInsecureSkipVerify\s*:\s*true\b", body)
    if insecure:
        ins_line, ins_ev = at(insecure.start())
        col.add(
            family="TLS", name="TLS (certificate validation disabled)", kind="protocol",
            mode="InsecureSkipVerify=true", file=rel, line=ins_line, evidence=ins_ev,
            extra={"api": api, "InsecureSkipVerify": True},
        )
        seen.add("TLS")
    suite_matches = list(_TLS_SUITE_RE.finditer(body))
    suites = [m.group(1) for m in suite_matches]
    if suites:
        weak = [s for s in suites if _WEAK_SUITE_RE.search(s)]
        list_line, list_ev = at(suite_matches[0].start())
        col.add(
            family="TLS", name="TLS (cipher suite list)", kind="protocol", mode="ciphers",
            file=rel, line=list_line, evidence=list_ev,
            extra={"api": api, "ciphers": suites, "weak_suites": weak},
            confidence="high" if weak else "medium",
        )
        seen.add("TLS")
        for match in suite_matches:
            suite = match.group(1)
            if not _WEAK_SUITE_RE.search(suite):
                continue
            suite_line, suite_ev = at(match.start())
            upper = suite.upper()
            if "3DES" in upper:
                col.add(family="3DES", key_size=168, mode="CBC", file=rel, line=suite_line,
                        evidence=suite_ev, extra={"api": api, "cipher_suite": suite})
                seen.add("3DES")
            elif "RC4" in upper:
                col.add(family="RC4", file=rel, line=suite_line, evidence=suite_ev,
                        extra={"api": api, "cipher_suite": suite})
                seen.add("RC4")
            elif "_DES_" in upper:
                col.add(family="DES", key_size=56, mode="CBC", file=rel, line=suite_line,
                        evidence=suite_ev, extra={"api": api, "cipher_suite": suite})
                seen.add("DES")
    for match in re.finditer(r"\btls\.(CurveP\d+|X25519)\b", body):
        curve = match.group(1)
        curve_line, curve_ev = at(match.start())
        normalized = normalize_curve(curve.replace("Curve", ""))
        if curve == "X25519":
            col.add(family="X25519", name="X25519", file=rel, line=curve_line, evidence=curve_ev,
                    extra={"api": api, "option": "CurvePreferences"}, confidence="medium")
            seen.add("X25519")
        elif normalized:
            col.add(family="ECDH", curve=normalized, file=rel, line=curve_line, evidence=curve_ev,
                    extra={"api": api, "option": "CurvePreferences"}, confidence="medium")
            seen.add("ECDH")


# --------------------------------------------------------------------------
# constants (signature algorithms, crypto.Hash, JWT signing methods)
# --------------------------------------------------------------------------
def _scan_constants(col: Collector, masked: Masked, rel: str, seen: set[str]) -> None:
    code = masked.code

    for m in _X509_SIGALG_RE.finditer(code):
        token = m.group(1)
        line = masked.line_of(m.start())
        evidence = masked.evidence(m.start())
        if token == "PureEd25519":
            col.add(family="Ed25519", name="Ed25519", file=rel, line=line, evidence=evidence,
                    extra={"api": "x509.SignatureAlgorithm"})
            seen.add("Ed25519")
            continue
        match = re.match(r"^(MD2|MD5|SHA1|SHA256|SHA384|SHA512)With(RSAPSS|RSA|ECDSA)$", token)
        if not match:
            continue
        info = hash_info(match.group(1))
        family = {"RSA": "RSA", "RSAPSS": "RSA", "ECDSA": "ECDSA"}[match.group(2)]
        col.add(
            family=family,
            name=f"{family}-{info[1]}" if info else None,
            padding="PSS" if match.group(2) == "RSAPSS" else ("PKCS1-v1_5" if family == "RSA" else None),
            file=rel, line=line, evidence=evidence,
            extra={"api": "x509.SignatureAlgorithm", "signature_alg": token,
                   "hash": info[1] if info else None},
        )
        seen.add(family)
        if info:
            col.add(family=info[0], name=info[1], file=rel, line=line, evidence=evidence,
                    extra={"api": "x509.SignatureAlgorithm"}, confidence="medium")
            seen.add(info[0])

    for m in _CRYPTO_HASH_RE.finditer(code):
        info = hash_info(m.group(1))
        if not info:
            continue
        line = masked.line_of(m.start())
        col.add(family=info[0], name=info[1], file=rel, line=line,
                evidence=masked.evidence(m.start()),
                extra={"api": "crypto.Hash"}, confidence="medium")
        seen.add(info[0])

    for m in _JWT_METHOD_RE.finditer(code):
        info = parse_jwt_alg(m.group(1))
        if not info:
            continue
        line = masked.line_of(m.start())
        col.add(
            family=info["family"], name=info["name"], key_size=info.get("key_size"),
            curve=info.get("curve"), mode=info.get("mode"), padding=info.get("padding"),
            file=rel, line=line, evidence=masked.evidence(m.start()),
            extra={"api": "jwt.SigningMethod", "jwt_alg": m.group(1).upper(),
                   "hash": info.get("hash")},
        )
        seen.add(info["family"])

    for m in _IDENT_RE.finditer(code):
        token = m.group(0)
        if len(token) < 4:
            continue
        info = pqc_info(token)
        if not info:
            continue
        line = masked.line_of(m.start())
        col.add(
            family=info["family"], name=info["name"], file=rel, line=line,
            evidence=masked.evidence(m.start()),
            extra={"matched": info["matched"], "source": "identifier",
                   "standardised": info["standardised"]},
            confidence="medium",
        )
        seen.add(info["family"])


# --------------------------------------------------------------------------
# imports
# --------------------------------------------------------------------------
def _import_paths(masked: Masked) -> list[tuple[str, int, str]]:
    """Return ``(path, line, evidence)`` for every imported package."""
    out: list[tuple[str, int, str]] = []
    code = masked.code

    for m in _IMPORT_BLOCK_RE.finditer(code):
        depth = 0
        i = m.end() - 1
        end = len(code)
        while i < len(code):
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        chunk = masked.text[m.end() : end]
        for sm in _STRING_RE.finditer(chunk):
            offset = m.end() + sm.start()
            out.append((sm.group(1), masked.line_of(offset), masked.evidence(offset)))

    for m in _IMPORT_SINGLE_RE.finditer(code):
        sm = _STRING_RE.search(masked.text, m.end() - 1)
        if sm is None:
            continue
        out.append((sm.group(1), masked.line_of(sm.start()), masked.evidence(sm.start())))
    return out


def _scan_imports(col: Collector, masked: Masked, rel: str, seen: set[str]) -> None:
    for path, line, evidence in _import_paths(masked):
        if not path or " " in path:
            continue
        info = pqc_info(path)
        if info:
            col.add(
                family=info["family"], name=info["name"], kind="library",
                file=rel, line=line, evidence=evidence,
                extra={"package": path, "source": "import", "ecosystem": "go",
                       "standardised": info["standardised"]},
            )
            seen.add(info["family"])
            continue

        for prefix, family, display in _IMPORT_LIBS:
            if path == prefix or path.startswith(prefix + "/"):
                col.add(
                    family="Library" if family == "Library" else family,
                    name=display, kind="library", file=rel, line=line, evidence=evidence,
                    extra={"package": path, "ecosystem": "go"},
                )
                break

        algo = _IMPORT_ALGOS.get(path)
        if algo and not (_IMPORT_COVER.get(path, {algo[0]}) & seen):
            family, name = algo
            col.add(
                family=family, name=name, file=rel, line=line, evidence=evidence,
                extra={"package": path, "source": "import",
                       "note": "imported but no call site resolved in this file"},
                confidence="medium",
            )
