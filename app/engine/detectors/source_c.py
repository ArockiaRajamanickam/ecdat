"""C and C++ cryptographic-asset detector (OpenSSL first, plus libsodium and PQC).

There is no tree-sitter C grammar in the ECDAT dependency set, so this detector
uses the same AST-lite machinery as the Go detector: the tokenizer in
:mod:`._srcutil` masks every ``//`` and ``/* */`` comment and every string
literal first, so an identifier can never match inside a comment or a string,
and call sites are then read with balanced-paren argument splitting.

NTRO's own dataset hint names OpenSSL, which is C, so this closes the language
gap the problem statement points at.

Covered surfaces
----------------
* OpenSSL EVP digests: ``EVP_md5/sha1/sha224/sha256/sha384/sha512/sha3_*`` and
  the one-shot ``MD5()/SHA1()/SHA256()`` helpers.
* OpenSSL EVP ciphers: ``EVP_aes_256_gcm``/``EVP_des_ede3_cbc``/``EVP_rc4`` ...
  the key length and mode are read straight out of the cipher function name.
* RSA: ``RSA_generate_key_ex``, ``RSA_generate_key``,
  ``EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)`` -- the modulus size is
  recovered from the integer argument.
* EC / ECDSA / ECDH: ``EC_KEY_new_by_curve_name(NID_...)`` and the ``NID_``
  curve constants, plus ``EVP_PKEY_ED25519`` / ``EVP_PKEY_X25519``.
* DH, HMAC, PBKDF2 (``PKCS5_PBKDF2_HMAC``), ChaCha20-Poly1305.
* TLS method constructors (``SSLv3_method``, ``TLSv1_method`` ... ) mapped to a
  protocol version so obsolete TLS shows up.
* ``#include`` lines for OpenSSL, libsodium and liboqs / PQC headers.

``detect(root_path, policy) -> (artefacts, files_scanned, errors)``
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ._srcutil import (
    Collector,
    Masked,
    PolicyView,
    iter_calls,
    iter_source_files,
    lit_int,
    mask_source,
    normalize_curve,
    tls_version,
)

__all__ = ["detect", "FILE_EXTS", "DETECTOR"]

DETECTOR = "source_c"
FILE_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx")

# --- one-shot and EVP digest helpers -> (family, name) ---------------------
_DIGEST_FUNCS = {
    "MD5": ("MD5", "MD5"), "MD4": ("MD4", "MD4"),
    "SHA1": ("SHA-1", "SHA-1"), "SHA": ("SHA-1", "SHA-1"),
    "SHA224": ("SHA-2", "SHA-224"), "SHA256": ("SHA-2", "SHA-256"),
    "SHA384": ("SHA-2", "SHA-384"), "SHA512": ("SHA-2", "SHA-512"),
    "RIPEMD160": ("RIPEMD", "RIPEMD-160"), "MDC2": ("MDC2", "MDC2"),
    "EVP_md5": ("MD5", "MD5"), "EVP_md4": ("MD4", "MD4"), "EVP_mdc2": ("MDC2", "MDC2"),
    "EVP_sha1": ("SHA-1", "SHA-1"), "EVP_ripemd160": ("RIPEMD", "RIPEMD-160"),
    "EVP_sha224": ("SHA-2", "SHA-224"), "EVP_sha256": ("SHA-2", "SHA-256"),
    "EVP_sha384": ("SHA-2", "SHA-384"), "EVP_sha512": ("SHA-2", "SHA-512"),
    "EVP_sha3_224": ("SHA-3", "SHA3-224"), "EVP_sha3_256": ("SHA-3", "SHA3-256"),
    "EVP_sha3_384": ("SHA-3", "SHA3-384"), "EVP_sha3_512": ("SHA-3", "SHA3-512"),
    "EVP_blake2b512": ("BLAKE2", "BLAKE2b"), "EVP_blake2s256": ("BLAKE2", "BLAKE2s"),
}

# --- direct algorithm functions -> (family, name, kind) --------------------
_ALGO_FUNCS = {
    "RC4": ("RC4", "RC4", "algorithm"), "EVP_rc4": ("RC4", "RC4", "algorithm"),
    "EVP_rc2_cbc": ("RC2", "RC2", "algorithm"),
    "BF_set_key": ("Blowfish", "Blowfish", "algorithm"),
    "EVP_bf_cbc": ("Blowfish", "Blowfish", "algorithm"),
    "EVP_bf_ecb": ("Blowfish", "Blowfish", "algorithm"),
    "DES_set_key": ("DES", "DES", "algorithm"), "DES_ecb_encrypt": ("DES", "DES", "algorithm"),
    "DES_ncbc_encrypt": ("DES", "DES", "algorithm"), "DES_cbc_encrypt": ("DES", "DES", "algorithm"),
    "EVP_des_cbc": ("DES", "DES", "algorithm"), "EVP_des_ecb": ("DES", "DES", "algorithm"),
    "EVP_des_ede3_cbc": ("3DES", "3DES", "algorithm"), "EVP_des_ede3": ("3DES", "3DES", "algorithm"),
    "DES_ede3_cbc_encrypt": ("3DES", "3DES", "algorithm"),
    "EVP_chacha20": ("ChaCha20", "ChaCha20", "algorithm"),
    "EVP_chacha20_poly1305": ("ChaCha20-Poly1305", "ChaCha20-Poly1305", "algorithm"),
    "HMAC": ("HMAC", "HMAC", "algorithm"), "HMAC_Init_ex": ("HMAC", "HMAC", "algorithm"),
    "PKCS5_PBKDF2_HMAC": ("PBKDF2", "PBKDF2", "algorithm"),
    "PKCS5_PBKDF2_HMAC_SHA1": ("PBKDF2", "PBKDF2", "algorithm"),
    "DH_generate_key": ("DH", "DH", "key agreement"),
    "DH_new": ("DH", "DH", "key agreement"),
    "ECDSA_sign": ("ECDSA", "ECDSA", "algorithm"),
    "ECDH_compute_key": ("ECDH", "ECDH", "key agreement"),
    "crypto_box_easy": ("X25519", "X25519", "key agreement"),
    "crypto_sign_ed25519": ("Ed25519", "Ed25519", "algorithm"),
    "crypto_sign": ("Ed25519", "Ed25519", "algorithm"),
}

# EVP cipher function name -> (family, key_size, mode)
_EVP_CIPHER_RE = re.compile(
    r"\bEVP_(aes|aria|camellia|sm4)_(128|192|256)_(gcm|ccm|cbc|ecb|ctr|ofb|cfb|cfb1|cfb8|cfb128|xts|wrap)\b"
)
_FAM_FROM_EVP = {"aes": "AES", "aria": "ARIA", "camellia": "Camellia", "sm4": "SM4"}

# NID_ curve constants -> canonical curve
_NID_CURVE = {
    "NID_X9_62_prime256v1": "secp256r1", "NID_secp256r1": "secp256r1",
    "NID_secp384r1": "secp384r1", "NID_secp521r1": "secp521r1",
    "NID_secp224r1": "secp224r1", "NID_X9_62_prime192v1": "secp192r1",
    "NID_secp256k1": "secp256k1", "NID_brainpoolP256r1": "brainpoolP256r1",
    "NID_X25519": "x25519", "NID_X448": "x448",
    "NID_ED25519": "ed25519", "NID_ED448": "ed448",
}
_NID_RE = re.compile(r"\bNID_[A-Za-z0-9_]+\b")

# EVP_PKEY_<ALG> identifiers -> (family, name, kind)
_PKEY_ID = {
    "EVP_PKEY_RSA": ("RSA", "RSA", "algorithm"),
    "EVP_PKEY_RSA_PSS": ("RSA", "RSA", "algorithm"),
    "EVP_PKEY_EC": ("ECDSA", "ECDSA", "algorithm"),
    "EVP_PKEY_DH": ("DH", "DH", "key agreement"),
    "EVP_PKEY_DSA": ("DSA", "DSA", "algorithm"),
    "EVP_PKEY_ED25519": ("Ed25519", "Ed25519", "algorithm"),
    "EVP_PKEY_ED448": ("Ed448", "Ed448", "algorithm"),
    "EVP_PKEY_X25519": ("X25519", "X25519", "key agreement"),
    "EVP_PKEY_X448": ("X448", "X448", "key agreement"),
}
_PKEY_RE = re.compile(r"\bEVP_PKEY_(?:RSA_PSS|RSA|EC|DH|DSA|ED25519|ED448|X25519|X448)\b")

# TLS method constructors -> version token
_TLS_METHOD_RE = re.compile(r"\b((?:SSLv2|SSLv3|SSLv23|TLSv1_2|TLSv1_1|TLSv1)_(?:client_|server_)?method)\b")
_TLS_VER = {
    "SSLv2": "SSLv2", "SSLv3": "SSLv3", "SSLv23": "TLS (auto-negotiated)",
    "TLSv1": "TLSv1", "TLSv1_1": "TLSv1.1", "TLSv1_2": "TLSv1.2",
}

_INCLUDE_RE = re.compile(r"^[ \t]*#\s*include\s*[<\"]([^>\"]+)[>\"]", re.M)
_INCLUDE_LIBS = (
    ("openssl/", "Library", "OpenSSL"),
    ("sodium.h", "Library", "libsodium"),
    ("sodium/", "Library", "libsodium"),
    ("oqs/", "PQC", "liboqs"),
    ("gcrypt.h", "Library", "libgcrypt"),
    ("mbedtls/", "Library", "mbedTLS"),
    ("wolfssl/", "Library", "wolfSSL"),
)
_PQC_CALL_RE = re.compile(r"\bOQS_(?:KEM|SIG)_(?:new|keypair|encaps|decaps|sign|verify)\b")


def detect(root_path: str | Path, policy: Any = None) -> tuple[list, int, list[str]]:
    """Scan ``root_path`` for C/C++ cryptographic assets."""
    pv = PolicyView(policy)
    col = Collector(DETECTOR)
    errors: list[str] = []
    files_scanned = 0

    for _path, rel, src in iter_source_files(root_path, FILE_EXTS, pv, errors):
        files_scanned += 1
        try:
            masked = mask_source(src, "c")
        except Exception as exc:  # pragma: no cover
            errors.append(f"{rel}: tokenizer failed ({type(exc).__name__}: {exc})")
            continue
        try:
            _scan_file(col, masked, rel)
        except Exception as exc:
            errors.append(f"{rel}: scan error ({type(exc).__name__}: {exc})")

    return col.artefacts(), files_scanned, errors


def _rsa_bits(calls_by_line: dict, want_line: int) -> int | None:
    return None  # placeholder, replaced below


def _scan_file(col: Collector, masked: Masked, rel: str) -> None:
    code = masked.code            # comment/string-masked view (offsets == source)
    text = masked.text            # string-preserving view for #include etc.

    def line_of(off: int) -> int:
        return masked.line_of(off)

    def ev(off: int) -> str:
        return masked.evidence(off)

    calls = iter_calls(masked)

    # RSA key size from EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)
    rsa_bits: int | None = None
    for c in calls:
        if c.base == "EVP_PKEY_CTX_set_rsa_keygen_bits":
            b = lit_int(c.arg(1))
            if b:
                rsa_bits = b

    for c in calls:
        base = c.base
        # --- digests -----------------------------------------------------
        if base in _DIGEST_FUNCS:
            fam, name = _DIGEST_FUNCS[base]
            col.add(family=fam, name=name, file=rel, line=c.line, evidence=c.evidence)
            continue
        # --- direct algorithm functions ----------------------------------
        if base in _ALGO_FUNCS:
            fam, name, kind = _ALGO_FUNCS[base]
            col.add(family=fam, name=name, kind=kind, file=rel, line=c.line, evidence=c.evidence)
            continue
        # --- EVP cipher (AES-256-GCM etc.) -------------------------------
        m = _EVP_CIPHER_RE.search(base)
        if m:
            fam = _FAM_FROM_EVP[m.group(1)]
            col.add(family=fam, file=rel, line=c.line, evidence=c.evidence,
                    key_size=int(m.group(2)), mode=m.group(3).upper())
            continue
        # --- RSA key generation -----------------------------------------
        if base == "RSA_generate_key_ex":
            bits = lit_int(c.arg(1)) or rsa_bits
            col.add(family="RSA", file=rel, line=c.line, evidence=c.evidence, key_size=bits)
            continue
        if base == "RSA_generate_key":
            bits = lit_int(c.arg(0)) or rsa_bits
            col.add(family="RSA", file=rel, line=c.line, evidence=c.evidence, key_size=bits)
            continue
        if base in ("RSA_new", "RSA_public_encrypt", "RSA_private_decrypt", "RSA_sign", "RSA_verify"):
            col.add(family="RSA", file=rel, line=c.line, evidence=c.evidence, key_size=rsa_bits)
            continue
        # --- EC key by curve name ---------------------------------------
        if base == "EC_KEY_new_by_curve_name":
            curve = None
            nm = _NID_RE.search(c.arg(0) or "")
            if nm:
                curve = _NID_CURVE.get(nm.group(0))
            col.add(family="EC", name="EC", kind="algorithm", file=rel, line=c.line,
                    evidence=c.evidence, curve=normalize_curve(curve) if curve else None)
            continue
        # --- TLS method constructors ------------------------------------
        tm = _TLS_METHOD_RE.search(base)
        if tm:
            proto = tm.group(1).split("_client")[0].split("_server")[0].split("_method")[0]
            ver = _TLS_VER.get(proto, proto)
            col.add(family="TLS", name=f"TLS ({ver})", kind="protocol", file=rel,
                    line=c.line, evidence=c.evidence, extra={"tls_version": ver})
            continue

    # --- EVP_PKEY_<ALG> identifier usages (not call-shaped) -------------
    for m in _PKEY_RE.finditer(code):
        fam, name, kind = _PKEY_ID[m.group(0)]
        ks = rsa_bits if fam == "RSA" else None
        col.add(family=fam, name=None if fam in ("RSA", "ECDSA") else name, kind=kind,
                file=rel, line=line_of(m.start()), evidence=ev(m.start()), key_size=ks)

    # --- bare NID_ curve constants (EC context) ------------------------
    for m in _NID_RE.finditer(code):
        curve = _NID_CURVE.get(m.group(0))
        if not curve:
            continue
        if curve in ("ed25519", "ed448"):
            fam = name = "Ed25519" if curve == "ed25519" else "Ed448"
            col.add(family=fam, name=name, kind="algorithm", file=rel,
                    line=line_of(m.start()), evidence=ev(m.start()))
        elif curve in ("x25519", "x448"):
            fam = name = "X25519" if curve == "x25519" else "X448"
            col.add(family=fam, name=name, kind="key agreement", file=rel,
                    line=line_of(m.start()), evidence=ev(m.start()))
        else:
            col.add(family="EC", name="EC", kind="algorithm", file=rel,
                    line=line_of(m.start()), evidence=ev(m.start()),
                    curve=normalize_curve(curve))

    # --- PQC library calls ---------------------------------------------
    for m in _PQC_CALL_RE.finditer(code):
        col.add(family="ML-KEM", name="liboqs (PQC)", kind="library", file=rel,
                line=line_of(m.start()), evidence=ev(m.start()), confidence="medium")

    # --- #include libraries --------------------------------------------
    for m in _INCLUDE_RE.finditer(text):
        header = m.group(1)
        for needle, kind, libname in _INCLUDE_LIBS:
            if needle in header:
                col.add(family=libname, name=f"{libname} (library)", kind="library",
                        file=rel, line=line_of(m.start()), evidence=ev(m.start()),
                        confidence="medium")
                break
