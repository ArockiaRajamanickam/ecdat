"""CycloneDX 1.6 CBOM (Cryptography Bill of Materials) serializer.

``to_cbom(scan_result)`` turns an ECDAT scan into a CycloneDX 1.6 document whose
components are ``cryptographic-asset`` entries carrying a real ``cryptoProperties``
block: primitive, parameter set, curve, mode, padding, execution environment,
certification level, crypto functions and the registered OID where we know one.

Two extras ride along on every component:

* ``evidence.occurrences`` - the spec's own provenance array, one entry per
  detector hit (file + line + the matched source text).
* our quantum-risk view - Mosca X/Y/Z/shortfall, severity, score and the
  recommended NIST PQC replacement.  These are emitted as namespaced
  ``properties[]`` (``ecdat:*``), which is schema-valid everywhere, and - unless
  ``strict=True`` - also as a convenience ``ecdat`` object on the component so
  dashboards do not have to unpack name/value pairs.

An OID is emitted only when it is actually registered for the observed
parameters; an unknown AES mode yields no ``oid`` field rather than a
synthesised arc.  Curve security strengths defer to :mod:`app.engine.kb`, which
is the authoritative table.

Pure stdlib.  Never raises on a partially-populated artefact.
"""

from __future__ import annotations

import json
from typing import Any

try:  # normal package import
    from ._common import (
        TOOL_NAME,
        TOOL_URI,
        TOOL_VENDOR,
        TOOL_VERSION,
        artefact_key,
        artefacts_of,
        engine_extra,
        extra_of,
        family_of,
        field,
        iso8601,
        name_of,
        occurrences_of,
        params_of,
        posix_path,
        rank_artefacts,
        relative_path,
        score_of,
        severity_counts,
        severity_of,
        slug,
        stable_id,
        threat_of,
        trade_offs_of,
    )
except ImportError:  # pragma: no cover - direct execution / partial tree
    from app.engine.serializers._common import (  # type: ignore[no-redef]
        TOOL_NAME,
        TOOL_URI,
        TOOL_VENDOR,
        TOOL_VERSION,
        artefact_key,
        artefacts_of,
        engine_extra,
        extra_of,
        family_of,
        field,
        iso8601,
        name_of,
        occurrences_of,
        params_of,
        posix_path,
        rank_artefacts,
        relative_path,
        score_of,
        severity_counts,
        severity_of,
        slug,
        stable_id,
        threat_of,
        trade_offs_of,
    )

__all__ = ["to_cbom", "to_cbom_json", "CBOM_SPEC_VERSION"]

CBOM_SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# --------------------------------------------------------------------------- #
# CycloneDX enum vocabularies (1.6)
# --------------------------------------------------------------------------- #

_PRIMITIVES = {
    "ae", "block-cipher", "combiner", "drbg", "hash", "kdf", "kem", "key-agree",
    "mac", "other", "pke", "signature", "stream-cipher", "unknown",
}
_MODES = {"cbc", "ccm", "cfb", "ctr", "ecb", "gcm", "none", "other", "unknown", "ofb"}
_PADDINGS = {
    "pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown",
}
_MATERIAL_TYPES = {
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret",
    "tag", "additional-data", "password", "credential", "token", "other", "unknown",
}
_PROTOCOL_TYPES = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}

# --------------------------------------------------------------------------- #
# Family -> primitive / crypto functions
# --------------------------------------------------------------------------- #

_FAMILY_PRIMITIVE: dict[str, str] = {
    "RSA": "pke",
    "DSA": "signature",
    "ECDSA": "signature",
    "EDDSA": "signature",
    "ED25519": "signature",
    "ED448": "signature",
    "ECDH": "key-agree",
    "DH": "key-agree",
    "DIFFIE-HELLMAN": "key-agree",
    "X25519": "key-agree",
    "X448": "key-agree",
    "ML-KEM": "kem",
    "KYBER": "kem",
    "HQC": "kem",
    "BIKE": "kem",
    "CLASSIC-MCELIECE": "kem",
    "FRODOKEM": "kem",
    "SIKE": "kem",
    "SIDH": "kem",
    "ML-DSA": "signature",
    "DILITHIUM": "signature",
    "SLH-DSA": "signature",
    "SPHINCS+": "signature",
    "FALCON": "signature",
    "FN-DSA": "signature",
    "XMSS": "signature",
    "LMS": "signature",
    "RAINBOW": "signature",
    "AES": "block-cipher",
    "3DES": "block-cipher",
    "DES": "block-cipher",
    "DESEDE": "block-cipher",
    "BLOWFISH": "block-cipher",
    "CAMELLIA": "block-cipher",
    "IDEA": "block-cipher",
    "CAST5": "block-cipher",
    "SEED": "block-cipher",
    "ARIA": "block-cipher",
    "SM4": "block-cipher",
    "RC2": "block-cipher",
    "RC4": "stream-cipher",
    "ARC4": "stream-cipher",
    "CHACHA20": "stream-cipher",
    "CHACHA20-POLY1305": "ae",
    "SALSA20": "stream-cipher",
    "SHA-1": "hash",
    "SHA-2": "hash",
    "SHA-3": "hash",
    "SHAKE": "hash",
    "MD5": "hash",
    "MD4": "hash",
    "MD2": "hash",
    "RIPEMD": "hash",
    "BLAKE2": "hash",
    "BLAKE3": "hash",
    "SM3": "hash",
    "HMAC": "mac",
    "CMAC": "mac",
    "GMAC": "mac",
    "POLY1305": "mac",
    "PBKDF2": "kdf",
    "SCRYPT": "kdf",
    "ARGON2": "kdf",
    "BCRYPT": "kdf",
    "HKDF": "kdf",
    "PBKDF1": "kdf",
    "DRBG": "drbg",
    "PRNG": "drbg",
}

_FAMILY_FUNCTIONS: dict[str, list[str]] = {
    "pke": ["encrypt", "decrypt", "keygen", "sign", "verify"],
    "signature": ["sign", "verify", "keygen"],
    "key-agree": ["keygen", "keyderive"],
    "kem": ["encapsulate", "decapsulate", "keygen"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "ae": ["encrypt", "decrypt", "tag"],
    "hash": ["digest"],
    "mac": ["tag"],
    "kdf": ["keyderive"],
    "drbg": ["generate"],
    "other": ["unknown"],
    "unknown": ["unknown"],
}

# Classical bits of security we can state with confidence.  Used for
# ``classicalSecurityLevel``; left out when unknown rather than guessed.
_CLASSICAL_RSA_DSA_DH = {
    512: 56, 768: 64, 1024: 80, 1536: 96, 2048: 112, 3072: 128, 4096: 152,
    7680: 192, 8192: 200, 15360: 256,
}

# Fallback only.  ``app.engine.kb`` owns the authoritative curve table and is
# consulted first; these values are kept in agreement with it (secp521r1 is
# 256-bit, matching kb.CURVES - the old 260 here was a second, divergent table).
_CLASSICAL_CURVE = {
    "secp192r1": 96, "prime192v1": 96, "p-192": 96,
    "secp224r1": 112, "p-224": 112,
    "secp256r1": 128, "prime256v1": 128, "p-256": 128, "secp256k1": 128,
    "secp384r1": 192, "p-384": 192,
    "secp521r1": 256, "p-521": 256,
    "curve25519": 128, "x25519": 128, "ed25519": 128,
    "curve448": 224, "x448": 224, "ed448": 224,
    "brainpoolp256r1": 128, "brainpoolp384r1": 192, "brainpoolp512r1": 256,
}

#: NIST PQC security categories for the standardised parameter sets.
_NIST_QUANTUM_LEVEL = {
    "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
    "KYBER512": 1, "KYBER768": 3, "KYBER1024": 5,
    "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
    "SLH-DSA-SHA2-128S": 1, "SLH-DSA-SHA2-128F": 1,
    "SLH-DSA-SHA2-192S": 3, "SLH-DSA-SHA2-192F": 3,
    "SLH-DSA-SHA2-256S": 5, "SLH-DSA-SHA2-256F": 5,
    "SLH-DSA-SHAKE-128S": 1, "SLH-DSA-SHAKE-128F": 1,
    "SLH-DSA-SHAKE-192S": 3, "SLH-DSA-SHAKE-192F": 3,
    "SLH-DSA-SHAKE-256S": 5, "SLH-DSA-SHAKE-256F": 5,
    "FALCON-512": 1, "FALCON-1024": 5,
}

# --------------------------------------------------------------------------- #
# Curve strengths: kb.py is authoritative, this module only falls back.
# --------------------------------------------------------------------------- #

_KB_SENTINEL = object()
_KB_MODULE: Any = _KB_SENTINEL


def _kb_module() -> Any:
    """Import ``app.engine.kb`` once, lazily, tolerating its absence."""
    global _KB_MODULE
    if _KB_MODULE is _KB_SENTINEL:
        try:
            from .. import kb as module  # type: ignore[no-redef]
        except Exception:
            try:
                from app.engine import kb as module  # type: ignore[no-redef]
            except Exception:
                module = None
        _KB_MODULE = module
    return _KB_MODULE


def _coerce_bits(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, dict):
        for key in ("classical_bits", "classical", "bits", "strength", "security",
                    "security_bits", "classical_security_level"):
            bits = _coerce_bits(value.get(key))
            if bits is not None:
                return bits
        return None
    for attr in ("classical_bits", "bits", "strength", "security_bits"):
        if hasattr(value, attr):
            bits = _coerce_bits(getattr(value, attr))
            if bits is not None:
                return bits
    return None


def _curve_strength(curve: str) -> int | None:
    """Classical security bits for ``curve``, preferring the KB's own table."""
    if not curve:
        return None
    key = curve.strip().lower()
    module = _kb_module()
    table = getattr(module, "CURVES", None) if module is not None else None
    if isinstance(table, dict):
        for candidate in (curve, key, key.replace("-", ""), key.replace("_", "-")):
            if candidate in table:
                bits = _coerce_bits(table[candidate])
                if bits is not None:
                    return bits
    return _CLASSICAL_CURVE.get(key)


# --------------------------------------------------------------------------- #
# OID registry - canonical name first, family/param fallback second.
# --------------------------------------------------------------------------- #

_OID_BY_NAME: dict[str, str] = {
    # Public key
    "RSA": "1.2.840.113549.1.1.1",
    "RSA-PSS": "1.2.840.113549.1.1.10",
    "RSA-OAEP": "1.2.840.113549.1.1.7",
    "SHA1WITHRSA": "1.2.840.113549.1.1.5",
    "SHA256WITHRSA": "1.2.840.113549.1.1.11",
    "SHA384WITHRSA": "1.2.840.113549.1.1.12",
    "SHA512WITHRSA": "1.2.840.113549.1.1.13",
    "MD5WITHRSA": "1.2.840.113549.1.1.4",
    "DSA": "1.2.840.10040.4.1",
    "ECDSA": "1.2.840.10045.2.1",
    "EC": "1.2.840.10045.2.1",
    "ECDSA-WITH-SHA1": "1.2.840.10045.4.1",
    "ECDSA-WITH-SHA256": "1.2.840.10045.4.3.2",
    "ECDSA-WITH-SHA384": "1.2.840.10045.4.3.3",
    "ECDSA-WITH-SHA512": "1.2.840.10045.4.3.4",
    "DH": "1.2.840.113549.1.3.1",
    "DIFFIE-HELLMAN": "1.2.840.113549.1.3.1",
    "ECDH": "1.3.132.1.12",
    "X25519": "1.3.101.110",
    "X448": "1.3.101.111",
    "ED25519": "1.3.101.112",
    "ED448": "1.3.101.113",
    # Block / stream ciphers
    "DES": "1.3.14.3.2.7",
    "3DES": "1.2.840.113549.3.7",
    "DESEDE": "1.2.840.113549.3.7",
    "TRIPLEDES": "1.2.840.113549.3.7",
    "RC2": "1.2.840.113549.3.2",
    "RC4": "1.2.840.113549.3.4",
    "ARC4": "1.2.840.113549.3.4",
    "BLOWFISH": "1.3.6.1.4.1.3029.1.2",
    "CHACHA20-POLY1305": "1.2.840.113549.1.9.16.3.18",
    # Hashes
    "MD2": "1.2.840.113549.2.2",
    "MD4": "1.2.840.113549.2.4",
    "MD5": "1.2.840.113549.2.5",
    "SHA-1": "1.3.14.3.2.26",
    "SHA1": "1.3.14.3.2.26",
    "SHA-224": "2.16.840.1.101.3.4.2.4",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-224": "2.16.840.1.101.3.4.2.7",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "SHA3-384": "2.16.840.1.101.3.4.2.9",
    "SHA3-512": "2.16.840.1.101.3.4.2.10",
    "SHAKE128": "2.16.840.1.101.3.4.2.11",
    "SHAKE256": "2.16.840.1.101.3.4.2.12",
    # MAC / KDF
    "HMAC-SHA1": "1.2.840.113549.2.7",
    "HMAC-SHA224": "1.2.840.113549.2.8",
    "HMAC-SHA256": "1.2.840.113549.2.9",
    "HMAC-SHA384": "1.2.840.113549.2.10",
    "HMAC-SHA512": "1.2.840.113549.2.11",
    "PBKDF2": "1.2.840.113549.1.5.12",
    "HKDF-SHA256": "1.2.840.113549.1.9.16.3.28",
    # NIST PQC (FIPS 203/204/205)
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
    "SLH-DSA-SHA2-128S": "2.16.840.1.101.3.4.3.20",
    "SLH-DSA-SHA2-128F": "2.16.840.1.101.3.4.3.21",
    "SLH-DSA-SHA2-192S": "2.16.840.1.101.3.4.3.22",
    "SLH-DSA-SHA2-192F": "2.16.840.1.101.3.4.3.23",
    "SLH-DSA-SHA2-256S": "2.16.840.1.101.3.4.3.24",
    "SLH-DSA-SHA2-256F": "2.16.840.1.101.3.4.3.25",
    "SLH-DSA-SHAKE-128S": "2.16.840.1.101.3.4.3.26",
    "SLH-DSA-SHAKE-128F": "2.16.840.1.101.3.4.3.27",
    "SLH-DSA-SHAKE-192S": "2.16.840.1.101.3.4.3.28",
    "SLH-DSA-SHAKE-192F": "2.16.840.1.101.3.4.3.29",
    "SLH-DSA-SHAKE-256S": "2.16.840.1.101.3.4.3.30",
    "SLH-DSA-SHAKE-256F": "2.16.840.1.101.3.4.3.31",
}

# AES: 2.16.840.1.101.3.4.1.<base + mode offset>
_AES_BASE = {128: 0, 192: 20, 256: 40}
_AES_MODE_OFFSET = {"ecb": 1, "cbc": 2, "ofb": 3, "cfb": 4, "wrap": 5, "gcm": 6, "ccm": 7}


def _aes_oid(key_size: Any, mode: Any) -> str | None:
    """Registered AES OID, or ``None`` when the parameters do not pin one.

    The NIST arc numbers a *mode* under each key size (``...4.1.1`` = aes128-ECB
    and so on); ``...4.1.0`` and ``...4.1.20`` are unassigned.  When either the
    key size or the mode is unknown there is no registered OID to state, so we
    emit none rather than synthesising an arc that does not exist.
    """
    try:
        base = _AES_BASE[int(key_size)]
    except (TypeError, ValueError, KeyError):
        return None
    offset = _AES_MODE_OFFSET.get(str(mode or "").strip().lower())
    if offset is None:
        return None
    return f"2.16.840.1.101.3.4.1.{base + offset}"


def _oid_for(artefact: Any) -> str | None:
    name = str(field(artefact, "name", "") or "").strip().upper()
    family = str(field(artefact, "family", "") or "").strip().upper()
    params = params_of(artefact)
    explicit = extra_of(artefact)
    if explicit.get("oid"):
        return str(explicit["oid"])
    if family == "AES" or name.startswith("AES"):
        return _aes_oid(field(params, "key_size", None), field(params, "mode", None))
    for candidate in (name, name.replace("_", "-"), family, family.replace("_", "-")):
        if candidate in _OID_BY_NAME:
            return _OID_BY_NAME[candidate]
    # "RSA-2048" / "SHA-256/HMAC" style names: try the leading token.
    head = name.split("-")[0].split("/")[0].split(" ")[0]
    if head in _OID_BY_NAME:
        return _OID_BY_NAME[head]
    return None


# --------------------------------------------------------------------------- #
# cryptoProperties builders
# --------------------------------------------------------------------------- #


def _primitive_for(artefact: Any) -> str:
    family = str(field(artefact, "family", "") or "").strip().upper()
    name = str(field(artefact, "name", "") or "").strip().upper()
    mode = str(field(params_of(artefact), "mode", "") or "").strip().lower()
    if mode in ("gcm", "ccm", "ocb", "eax", "siv") or "POLY1305" in name:
        if family not in ("HMAC", "CMAC", "POLY1305"):
            return "ae"
    for key in (family, name):
        if key in _FAMILY_PRIMITIVE:
            return _FAMILY_PRIMITIVE[key]
    for key, primitive in _FAMILY_PRIMITIVE.items():
        if name.startswith(key) or family.startswith(key):
            return primitive
    if "SHA" in name or "HASH" in name:
        return "hash"
    return "unknown"


def _crypto_functions(artefact: Any, primitive: str) -> list[str]:
    declared = extra_of(artefact).get("crypto_functions")
    if isinstance(declared, (list, tuple)) and declared:
        return [str(f).strip().lower() for f in declared if str(f).strip()]
    return list(_FAMILY_FUNCTIONS.get(primitive, ["unknown"]))


def _parameter_set_identifier(artefact: Any) -> str | None:
    params = params_of(artefact)
    key_size = field(params, "key_size", None)
    if key_size not in (None, ""):
        return str(key_size)
    name = str(field(artefact, "name", "") or "")
    family = str(field(artefact, "family", "") or "")
    if name and family and name.upper() != family.upper():
        tail = name[len(family):].lstrip("-_ ") if name.upper().startswith(family.upper()) else name
        return tail or name
    curve = field(params, "curve", None)
    return str(curve) if curve else None


def _classical_level(artefact: Any) -> int | None:
    family = str(field(artefact, "family", "") or "").strip().upper()
    params = params_of(artefact)
    curve = str(field(params, "curve", "") or "").strip()
    if curve:
        bits = _curve_strength(curve)
        if bits is not None:
            return bits
    key_size = field(params, "key_size", None)
    try:
        bits = int(key_size)
    except (TypeError, ValueError):
        return None
    if family in ("RSA", "DSA", "DH", "DIFFIE-HELLMAN", "ELGAMAL"):
        return _CLASSICAL_RSA_DSA_DH.get(bits)
    if family in ("AES", "CAMELLIA", "ARIA", "CHACHA20", "CHACHA20-POLY1305", "SEED", "SM4"):
        return bits
    if family in ("3DES", "DESEDE", "TRIPLEDES"):
        return 112
    if family == "DES":
        return 56
    if family in ("SHA-2", "SHA-3", "SHA2", "SHA3"):
        return bits // 2
    return None


def _quantum_level(artefact: Any) -> int | None:
    name = str(field(artefact, "name", "") or "").strip().upper()
    if name in _NIST_QUANTUM_LEVEL:
        return _NIST_QUANTUM_LEVEL[name]
    family = str(field(artefact, "family", "") or "").strip().upper()
    key_size = field(params_of(artefact), "key_size", None)
    combined = f"{family}-{key_size}" if key_size else family
    return _NIST_QUANTUM_LEVEL.get(combined)


def _enum_or_other(value: Any, allowed: set[str], fallback: str = "other") -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower().replace("_", "-")
    if text in allowed:
        return text
    return fallback


def _algorithm_properties(artefact: Any) -> dict[str, Any]:
    params = params_of(artefact)
    extra = extra_of(artefact)
    primitive = _primitive_for(artefact)
    props: dict[str, Any] = {"primitive": primitive if primitive in _PRIMITIVES else "unknown"}

    parameter_set = _parameter_set_identifier(artefact)
    if parameter_set:
        props["parameterSetIdentifier"] = parameter_set

    curve = field(params, "curve", None)
    if curve:
        props["curve"] = str(curve)

    mode = _enum_or_other(field(params, "mode", None), _MODES)
    if mode:
        props["mode"] = mode

    padding = _enum_or_other(field(params, "padding", None), _PADDINGS)
    if padding:
        props["padding"] = padding

    execution = extra.get("execution_environment")
    props["executionEnvironment"] = str(execution or "software-plain-ram")
    platform = extra.get("implementation_platform")
    props["implementationPlatform"] = str(platform or "generic")
    certification = extra.get("certification_level")
    if isinstance(certification, (list, tuple)) and certification:
        props["certificationLevel"] = [str(c) for c in certification]
    else:
        props["certificationLevel"] = [str(certification) if certification else "none"]

    props["cryptoFunctions"] = _crypto_functions(artefact, primitive)

    classical = _classical_level(artefact)
    if classical is not None:
        props["classicalSecurityLevel"] = int(classical)
    quantum = _quantum_level(artefact)
    if quantum is not None:
        props["nistQuantumSecurityLevel"] = int(quantum)
    elif threat_of(artefact) in ("shor_broken", "legacy_broken"):
        props["nistQuantumSecurityLevel"] = 0
    return props


def _certificate_properties(artefact: Any) -> dict[str, Any]:
    params = params_of(artefact)
    extra = extra_of(artefact)
    props: dict[str, Any] = {}
    mapping = {
        "subjectName": ("subject", "subject_name", "subject_dn"),
        "issuerName": ("issuer", "issuer_name", "issuer_dn"),
        "notValidBefore": ("not_before", "not_valid_before"),
        "certificateFormat": ("format", "certificate_format"),
        "certificateExtension": ("extension", "file_extension"),
    }
    for target, keys in mapping.items():
        for key in keys:
            if extra.get(key):
                value = extra[key]
                props[target] = iso8601(value) if target == "notValidBefore" else str(value)
                break
    not_after = field(params, "not_after", None) or extra.get("not_after")
    if not_after:
        props["notValidAfter"] = iso8601(not_after)
    props.setdefault("certificateFormat", "X.509")
    props.setdefault("certificateExtension", "pem")
    for target, key in (("signatureAlgorithmRef", "signature_algorithm_ref"),
                        ("subjectPublicKeyRef", "subject_public_key_ref")):
        if extra.get(key):
            props[target] = str(extra[key])
    return props


def _related_material_properties(artefact: Any) -> dict[str, Any]:
    params = params_of(artefact)
    extra = extra_of(artefact)
    name = str(field(artefact, "name", "") or "").lower()
    declared = str(extra.get("material_type", "") or "").strip().lower()
    if declared in _MATERIAL_TYPES:
        material = declared
    elif "private" in name:
        material = "private-key"
    elif "public" in name:
        material = "public-key"
    elif "secret" in name or "symmetric" in name:
        material = "secret-key"
    elif "password" in name or "credential" in name:
        material = "credential"
    elif "token" in name:
        material = "token"
    else:
        material = "key"
    props: dict[str, Any] = {"type": material}
    key_size = field(params, "key_size", None)
    if key_size not in (None, ""):
        try:
            props["size"] = int(key_size)
        except (TypeError, ValueError):
            pass
    if extra.get("format"):
        props["format"] = str(extra["format"])
    if extra.get("state"):
        props["state"] = str(extra["state"])
    not_after = field(params, "not_after", None)
    if not_after:
        props["expirationDate"] = iso8601(not_after)
    props["secured"] = bool(extra.get("secured", False))
    return props


def _protocol_properties(artefact: Any) -> dict[str, Any]:
    extra = extra_of(artefact)
    name = str(field(artefact, "name", "") or "").lower()
    family = str(field(artefact, "family", "") or "").lower()
    kind = "other"
    for candidate in _PROTOCOL_TYPES:
        if candidate in name or candidate in family:
            kind = candidate
            break
    props: dict[str, Any] = {"type": kind}
    version = extra.get("version") or extra.get("protocol_version")
    if version:
        props["version"] = str(version)
    else:
        digits = "".join(ch for ch in name if ch.isdigit() or ch == ".")
        if digits.strip("."):
            props["version"] = digits.strip(".")
    suites = extra.get("cipher_suites") or extra.get("ciphersuites")
    if isinstance(suites, (list, tuple)) and suites:
        rendered = []
        for suite in suites:
            if isinstance(suite, dict):
                rendered.append({k: v for k, v in suite.items() if v not in (None, "", [])})
            else:
                rendered.append({"name": str(suite)})
        props["cipherSuites"] = rendered
    return props


_KIND_TO_ASSET_TYPE = {
    "algorithm": "algorithm",
    "certificate": "certificate",
    "key": "related-crypto-material",
    "material": "related-crypto-material",
    "related-crypto-material": "related-crypto-material",
    "protocol": "protocol",
}


def _crypto_properties(artefact: Any) -> dict[str, Any]:
    kind = str(field(artefact, "kind", "algorithm") or "algorithm").strip().lower()
    asset_type = _KIND_TO_ASSET_TYPE.get(kind, "algorithm")
    props: dict[str, Any] = {"assetType": asset_type}
    if asset_type == "certificate":
        props["certificateProperties"] = _certificate_properties(artefact)
    elif asset_type == "related-crypto-material":
        props["relatedCryptoMaterialProperties"] = _related_material_properties(artefact)
        props["algorithmProperties"] = _algorithm_properties(artefact)
    elif asset_type == "protocol":
        props["protocolProperties"] = _protocol_properties(artefact)
    else:
        props["algorithmProperties"] = _algorithm_properties(artefact)
    oid = _oid_for(artefact)
    if oid:
        props["oid"] = oid
    return props


# --------------------------------------------------------------------------- #
# ECDAT risk view
# --------------------------------------------------------------------------- #


def _risk_view(artefact: Any) -> dict[str, Any]:
    view: dict[str, Any] = {
        "quantumRisk": threat_of(artefact),
        "quantumRiskReason": str(field(artefact, "threat_reason", "") or ""),
        "severity": severity_of(artefact),
        "score": round(score_of(artefact), 2),
        "recommendation": str(field(artefact, "recommendation", "") or ""),
        "recommendationRationale": str(field(artefact, "rec_rationale", "") or ""),
        "dataClass": str(field(artefact, "data_class", "") or ""),
        "criticality": str(field(artefact, "criticality", "") or ""),
        "mosca": {
            "xYears": field(artefact, "x_years", None),
            "yYears": field(artefact, "y_years", None),
            "zYear": engine_extra(artefact, "z_year", None),
            "deadlineYear": engine_extra(artefact, "mosca_deadline_year", None),
            "shortfallYears": field(artefact, "mosca_shortfall", None),
            "actNow": bool(field(artefact, "mosca_act_now", False)),
            "statement": engine_extra(artefact, "mosca_statement", ""),
        },
        "tradeOffs": trade_offs_of(artefact),
        "occurrenceCount": len(occurrences_of(artefact)),
        "detectors": sorted(
            {
                str(field(occ, "detector", "") or "")
                for occ in occurrences_of(artefact)
                if field(occ, "detector", "")
            }
        ),
    }
    for target, key in (
        ("policyRule", "policy_rule"),
        ("policyName", "policy_name"),
        ("kbCitation", "kb_citation"),
    ):
        value = engine_extra(artefact, key, "")
        if value not in (None, "", [], {}):
            view[target] = value
    classical = extra_of(artefact).get("classical_findings")
    if classical not in (None, "", [], {}):
        view["classicalFindings"] = classical
    patch = str(field(artefact, "fix_patch", "") or "")
    if patch:
        view["fixPatch"] = patch
    return view


def _properties_from_risk(risk: dict[str, Any]) -> list[dict[str, str]]:
    """Namespaced, schema-valid name/value pairs mirroring the risk view."""
    mosca = risk.get("mosca", {})
    classical = risk.get("classicalFindings")
    if isinstance(classical, (list, tuple)):
        classical = ", ".join(str(item) for item in classical)
    pairs: list[tuple[str, Any]] = [
        ("ecdat:quantum:risk", risk.get("quantumRisk")),
        ("ecdat:quantum:reason", risk.get("quantumRiskReason")),
        ("ecdat:classical:findings", classical),
        ("ecdat:severity", risk.get("severity")),
        ("ecdat:score", risk.get("score")),
        ("ecdat:data-class", risk.get("dataClass")),
        ("ecdat:criticality", risk.get("criticality")),
        ("ecdat:policy:rule", risk.get("policyRule")),
        ("ecdat:policy:name", risk.get("policyName")),
        ("ecdat:kb:citation", risk.get("kbCitation")),
        ("ecdat:mosca:x-years", mosca.get("xYears")),
        ("ecdat:mosca:y-years", mosca.get("yYears")),
        ("ecdat:mosca:z-year", mosca.get("zYear")),
        ("ecdat:mosca:deadline-year", mosca.get("deadlineYear")),
        ("ecdat:mosca:shortfall-years", mosca.get("shortfallYears")),
        ("ecdat:mosca:act-now", str(mosca.get("actNow", False)).lower()),
        ("ecdat:mosca:statement", mosca.get("statement")),
        ("ecdat:recommendation", risk.get("recommendation")),
        ("ecdat:recommendation:rationale", risk.get("recommendationRationale")),
        ("ecdat:occurrences:count", risk.get("occurrenceCount")),
        ("ecdat:detectors", ", ".join(risk.get("detectors", []) or [])),
    ]
    for label, text in (risk.get("tradeOffs") or {}).items():
        pairs.append((f"ecdat:trade-off:{slug(label)}", text))
    if risk.get("fixPatch"):
        pairs.append(("ecdat:fix:patch", risk["fixPatch"]))
    return [
        {"name": name, "value": str(value)}
        for name, value in pairs
        if value not in (None, "", [], {})
    ]


def _evidence(artefact: Any, root: Any, bom_ref: str) -> dict[str, Any]:
    occurrences = []
    for index, occ in enumerate(occurrences_of(artefact)):
        entry: dict[str, Any] = {
            "bom-ref": f"{bom_ref}/occ/{index + 1}",
            "location": relative_path(field(occ, "file", ""), root) or "unknown",
        }
        line = field(occ, "line", None)
        try:
            if line is not None and int(line) > 0:
                entry["line"] = int(line)
        except (TypeError, ValueError):
            pass
        text = str(field(occ, "evidence", "") or "").strip()
        if text:
            entry["symbol"] = text[:200]
            entry["additionalContext"] = text[:600]
        detector = str(field(occ, "detector", "") or "")
        confidence = str(field(occ, "confidence", "") or "")
        note = " ".join(part for part in (
            f"detector={detector}" if detector else "",
            f"confidence={confidence}" if confidence else "",
        ) if part)
        if note:
            entry["additionalContext"] = (
                f"{entry.get('additionalContext', '')} [{note}]".strip()
            )
        occurrences.append(entry)
    return {"occurrences": occurrences}


def _component(artefact: Any, root: Any, index: int, strict: bool) -> dict[str, Any]:
    name = name_of(artefact, "unknown-crypto-asset")
    family = family_of(artefact)
    kind = str(field(artefact, "kind", "algorithm") or "algorithm").strip().lower()
    key = artefact_key(artefact)
    bom_ref = f"crypto/{slug(family)}/{slug(name)}/{stable_id(key, name, index)}"

    component: dict[str, Any] = {
        "bom-ref": bom_ref,
        "type": "library" if kind == "library" else "cryptographic-asset",
        "name": name,
        "description": (
            f"{family} {kind} discovered by ECDAT static analysis"
            + (f": {field(artefact, 'threat_reason', '')}" if field(artefact, "threat_reason", "") else "")
        ),
    }
    version = extra_of(artefact).get("version")
    if version:
        component["version"] = str(version)

    if kind != "library":
        component["cryptoProperties"] = _crypto_properties(artefact)

    risk = _risk_view(artefact)
    component["properties"] = [
        {"name": "ecdat:asset:family", "value": family},
        {"name": "ecdat:asset:kind", "value": kind},
        {"name": "ecdat:asset:key", "value": key},
        *_properties_from_risk(risk),
    ]
    component["evidence"] = _evidence(artefact, root, bom_ref)
    if not strict:
        component["ecdat"] = risk
    return component


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def to_cbom(
    scan_result: Any,
    *,
    strict: bool = False,
    serial_number: str | None = None,
    tool_version: str = TOOL_VERSION,
) -> dict[str, Any]:
    """Serialize a :class:`ScanResult` into a CycloneDX 1.6 CBOM dictionary.

    Args:
        scan_result: a ``ScanResult`` (or its ``to_dict()`` form).
        strict: when ``True`` the non-standard ``component.ecdat`` convenience
            block is omitted, leaving only schema-valid ``properties[]``.
        serial_number: override the deterministic ``urn:uuid:`` serial.
        tool_version: version string reported for the ECDAT tool component.

    Returns:
        A JSON-serialisable ``dict``.  Never raises for malformed artefacts.
    """
    target = str(field(scan_result, "target", "") or "unknown-target")
    artefacts = rank_artefacts(artefacts_of(scan_result))
    started = field(scan_result, "started", None)
    finished = field(scan_result, "finished", None)
    errors = list(field(scan_result, "errors", []) or [])
    counts = severity_counts(artefacts)

    digest = stable_id(target, iso8601(started), len(artefacts))
    serial = serial_number or (
        "urn:uuid:"
        f"{digest[:8]}-{digest[8:12]}-4{digest[12:15]}-a{digest[:3]}-{digest[:12]}"
    )

    bom: dict[str, Any] = {
        "bomFormat": _BOM_FORMAT,
        "specVersion": CBOM_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": iso8601(finished or started),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "tool/ecdat",
                        "author": TOOL_VENDOR,
                        "publisher": TOOL_VENDOR,
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "description": (
                            "Enterprise Cryptographic Discovery & Analysis Tool - "
                            "cryptographic inventory, quantum-risk classification, "
                            "Mosca prioritisation and NIST PQC migration guidance."
                        ),
                        "externalReferences": [
                            {"type": "website", "url": TOOL_URI}
                        ],
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"target/{slug(target, 'scan-target')}",
                "name": posix_path(target),
                "version": "unknown",
                "description": "Scan target inventoried by ECDAT",
            },
            "properties": [
                {"name": "ecdat:scan:target", "value": posix_path(target)},
                {"name": "ecdat:scan:started", "value": iso8601(started)},
                {"name": "ecdat:scan:finished", "value": iso8601(finished)},
                {"name": "ecdat:scan:files-scanned",
                 "value": str(field(scan_result, "files_scanned", 0) or 0)},
                {"name": "ecdat:scan:policy",
                 "value": str(field(scan_result, "policy_name", "default") or "default")},
                {"name": "ecdat:scan:artefacts", "value": str(len(artefacts))},
                {"name": "ecdat:scan:errors", "value": str(len(errors))},
                *[
                    {"name": f"ecdat:scan:severity:{name}", "value": str(counts.get(name, 0))}
                    for name in counts
                ],
                {
                    "name": "ecdat:scan:mosca:act-now",
                    "value": str(sum(1 for a in artefacts if field(a, "mosca_act_now", False))),
                },
            ],
        },
        "components": [
            _component(artefact, target, index, strict)
            for index, artefact in enumerate(artefacts)
        ],
    }
    if errors:
        bom["metadata"]["properties"].extend(
            {"name": "ecdat:scan:error", "value": str(err)[:800]} for err in errors[:50]
        )
    return bom


def to_cbom_json(scan_result: Any, *, indent: int = 2, **kwargs: Any) -> str:
    """Convenience wrapper returning the CBOM as a JSON string."""
    return json.dumps(to_cbom(scan_result, **kwargs), indent=indent, sort_keys=False, default=str)
