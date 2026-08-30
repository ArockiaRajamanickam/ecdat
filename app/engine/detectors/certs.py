"""X.509 certificate and key-material detector for ECDAT.

Finds cryptographic assets that never appear in source code: the certificates,
public keys and private keys that are shipped alongside it.  Handles PEM, DER,
PKCS#7 and OpenSSH encodings.

Design notes
------------
* The ``cryptography`` library is used when importable (full parameter
  extraction).  When it is missing we fall back to a pure-stdlib PEM/DER/OpenSSH
  parser that still recovers the key family and, for RSA/DSA/ECDSA OpenSSH keys,
  the exact key size.
* Nothing here ever raises: every parse is guarded and failures are returned as
  strings in the ``errors`` list so the caller can put them in
  ``ScanResult.errors``.
* Every artefact carries file + line + the matched evidence text.

Public API
----------
    matches(path) -> bool
    scan_file(path, data=None) -> (list[Artefact], list[str])
    detect(path, data=None) -> list[Artefact]
    artefacts_from_certificate(der, file, line, detector) -> list[Artefact]
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import os
import re
from typing import Any, Iterable, Optional

try:  # package-relative first (normal case)
    from ..models import Artefact, Occurrence, Params
except ImportError:  # pragma: no cover - standalone / script execution
    from app.engine.models import Artefact, Occurrence, Params  # type: ignore

# --------------------------------------------------------------------------- #
# optional dependency
# --------------------------------------------------------------------------- #
_CRYPTO_OK = False
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dsa as _dsa,
        ec as _ec,
        ed448 as _ed448,
        ed25519 as _ed25519,
        rsa as _rsa,
        x448 as _x448,
        x25519 as _x25519,
    )

    _CRYPTO_OK = True
except Exception:  # pragma: no cover - degrade gracefully
    x509 = None  # type: ignore
    serialization = None  # type: ignore

try:
    from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
except Exception:  # pragma: no cover
    _pkcs7 = None  # type: ignore

try:
    from cryptography.hazmat.primitives.asymmetric import dh as _dh
except Exception:  # pragma: no cover
    _dh = None  # type: ignore


NAME = "certs"
DETECTOR = "certs"

#: extensions this detector claims
FILE_EXTS: frozenset[str] = frozenset(
    {
        ".pem",
        ".crt",
        ".cer",
        ".der",
        ".key",
        ".pub",
        ".p7b",
        ".p7c",
        ".csr",
        ".cert",
        ".ca-bundle",
        ".crl",
        ".keystore",
    }
)

#: bare filenames (no extension) that are key material by convention
FILE_NAMES: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
        "identity",
        "server.key",
        "client.key",
        "authorized_keys",
        "known_hosts",
        "ssh_host_rsa_key",
        "ssh_host_dsa_key",
        "ssh_host_ecdsa_key",
        "ssh_host_ed25519_key",
    }
)

#: hard cap so a stray 500 MB blob cannot stall a scan
MAX_BYTES = 8 * 1024 * 1024

#: certificates inside this window are called out as "expiring soon"
EXPIRY_WARN_DAYS = 90

_PEM_RE = re.compile(
    rb"-----BEGIN ([A-Za-z0-9 #]+)-----\s*(.*?)-----END \1-----", re.DOTALL
)

_SSH_PUB_RE = re.compile(
    rb"(?:^|\s)((?:sk-)?(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d+|"
    rb"rsa-sha2-(?:256|512))(?:@openssh\.com)?)\s+([A-Za-z0-9+/=]{40,})"
)

_NIST_CURVES = {
    b"nistp256": "secp256r1",
    b"nistp384": "secp384r1",
    b"nistp521": "secp521r1",
}

#: field size in bits for the named curves we can meet on the SSH wire
_CURVE_BITS = {
    "secp256r1": 256,
    "secp384r1": 384,
    "secp521r1": 521,
    "secp256k1": 256,
    "secp224r1": 224,
    "secp192r1": 192,
}

# NIST PQC object identifiers (FIPS 203/204/205).  A cert signed with one of
# these is already quantum-safe and must not be reported as a migration target.
_PQC_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

_PQC_FAMILY = {"ML-DSA": "ML-DSA", "SLH-DSA": "SLH-DSA", "ML-KEM": "ML-KEM"}

# Classical algorithm OIDs, used only by the no-``cryptography`` fallback path:
# grepping the DER for these recovers the key family (not the size) so a scan
# still reports something specific instead of "UNKNOWN".
_CLASSIC_OIDS: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.1": ("RSA", "RSA"),
    "1.2.840.10045.2.1": ("ECDSA", "ECDSA"),
    "1.2.840.10040.4.1": ("DSA", "DSA"),
    "1.3.101.112": ("Ed25519", "Ed25519"),
    "1.3.101.113": ("Ed448", "Ed448"),
    "1.3.101.110": ("X25519", "X25519"),
    "1.3.101.111": ("X448", "X448"),
    "1.2.840.113549.1.3.1": ("DH", "DH"),
}

#: named-curve OIDs, same fallback purpose
_CURVE_OIDS: dict[str, str] = {
    "1.2.840.10045.3.1.7": "secp256r1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.132.0.10": "secp256k1",
    "1.3.132.0.33": "secp224r1",
    "1.2.840.10045.3.1.1": "secp192r1",
}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _clip(text: str, limit: int = 240) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def _iso(value: Optional[_dt.datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.timezone.utc)
    return value.astimezone(_dt.timezone.utc).isoformat()


def _encode_oid(dotted: str) -> bytes:
    """DER-encode an OID value (no tag/length) so it can be grepped for."""
    try:
        parts = [int(p) for p in dotted.split(".")]
        if len(parts) < 2:
            return b""
        out = bytearray([parts[0] * 40 + parts[1]])
        for node in parts[2:]:
            chunk = [node & 0x7F]
            node >>= 7
            while node:
                chunk.append((node & 0x7F) | 0x80)
                node >>= 7
            out.extend(reversed(chunk))
        return bytes(out)
    except Exception:
        return b""


_PQC_OID_BYTES = [(v, _encode_oid(k), k) for k, v in _PQC_OIDS.items()]
_CLASSIC_OID_BYTES = [(v, _encode_oid(k), k) for k, v in _CLASSIC_OIDS.items()]
_CURVE_OID_BYTES = [(v, _encode_oid(k), k) for k, v in _CURVE_OIDS.items()]


def _pqc_in_der(der: bytes) -> Optional[tuple[str, str]]:
    """Best-effort: spot a NIST PQC OID inside a DER blob (name, dotted)."""
    for label, encoded, dotted in _PQC_OID_BYTES:
        if encoded and encoded in der:
            return label, dotted
    return None


def _classic_in_der(der: bytes) -> Optional[dict[str, Any]]:
    """Fallback family detection by OID grep (used when cryptography is absent).

    Recovers the algorithm family and, for EC keys, the named curve.  The key
    size is deliberately left None rather than guessed.
    """
    for (name, family), encoded, _dotted in _CLASSIC_OID_BYTES:
        if not encoded or encoded not in der:
            continue
        info: dict[str, Any] = {
            "name": name, "family": family, "key_size": None, "curve": None
        }
        if family == "ECDSA":
            for curve, cenc, _cd in _CURVE_OID_BYTES:
                if cenc and cenc in der:
                    info["curve"] = curve
                    info["key_size"] = _CURVE_BITS.get(curve)
                    info["name"] = f"ECDSA-{curve}"
                    break
        elif family in ("Ed25519", "X25519"):
            info["key_size"] = 256
            info["curve"] = family.lower()
        elif family in ("Ed448", "X448"):
            info["key_size"] = 448
            info["curve"] = family.lower()
        return info
    return None


def _pqc_family(label: str) -> str:
    for prefix, fam in _PQC_FAMILY.items():
        if label.startswith(prefix):
            return fam
    return "PQC"


def _hash_family(hash_name: str) -> str:
    """Map a hash name onto the family the risk engine keys on.

    Careful: "SHA384" must not be read as SHA-3 -- classify on the normalised
    display form, where SHA-3 always carries its dash ("SHA3-384").
    """
    h = _hash_display(hash_name)
    if h.startswith("SHA3-"):
        return "SHA-3"
    if h in {"SHA-1", "SHA1"}:
        return "SHA-1"
    if h.startswith("SHAKE"):
        return "SHAKE"
    if h in {"MD5", "MD5-SHA1", "MD4", "MD2"}:
        return "MD5" if h.startswith("MD5") else h
    if h.startswith("SHA-"):
        return "SHA-2"
    if h.startswith("BLAKE"):
        return "BLAKE2"
    return h or "UNKNOWN"


def _hash_display(hash_name: str) -> str:
    h = (hash_name or "").upper().replace("_", "-")
    m = re.fullmatch(r"SHA-?3-?(\d{3})", h)
    if m:
        return f"SHA3-{m.group(1)}"
    m = re.fullmatch(r"SHA-?(\d{1,3})", h)
    if m:
        return f"SHA-{m.group(1)}"
    m = re.fullmatch(r"SHAKE-?(\d{3})", h)
    if m:
        return f"SHAKE{m.group(1)}"
    return h


def _mk(
    name: str,
    family: str,
    kind: str,
    file: str,
    line: Optional[int],
    evidence: str,
    *,
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
    mode: Optional[str] = None,
    padding: Optional[str] = None,
    not_after: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
    confidence: str = "high",
    detector: str = DETECTOR,
) -> Artefact:
    return Artefact(
        name=name,
        family=family,
        kind=kind,
        params=Params(
            key_size=key_size,
            curve=curve,
            mode=mode,
            padding=padding,
            not_after=not_after,
            extra=dict(extra or {}),
        ),
        occurrences=[
            Occurrence(
                file=file,
                line=line,
                evidence=_clip(evidence),
                detector=detector,
                confidence=confidence,
            )
        ],
    )


# --------------------------------------------------------------------------- #
# public-key introspection (cryptography backend)
# --------------------------------------------------------------------------- #
def _public_key_info(pub: Any) -> dict[str, Any]:
    """-> {name, family, key_size, curve}. Never raises."""
    info: dict[str, Any] = {
        "name": "UNKNOWN-KEY",
        "family": "UNKNOWN",
        "key_size": None,
        "curve": None,
    }
    if not _CRYPTO_OK or pub is None:
        return info
    try:
        if isinstance(pub, _rsa.RSAPublicKey):
            info.update(
                name=f"RSA-{pub.key_size}", family="RSA", key_size=int(pub.key_size)
            )
        elif isinstance(pub, _dsa.DSAPublicKey):
            info.update(
                name=f"DSA-{pub.key_size}", family="DSA", key_size=int(pub.key_size)
            )
        elif isinstance(pub, _ec.EllipticCurvePublicKey):
            curve = getattr(pub.curve, "name", "unknown-curve")
            info.update(
                name=f"ECDSA-{curve}",
                family="ECDSA",
                key_size=int(getattr(pub.curve, "key_size", 0)) or None,
                curve=curve,
            )
        elif isinstance(pub, _ed25519.Ed25519PublicKey):
            info.update(name="Ed25519", family="Ed25519", key_size=256, curve="ed25519")
        elif isinstance(pub, _ed448.Ed448PublicKey):
            info.update(name="Ed448", family="Ed448", key_size=448, curve="ed448")
        elif isinstance(pub, _x25519.X25519PublicKey):
            info.update(name="X25519", family="X25519", key_size=256, curve="x25519")
        elif isinstance(pub, _x448.X448PublicKey):
            info.update(name="X448", family="X448", key_size=448, curve="x448")
        else:
            info["name"] = type(pub).__name__
    except Exception:
        pass
    return info


def _private_key_info(priv: Any) -> dict[str, Any]:
    try:
        return _public_key_info(priv.public_key())
    except Exception:
        return {"name": "UNKNOWN-KEY", "family": "UNKNOWN", "key_size": None, "curve": None}


def _subject_cn(subject: Any) -> Optional[str]:
    try:
        vals = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if vals:
            return str(vals[0].value)
    except Exception:
        pass
    try:
        return subject.rfc4514_string()
    except Exception:
        return None


def _san_names(cert: Any) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(v) for v in ext.value.get_values_for_type(x509.DNSName)][:12]
    except Exception:
        return []


def _is_ca(cert: Any) -> Optional[bool]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bool(ext.value.ca)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# certificate -> artefacts
# --------------------------------------------------------------------------- #
def artefacts_from_certificate(
    der: bytes,
    file: str,
    line: Optional[int],
    detector: str = DETECTOR,
    *,
    source_note: str = "X.509 certificate",
) -> tuple[list[Artefact], list[str]]:
    """Turn one DER-encoded certificate into artefacts. Never raises."""
    out: list[Artefact] = []
    errs: list[str] = []
    if not der:
        return out, errs

    if not _CRYPTO_OK:
        out.append(
            _mk(
                "X.509-certificate",
                "X.509",
                "certificate",
                file,
                line,
                f"{source_note} present ({len(der)} bytes); "
                "install 'cryptography' for full parameter extraction",
                extra={"parsed": False},
                confidence="low",
                detector=detector,
            )
        )
        return out, errs

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        pqc = _pqc_in_der(der)
        if pqc:
            label, dotted = pqc
            out.append(
                _mk(
                    label,
                    _pqc_family(label),
                    "certificate",
                    file,
                    line,
                    f"{source_note} using PQC algorithm {label} (OID {dotted}); "
                    "not parseable by the installed cryptography build",
                    extra={"oid": dotted, "pqc": True, "threat_hint": "pqc"},
                    confidence="medium",
                    detector=detector,
                )
            )
            return out, errs
        errs.append(f"{file}:{line}: certificate parse failed: {type(exc).__name__}: {exc}")
        return out, errs

    # --- validity ---------------------------------------------------------- #
    try:
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    except Exception:
        not_after = None
    try:
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    except Exception:
        not_before = None
    not_after_iso = _iso(not_after)

    flags: list[str] = []
    days_left: Optional[int] = None
    if not_after is not None:
        na = not_after if not_after.tzinfo else not_after.replace(tzinfo=_dt.timezone.utc)
        days_left = (na - _now()).days
        if days_left < 0:
            flags.append(f"EXPIRED {abs(days_left)}d ago")
        elif days_left <= EXPIRY_WARN_DAYS:
            flags.append(f"EXPIRES IN {days_left}d")
    validity_days: Optional[int] = None
    if not_before is not None and not_after is not None:
        try:
            nb = not_before if not_before.tzinfo else not_before.replace(tzinfo=_dt.timezone.utc)
            na = not_after if not_after.tzinfo else not_after.replace(tzinfo=_dt.timezone.utc)
            validity_days = (na - nb).days
            if validity_days > 398:
                flags.append(f"long-lived ({validity_days}d validity)")
        except Exception:
            pass

    cn = _subject_cn(cert.subject)
    issuer_cn = _subject_cn(cert.issuer)
    self_signed = bool(cn is not None and cn == issuer_cn)
    if self_signed:
        flags.append("self-signed")

    # --- signature algorithm ----------------------------------------------- #
    sig_oid = ""
    sig_alg = "unknown"
    try:
        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_alg = cert.signature_algorithm_oid._name or sig_oid
    except Exception:
        pass
    sig_hash = None
    try:
        algo = cert.signature_hash_algorithm
        if algo is not None:
            sig_hash = algo.name.upper()
    except Exception:
        sig_hash = None

    try:
        serial = format(cert.serial_number, "x")
    except Exception:
        serial = None

    common_extra: dict[str, Any] = {
        "subject_cn": cn,
        "issuer_cn": issuer_cn,
        "self_signed": self_signed,
        "serial": serial,
        "signature_algorithm": sig_alg,
        "signature_oid": sig_oid,
        "signature_hash": _hash_display(sig_hash) if sig_hash else None,
        "expired": (days_left is not None and days_left < 0),
        "days_to_expiry": days_left,
        "validity_days": validity_days,
        "is_ca": _is_ca(cert),
        "san": _san_names(cert),
        "source": source_note,
    }

    # --- PQC signature? ----------------------------------------------------- #
    pqc_label = _PQC_OIDS.get(sig_oid)

    # --- public key --------------------------------------------------------- #
    try:
        pub = cert.public_key()
        info = _public_key_info(pub)
    except Exception:
        info = {"name": "UNKNOWN-KEY", "family": "UNKNOWN", "key_size": None, "curve": None}
        found = _pqc_in_der(der)
        if found:
            info = {"name": found[0], "family": _pqc_family(found[0]), "key_size": None, "curve": None}
            common_extra["pqc"] = True
            common_extra["threat_hint"] = "pqc"

    ev = (
        f"{source_note} CN={cn or '?'} key={info['name']} sig={sig_alg} "
        f"notAfter={not_after_iso or '?'}"
    )
    if flags:
        ev += " [" + "; ".join(flags) + "]"

    out.append(
        _mk(
            info["name"],
            info["family"],
            "certificate",
            file,
            line,
            ev,
            key_size=info["key_size"],
            curve=info["curve"],
            not_after=not_after_iso,
            extra=common_extra,
            detector=detector,
        )
    )

    # --- signature algorithm artefact --------------------------------------- #
    if pqc_label:
        out.append(
            _mk(
                pqc_label,
                _pqc_family(pqc_label),
                "certificate",
                file,
                line,
                f"{source_note} CN={cn or '?'} signed with NIST PQC algorithm "
                f"{pqc_label} (OID {sig_oid})",
                not_after=not_after_iso,
                extra={
                    "role": "signature",
                    "subject_cn": cn,
                    "pqc": True,
                    "threat_hint": "pqc",
                    "oid": sig_oid,
                },
                detector=detector,
            )
        )
    elif sig_hash:
        out.append(
            _mk(
                _hash_display(sig_hash),
                _hash_family(sig_hash),
                "certificate",
                file,
                line,
                f"{source_note} CN={cn or '?'} signed with {sig_alg} "
                f"(hash {_hash_display(sig_hash)})",
                not_after=not_after_iso,
                extra={
                    "role": "signature_hash",
                    "subject_cn": cn,
                    "signature_algorithm": sig_alg,
                    "is_ca": common_extra["is_ca"],
                },
                detector=detector,
            )
        )
    return out, errs


# --------------------------------------------------------------------------- #
# OpenSSH parsing (works with or without `cryptography`)
# --------------------------------------------------------------------------- #
def _ssh_fields(blob: bytes, limit: int = 16) -> list[bytes]:
    """Split an SSH wire-format blob into its length-prefixed fields."""
    fields: list[bytes] = []
    i = 0
    n = len(blob)
    while i + 4 <= n and len(fields) < limit:
        size = int.from_bytes(blob[i : i + 4], "big")
        i += 4
        if size < 0 or size > n - i or size > 65536:
            break
        fields.append(blob[i : i + size])
        i += size
    return fields


def _ssh_pub_info(blob: bytes) -> dict[str, Any]:
    """Derive family/size/curve from a decoded SSH public-key blob."""
    info: dict[str, Any] = {
        "name": "UNKNOWN-KEY",
        "family": "UNKNOWN",
        "key_size": None,
        "curve": None,
        "type": None,
    }
    fields = _ssh_fields(blob, limit=6)
    if not fields:
        return info
    ktype = fields[0].decode("ascii", "replace")
    info["type"] = ktype
    base = ktype.replace("sk-", "").replace("@openssh.com", "")
    try:
        if base in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512") and len(fields) >= 3:
            bits = int.from_bytes(fields[2], "big").bit_length()
            info.update(name=f"RSA-{bits}", family="RSA", key_size=bits)
        elif base == "ssh-dss" and len(fields) >= 2:
            bits = int.from_bytes(fields[1], "big").bit_length()
            info.update(name=f"DSA-{bits}", family="DSA", key_size=bits)
        elif base.startswith("ecdsa-sha2-") and len(fields) >= 2:
            curve = _NIST_CURVES.get(fields[1], fields[1].decode("ascii", "replace"))
            size = _CURVE_BITS.get(curve)
            info.update(
                name=f"ECDSA-{curve}", family="ECDSA", curve=curve, key_size=size
            )
        elif base == "ssh-ed25519":
            info.update(name="Ed25519", family="Ed25519", key_size=256, curve="ed25519")
        elif base == "ssh-ed448":
            info.update(name="Ed448", family="Ed448", key_size=448, curve="ed448")
        else:
            info.update(name=ktype, family=ktype)
    except Exception:
        pass
    return info


def _scan_ssh_public_keys(data: bytes, file: str) -> list[Artefact]:
    out: list[Artefact] = []
    for m in _SSH_PUB_RE.finditer(data):
        ktype_raw, b64 = m.group(1), m.group(2)
        line = _line_of(data, m.start(1))
        try:
            blob = base64.b64decode(b64, validate=False)
        except (binascii.Error, ValueError):
            continue
        info = _ssh_pub_info(blob)
        if info["family"] == "UNKNOWN":
            info["name"] = ktype_raw.decode("ascii", "replace")
            info["family"] = info["name"]
        hardware = ktype_raw.startswith(b"sk-")
        ev = f"OpenSSH public key {ktype_raw.decode('ascii', 'replace')} -> {info['name']}"
        if hardware:
            ev += " (FIDO/hardware-backed)"
        out.append(
            _mk(
                info["name"],
                info["family"],
                "key",
                file,
                line,
                ev,
                key_size=info["key_size"],
                curve=info["curve"],
                extra={
                    "key_role": "public",
                    "format": "openssh",
                    "ssh_type": info["type"],
                    "hardware_backed": hardware,
                },
            )
        )
    return out


def _openssh_private(body: bytes, file: str, line: int) -> tuple[list[Artefact], list[str]]:
    """Parse an ``-----BEGIN OPENSSH PRIVATE KEY-----`` body."""
    errs: list[str] = []
    try:
        raw = base64.b64decode(re.sub(rb"\s", b"", body), validate=False)
    except Exception as exc:
        return [], [f"{file}:{line}: OpenSSH key base64 decode failed: {exc}"]

    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        return [], [f"{file}:{line}: OpenSSH private key has unexpected magic header"]

    rest = raw[len(magic) :]
    fields = _ssh_fields(rest, limit=4)
    cipher = fields[0].decode("ascii", "replace") if fields else "?"
    kdf = fields[1].decode("ascii", "replace") if len(fields) > 1 else "?"
    encrypted = cipher not in ("none", "")

    # skip ciphername, kdfname, kdfoptions, then uint32 nkeys, then pubkey blob
    idx = 0
    for _ in range(3):
        if idx + 4 > len(rest):
            break
        size = int.from_bytes(rest[idx : idx + 4], "big")
        idx += 4 + size
    idx += 4  # nkeys
    info: dict[str, Any] = {"name": "UNKNOWN-KEY", "family": "UNKNOWN", "key_size": None, "curve": None}
    if idx + 4 <= len(rest):
        size = int.from_bytes(rest[idx : idx + 4], "big")
        if 0 < size <= len(rest) - idx - 4:
            info = _ssh_pub_info(rest[idx + 4 : idx + 4 + size])

    ev = (
        f"-----BEGIN OPENSSH PRIVATE KEY----- {info['name']} "
        f"cipher={cipher} kdf={kdf}"
    )
    if not encrypted:
        ev += " [UNENCRYPTED PRIVATE KEY ON DISK]"
    return (
        [
            _mk(
                info["name"],
                info["family"],
                "key",
                file,
                line,
                ev,
                key_size=info["key_size"],
                curve=info["curve"],
                extra={
                    "key_role": "private",
                    "format": "openssh",
                    "encrypted": encrypted,
                    "cipher": cipher,
                    "kdf": kdf,
                    "ssh_type": info.get("type"),
                },
            )
        ],
        errs,
    )


# --------------------------------------------------------------------------- #
# PEM block handling
# --------------------------------------------------------------------------- #
_PEM_KEY_FAMILY_HINT = {
    "RSA PRIVATE KEY": ("RSA", "PKCS#1"),
    "RSA PUBLIC KEY": ("RSA", "PKCS#1"),
    "DSA PRIVATE KEY": ("DSA", "PKCS#1"),
    "EC PRIVATE KEY": ("ECDSA", "SEC1"),
    "PRIVATE KEY": (None, "PKCS#8"),
    "ENCRYPTED PRIVATE KEY": (None, "PKCS#8-encrypted"),
    "PUBLIC KEY": (None, "SubjectPublicKeyInfo"),
}


def _pem_body_der(body: bytes) -> Optional[bytes]:
    try:
        return base64.b64decode(re.sub(rb"[^A-Za-z0-9+/=]", b"", body), validate=False)
    except Exception:
        return None


def _handle_pem_block(
    label: str, block: bytes, body: bytes, file: str, line: int
) -> tuple[list[Artefact], list[str]]:
    out: list[Artefact] = []
    errs: list[str] = []
    der = _pem_body_der(body)

    if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
        if der:
            a, e = artefacts_from_certificate(der, file, line, source_note="X.509 certificate (PEM)")
            out += a
            errs += e
        else:
            errs.append(f"{file}:{line}: malformed PEM block '{label}': body is not valid base64")
        return out, errs

    if label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
        if der and _CRYPTO_OK:
            try:
                csr = x509.load_der_x509_csr(der)
                info = _public_key_info(csr.public_key())
                cn = _subject_cn(csr.subject)
                out.append(
                    _mk(
                        info["name"],
                        info["family"],
                        "certificate",
                        file,
                        line,
                        f"PKCS#10 certificate signing request CN={cn or '?'} key={info['name']}",
                        key_size=info["key_size"],
                        curve=info["curve"],
                        extra={"role": "csr", "subject_cn": cn},
                    )
                )
            except Exception as exc:
                errs.append(f"{file}:{line}: CSR parse failed: {exc}")
        return out, errs

    if label in ("PKCS7", "PKCS #7 SIGNED DATA"):
        if _pkcs7 is not None:
            try:
                certs = _pkcs7.load_pem_pkcs7_certificates(block)
                for cert in certs:
                    a, e = artefacts_from_certificate(
                        cert.public_bytes(serialization.Encoding.DER),
                        file,
                        line,
                        source_note="X.509 certificate (PKCS#7 bundle)",
                    )
                    out += a
                    errs += e
            except Exception as exc:
                errs.append(f"{file}:{line}: PKCS#7 parse failed: {exc}")
        return out, errs

    if label == "OPENSSH PRIVATE KEY":
        return _openssh_private(body, file, line)

    if label in ("DH PARAMETERS", "X9.42 DH PARAMETERS"):
        bits = None
        if _CRYPTO_OK and _dh is not None:
            try:
                params = serialization.load_pem_parameters(block)
                bits = int(params.parameter_numbers().p.bit_length())
            except Exception:
                bits = None
        out.append(
            _mk(
                f"DH-{bits}" if bits else "DH",
                "DH",
                "key",
                file,
                line,
                f"-----BEGIN {label}----- finite-field Diffie-Hellman parameters"
                + (f" p={bits} bits" if bits else ""),
                key_size=bits,
                extra={"key_role": "parameters"},
            )
        )
        return out, errs

    if label in _PEM_KEY_FAMILY_HINT or "KEY" in label:
        return _handle_pem_key(label, block, der, file, line)

    return out, errs


def _handle_pem_key(
    label: str, block: bytes, der: Optional[bytes], file: str, line: int
) -> tuple[list[Artefact], list[str]]:
    out: list[Artefact] = []
    errs: list[str] = []
    is_private = "PRIVATE" in label
    hint_family, encoding = _PEM_KEY_FAMILY_HINT.get(label, (None, "PEM"))
    encrypted = label == "ENCRYPTED PRIVATE KEY" or b"Proc-Type: 4,ENCRYPTED" in block
    info: dict[str, Any] = {
        "name": hint_family
        or ("ENCRYPTED-PRIVATE-KEY" if encrypted else "UNKNOWN-KEY"),
        "family": hint_family or "UNKNOWN",
        "key_size": None,
        "curve": None,
    }
    parsed = False

    if _CRYPTO_OK and not encrypted:
        try:
            if is_private:
                key = serialization.load_pem_private_key(block, password=None)
                info = _private_key_info(key)
            else:
                key = serialization.load_pem_public_key(block)
                info = _public_key_info(key)
            parsed = True
        except TypeError:
            encrypted = True  # password required
        except Exception as exc:
            found = _pqc_in_der(der) if der else None
            if found:
                info = {
                    "name": found[0],
                    "family": _pqc_family(found[0]),
                    "key_size": None,
                    "curve": None,
                }
                parsed = True
            else:
                errs.append(f"{file}:{line}: {label} parse failed: {type(exc).__name__}: {exc}")

    if not parsed and info["family"] == "UNKNOWN" and der:
        found = _pqc_in_der(der)
        if found:
            info = {
                "name": found[0],
                "family": _pqc_family(found[0]),
                "key_size": None,
                "curve": None,
            }
        else:
            classic = _classic_in_der(der)
            if classic:
                info = classic

    ev = f"-----BEGIN {label}----- {info['name']} ({encoding})"
    extra: dict[str, Any] = {
        "key_role": "private" if is_private else "public",
        "format": encoding,
        "encrypted": bool(encrypted),
        "parsed": parsed,
    }
    if info["family"] in ("ML-KEM", "ML-DSA", "SLH-DSA", "PQC"):
        extra["pqc"] = True
        extra["threat_hint"] = "pqc"
    if is_private and not encrypted:
        ev += " [UNENCRYPTED PRIVATE KEY ON DISK]"
    elif is_private and encrypted:
        ev += " [passphrase-protected]"

    out.append(
        _mk(
            info["name"],
            info["family"],
            "key",
            file,
            line,
            ev,
            key_size=info["key_size"],
            curve=info["curve"],
            extra=extra,
            confidence="high" if parsed else "medium",
        )
    )
    return out, errs


# --------------------------------------------------------------------------- #
# DER / binary handling
# --------------------------------------------------------------------------- #
def _handle_binary(data: bytes, file: str) -> tuple[list[Artefact], list[str]]:
    out: list[Artefact] = []
    errs: list[str] = []
    if not data.startswith(b"\x30"):  # not an ASN.1 SEQUENCE -> not DER
        return out, errs

    if _CRYPTO_OK:
        try:
            x509.load_der_x509_certificate(data)
            return artefacts_from_certificate(
                data, file, 1, source_note="X.509 certificate (DER)"
            )
        except Exception:
            pass
        if _pkcs7 is not None:
            try:
                certs = _pkcs7.load_der_pkcs7_certificates(data)
                if certs:
                    for cert in certs:
                        a, e = artefacts_from_certificate(
                            cert.public_bytes(serialization.Encoding.DER),
                            file,
                            1,
                            source_note="X.509 certificate (PKCS#7 DER bundle)",
                        )
                        out += a
                        errs += e
                    return out, errs
            except Exception:
                pass
        for loader, role in (
            (lambda d: serialization.load_der_public_key(d), "public"),
            (lambda d: serialization.load_der_private_key(d, password=None), "private"),
        ):
            try:
                key = loader(data)
            except Exception:
                continue
            info = _public_key_info(key if role == "public" else key.public_key())
            ev = f"DER-encoded {role} key {info['name']}"
            if role == "private":
                ev += " [UNENCRYPTED PRIVATE KEY ON DISK]"
            out.append(
                _mk(
                    info["name"],
                    info["family"],
                    "key",
                    file,
                    1,
                    ev,
                    key_size=info["key_size"],
                    curve=info["curve"],
                    extra={"key_role": role, "format": "DER", "encrypted": False},
                )
            )
            return out, errs

    found = _pqc_in_der(data)
    if found:
        out.append(
            _mk(
                found[0],
                _pqc_family(found[0]),
                "certificate",
                file,
                1,
                f"DER blob containing NIST PQC OID {found[1]} ({found[0]})",
                extra={"pqc": True, "threat_hint": "pqc", "oid": found[1]},
                confidence="medium",
            )
        )
        return out, errs

    # No parser backend available: recover what we can from the OIDs so a DER
    # certificate is still reported rather than silently dropped.
    if data[:2] == b"\x30\x82":
        classic = _classic_in_der(data)
        if classic:
            out.append(
                _mk(
                    classic["name"],
                    classic["family"],
                    "certificate",
                    file,
                    1,
                    f"DER blob (ASN.1 SEQUENCE, {len(data)} bytes) carrying a "
                    f"{classic['name']} public key; install 'cryptography' for "
                    "key size, subject and validity dates",
                    key_size=classic["key_size"],
                    curve=classic["curve"],
                    extra={"parsed": False, "format": "DER"},
                    confidence="medium",
                )
            )
    return out, errs


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
def matches(path: str) -> bool:
    """True when this detector should be offered the file."""
    base = os.path.basename(path)
    low = base.lower()
    if low in FILE_NAMES:
        return True
    ext = os.path.splitext(low)[1]
    if ext in FILE_EXTS:
        return True
    # id_rsa.pub / id_ed25519-cert.pub / ssh_host_*_key etc.
    if low.startswith("id_") or low.startswith("ssh_host_"):
        return True
    return False


def scan_file(
    path: str, data: Optional[bytes | str] = None
) -> tuple[list[Artefact], list[str]]:
    """Scan one certificate/key file.

    Returns ``(artefacts, errors)``.  Never raises, whatever the file holds.
    """
    artefacts: list[Artefact] = []
    errors: list[str] = []

    if data is None:
        try:
            size = os.path.getsize(path)
            if size > MAX_BYTES:
                return [], [f"{path}: skipped, {size} bytes exceeds MAX_BYTES({MAX_BYTES})"]
            with open(path, "rb") as fh:
                raw = fh.read(MAX_BYTES)
        except OSError as exc:
            return [], [f"{path}: unreadable: {exc}"]
    elif isinstance(data, str):
        raw = data.encode("utf-8", "replace")
    else:
        raw = bytes(data)[:MAX_BYTES]

    if not raw:
        return [], []

    try:
        seen_pem = False
        for m in _PEM_RE.finditer(raw):
            seen_pem = True
            label = m.group(1).decode("ascii", "replace").strip()
            line = _line_of(raw, m.start())
            try:
                a, e = _handle_pem_block(label, m.group(0), m.group(2), path, line)
                artefacts += a
                errors += e
            except Exception as exc:  # belt and braces
                errors.append(f"{path}:{line}: PEM block '{label}' failed: {exc}")

        try:
            artefacts += _scan_ssh_public_keys(raw, path)
        except Exception as exc:
            errors.append(f"{path}: OpenSSH public key scan failed: {exc}")

        if not seen_pem:
            a, e = _handle_binary(raw, path)
            artefacts += a
            errors += e
    except Exception as exc:  # absolute last resort
        errors.append(f"{path}: certs detector aborted: {type(exc).__name__}: {exc}")

    return artefacts, errors


def detect(path: str, data: Optional[bytes | str] = None) -> list[Artefact]:
    """Convenience wrapper returning artefacts only."""
    return scan_file(path, data)[0]


def scan_files(paths: Iterable[str]) -> tuple[list[Artefact], list[str]]:
    artefacts: list[Artefact] = []
    errors: list[str] = []
    for p in paths:
        if not matches(p):
            continue
        a, e = scan_file(p)
        artefacts += a
        errors += e
    return artefacts, errors


__all__ = [
    "NAME",
    "FILE_EXTS",
    "FILE_NAMES",
    "matches",
    "scan_file",
    "scan_files",
    "detect",
    "artefacts_from_certificate",
]
