"""Java cryptographic-asset detector (JCA/JCE aware).

Uses tree-sitter (grammar ``tree_sitter_java``) when it is installed and the
masked tokenizer from :mod:`._srcutil` otherwise -- in practice both, unioned,
so a grammar mismatch can only ever *add* coverage.

The JCA is a two-step API: the algorithm comes from ``getInstance("...")`` and
the parameters arrive later through ``initialize()``/``init()``.  This detector
therefore resolves per file:

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp384r1"));      -> ECDSA-secp384r1

    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128);                                             -> AES-128

Also covers ``Cipher.getInstance("AES/GCM/NoPadding")`` (family + mode +
padding), ``MessageDigest``, ``Mac``, ``Signature``, ``SecretKeyFactory``,
``KeyAgreement``, ``SecureRandom``, ``KeyStore``, ``CertificateFactory``,
``SSLContext.getInstance("TLSv1")``, ``setEnabledProtocols`` /
``setEnabledCipherSuites``, BouncyCastle (incl. its PQC packages) and any
ML-KEM/ML-DSA/Kyber/Dilithium algorithm string.

``detect(root_path, policy) -> (artefacts, files_scanned, errors)``
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._srcutil import (
    CallSite,
    Collector,
    Masked,
    PolicyView,
    all_strings,
    collapse_ws,
    hash_info,
    iter_calls,
    iter_source_files,
    lit_int,
    lit_str,
    load_ts_parser,
    mask_source,
    node_text,
    normalize_curve,
    parse_java_transformation,
    pqc_info,
    snippet,
    tls_version,
    walk_nodes,
)

__all__ = ["detect", "FILE_EXTS", "DETECTOR"]

DETECTOR = "source_java"
FILE_EXTS = (".java",)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# ``getInstance`` factories we understand, mapped to a handler tag.
_FACTORIES = {
    "KeyPairGenerator": "keypair",
    "KeyPairGeneratorSpi": "keypair",
    "KeyGenerator": "keygen",
    "Cipher": "cipher",
    "MessageDigest": "digest",
    "Mac": "mac",
    "Signature": "signature",
    "SSLContext": "ssl",
    "SecretKeyFactory": "secretkeyfactory",
    "KeyAgreement": "keyagreement",
    "KeyFactory": "keyfactory",
    "CertificateFactory": "certfactory",
    "SecureRandom": "random",
    "KeyStore": "keystore",
    "AlgorithmParameterGenerator": "algparams",
    "AlgorithmParameters": "algparams",
    "TrustManagerFactory": "trustmanager",
    "KeyManagerFactory": "keymanager",
}

_KPG_FAMILIES = {
    "RSA": ("RSA", None),
    "RSASSA-PSS": ("RSA", "PSS"),
    "EC": ("ECDSA", None),
    "ECDSA": ("ECDSA", None),
    "ECDH": ("ECDH", None),
    "ECIES": ("ECIES", None),
    "DSA": ("DSA", None),
    "DH": ("DH", None),
    "DIFFIEHELLMAN": ("DH", None),
    "ED25519": ("Ed25519", None),
    "ED448": ("Ed448", None),
    "EDDSA": ("Ed25519", None),
    "X25519": ("X25519", None),
    "X448": ("X448", None),
    "XDH": ("XDH", None),
    "ELGAMAL": ("ElGamal", None),
}

_KEYGEN_FAMILIES = {
    "AES": "AES",
    "DESEDE": "3DES",
    "TRIPLEDES": "3DES",
    "DES": "DES",
    "BLOWFISH": "Blowfish",
    "ARCFOUR": "RC4",
    "RC4": "RC4",
    "RC2": "RC2",
    "CHACHA20": "ChaCha20",
    "CHACHA20-POLY1305": "ChaCha20-Poly1305",
    "CAMELLIA": "Camellia",
    "SEED": "SEED",
    "SM4": "SM4",
}

_JAVA_LIBS = (
    ("org.bouncycastle.pqc", "PQC", "BouncyCastle PQC provider"),
    ("org.bouncycastle", "Library", "BouncyCastle"),
    ("com.nimbusds.jose", "Library", "Nimbus JOSE+JWT"),
    ("io.jsonwebtoken", "Library", "jjwt"),
    ("com.auth0.jwt", "Library", "java-jwt"),
    ("com.google.crypto.tink", "Library", "Google Tink"),
    ("org.apache.commons.codec.digest", "Library", "commons-codec (digest)"),
    ("org.jasypt", "Library", "Jasypt"),
    ("org.openquantumsafe", "PQC", "liboqs-java"),
    ("com.sun.crypto.provider", "Library", "SunJCE"),
)

_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z0-9_.$*]+)\s*;", re.M)
_SIG_RE = re.compile(
    r"^(?P<hash>[A-Za-z0-9\-]+?)with(?P<alg>[A-Za-z0-9]+)(?:and(?P<mgf>[A-Za-z0-9]+))?$",
    re.I,
)


@dataclass
class _Generator:
    """A ``KeyPairGenerator``/``KeyGenerator`` awaiting its ``init`` call."""

    tag: str
    family: str
    alg: str
    line: int
    evidence: str
    key_size: int | None = None
    curve: str | None = None
    padding: str | None = None
    extra: dict = field(default_factory=dict)
    confidence: str = "high"


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def detect(root_path: str | Path, policy: Any = None) -> tuple[list, int, list[str]]:
    """Scan ``root_path`` for Java cryptographic assets."""
    pv = PolicyView(policy)
    col = Collector(DETECTOR)
    errors: list[str] = []
    files_scanned = 0
    parser = load_ts_parser("tree_sitter_java", "java")

    for _path, rel, src in iter_source_files(root_path, FILE_EXTS, pv, errors):
        files_scanned += 1
        try:
            masked = mask_source(src, "java")
        except Exception as exc:  # pragma: no cover
            errors.append(f"{rel}: tokenizer failed ({type(exc).__name__}: {exc})")
            continue

        calls: list[CallSite] = []
        try:
            calls.extend(iter_calls(masked))
        except Exception as exc:
            errors.append(f"{rel}: call scan failed ({type(exc).__name__}: {exc})")
        if parser is not None:
            try:
                calls.extend(_ast_calls(parser, src, masked))
            except Exception as exc:
                errors.append(f"{rel}: tree-sitter parse failed ({type(exc).__name__}: {exc})")

        try:
            _scan_file(col, _dedupe(calls), masked, rel)
            _scan_imports(col, masked, rel)
        except Exception as exc:
            errors.append(f"{rel}: scan error ({type(exc).__name__}: {exc})")

    return col.artefacts(), files_scanned, errors


def _dedupe(calls: list[CallSite]) -> list[CallSite]:
    seen: set[tuple] = set()
    out: list[CallSite] = []
    for site in calls:
        key = (site.line, site.callee, tuple(collapse_ws(a) for a in site.args))
        if key in seen:
            continue
        seen.add(key)
        out.append(site)
    out.sort(key=lambda s: (s.line, s.callee))
    return out


# --------------------------------------------------------------------------
# tree-sitter call extraction
# --------------------------------------------------------------------------
def _ast_calls(parser: Any, src: str, masked: Masked) -> list[CallSite]:
    src_bytes = src.encode("utf-8", "replace")
    tree = parser.parse(src_bytes)
    calls: list[CallSite] = []
    for node in walk_nodes(tree.root_node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            base = node_text(src_bytes, name_node) if name_node is not None else ""
            receiver_call = None
            if obj_node is None:
                receiver = ""
                callee = base
            elif obj_node.type in ("method_invocation", "object_creation_expression"):
                receiver_call = collapse_ws(node_text(src_bytes, obj_node))
                receiver = "<call>"
                callee = f"<call>.{base}"
            else:
                receiver = collapse_ws(node_text(src_bytes, obj_node))
                callee = f"{receiver}.{base}" if receiver else base
        elif node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            base = collapse_ws(node_text(src_bytes, type_node)) if type_node is not None else ""
            receiver = ""
            receiver_call = None
            callee = f"new {base}"
        else:
            continue

        args_node = node.child_by_field_name("arguments")
        args: list[str] = []
        if args_node is not None:
            for child in args_node.children:
                if child.type in ("(", ")", ","):
                    continue
                args.append(collapse_ws(node_text(src_bytes, child)))

        assigned = None
        parent = node.parent
        for _ in range(3):
            if parent is None:
                break
            if parent.type in ("variable_declarator", "assignment_expression"):
                target = parent.child_by_field_name("name") or parent.child_by_field_name("left")
                if target is not None:
                    ids = _IDENT_RE.findall(node_text(src_bytes, target))
                    assigned = ids[-1] if ids else None
                break
            if parent.type in ("parenthesized_expression", "cast_expression"):
                parent = parent.parent
                continue
            break

        line = node.start_point[0] + 1
        calls.append(
            CallSite(
                callee=callee,
                base=base.rsplit(".", 1)[-1],
                receiver=receiver,
                args=args,
                line=line,
                evidence=snippet(masked.line_text(line)),
                assigned_to=assigned,
                receiver_call=receiver_call,
                raw=collapse_ws(node_text(src_bytes, node)),
            )
        )
    return calls


# --------------------------------------------------------------------------
# per-file analysis
# --------------------------------------------------------------------------
def _scan_file(col: Collector, calls: list[CallSite], masked: Masked, rel: str) -> None:
    generators: dict[str, _Generator] = {}      # variable name -> record
    anonymous: list[_Generator] = []            # chained / unassigned generators
    spec_orphans: list[tuple[str, int, str]] = []
    bound_curves: set[str] = set()

    for site in calls:
        base = site.base
        line, ev = site.line, site.evidence

        # ---- new XxxParameterSpec(...) --------------------------------
        if site.callee.startswith("new "):
            _handle_new(col, site, generators, anonymous, spec_orphans, bound_curves, rel)
            continue

        # ---- Xxx.getInstance("ALG") -----------------------------------
        if base == "getInstance":
            factory = site.receiver.rsplit(".", 1)[-1]
            tag = _FACTORIES.get(factory)
            if tag is None:
                continue
            alg = lit_str(site.arg(0))
            if alg is None:
                if factory in ("Cipher", "MessageDigest", "KeyPairGenerator", "Signature"):
                    col.add(
                        family="Unknown",
                        name=f"UNKNOWN ({factory}.getInstance)",
                        file=rel, line=line, evidence=ev,
                        extra={
                            "api": f"{factory}.getInstance",
                            "reason": "algorithm selected at runtime (non-literal argument)",
                        },
                        confidence="low",
                    )
                continue
            provider = lit_str(site.arg(1)) if len(site.args) > 1 else None
            record = _handle_get_instance(col, tag, factory, alg, provider, rel, line, ev)
            if record is not None:
                if site.assigned_to:
                    generators[site.assigned_to] = record
                else:
                    anonymous.append(record)
            continue

        # ---- generator.initialize(...) / generator.init(...) ----------
        if base in ("initialize", "init", "initSign", "initVerify"):
            record = generators.get(site.receiver)
            if record is None and site.receiver_call and "getInstance" in site.receiver_call:
                candidates = [r for r in anonymous if r.line <= site.line]
                record = candidates[-1] if candidates else None
            if record is not None:
                _apply_init(record, site, bound_curves)
            continue

        # ---- TLS protocol / cipher-suite configuration ----------------
        if base in ("setEnabledProtocols", "setProtocols", "setEnabledCipherSuites",
                    "setCipherSuites", "setSSLParameters"):
            _handle_tls_setter(col, site, rel)
            continue

    for record in list(generators.values()) + anonymous:
        _emit_generator(col, record, rel)

    for curve, line, ev in spec_orphans:
        col.add(
            family="ECDSA",
            curve=curve,
            file=rel, line=line, evidence=ev,
            extra={"api": "ECGenParameterSpec", "note": "curve not bound to a visible generator"},
            confidence="medium",
        )


def _handle_new(
    col: Collector,
    site: CallSite,
    generators: dict[str, _Generator],
    anonymous: list[_Generator],
    spec_orphans: list[tuple[str, int, str]],
    bound_curves: set[str],
    rel: str,
) -> None:
    type_name = site.callee[4:].split("<")[0].rsplit(".", 1)[-1]
    line, ev = site.line, site.evidence

    if type_name == "SecretKeySpec":
        alg = lit_str(site.args[-1]) if site.args else None
        family = _KEYGEN_FAMILIES.get((alg or "").upper())
        if family:
            col.add(
                family=family, file=rel, line=line, evidence=ev,
                extra={"api": "new SecretKeySpec"}, confidence="medium",
            )
        return

    if type_name == "PBEKeySpec":
        col.add(
            family="PBKDF2", name="PBKDF2", file=rel, line=line, evidence=ev,
            extra={
                "api": "new PBEKeySpec",
                "iterations": lit_int(site.arg(2)),
                "key_length": lit_int(site.arg(3)),
            },
            confidence="medium",
        )
        return

    if type_name == "GCMParameterSpec":
        tag_bits = lit_int(site.arg(0))
        col.add(
            family="AES", mode="GCM", file=rel, line=line, evidence=ev,
            extra={"api": "new GCMParameterSpec", "tag_bits": tag_bits},
            confidence="medium",
        )
        return

    if type_name in ("ECGenParameterSpec", "ECParameterSpec", "NamedParameterSpec"):
        value = lit_str(site.arg(0))
        curve = normalize_curve(value) if value else None
        if not curve:
            return
        target = None
        for record in list(generators.values()) + anonymous:
            if record.family in ("ECDSA", "ECDH", "EC", "ECIES", "XDH") and record.curve is None:
                target = record
        if curve in ("X25519", "X448", "Ed25519", "Ed448") and target is None:
            family = "Ed25519" if curve.startswith("Ed") else curve
            col.add(
                family=family, name=family, file=rel, line=line, evidence=ev,
                extra={"api": f"new {type_name}"}, confidence="medium",
            )
            return
        if target is not None:
            target.curve = curve
            target.extra["curve_source"] = f"new {type_name}"
            bound_curves.add(curve)
        elif curve not in bound_curves:
            spec_orphans.append((curve, line, ev))
        return

    if type_name == "RSAKeyGenParameterSpec":
        size = lit_int(site.arg(0))
        target = None
        for record in list(generators.values()) + anonymous:
            if record.family == "RSA" and record.key_size is None:
                target = record
        if target is not None and size:
            target.key_size = size
        elif size:
            col.add(family="RSA", key_size=size, file=rel, line=line, evidence=ev,
                    extra={"api": "new RSAKeyGenParameterSpec"})
        return

    if type_name == "DHParameterSpec":
        col.add(family="DH", file=rel, line=line, evidence=ev,
                extra={"api": "new DHParameterSpec"}, confidence="medium")
        return

    if type_name in ("IvParameterSpec", "PBEParameterSpec", "OAEPParameterSpec"):
        if type_name == "OAEPParameterSpec":
            col.add(family="RSA", padding="OAEP", file=rel, line=line, evidence=ev,
                    extra={"api": "new OAEPParameterSpec"}, confidence="medium")
        return


def _handle_get_instance(
    col: Collector,
    tag: str,
    factory: str,
    alg: str,
    provider: str | None,
    rel: str,
    line: int,
    ev: str,
) -> _Generator | None:
    api = f"{factory}.getInstance"
    extra: dict[str, Any] = {"api": api, "algorithm": alg}
    if provider:
        extra["provider"] = provider

    pqc = pqc_info(alg)
    if pqc and tag in ("keypair", "signature", "keygen", "cipher", "keyagreement", "keyfactory"):
        col.add(
            family=pqc["family"], name=pqc["name"], file=rel, line=line, evidence=ev,
            extra={**extra, "standardised": pqc["standardised"], "matched": pqc["matched"]},
        )
        return None

    upper = alg.upper()

    if tag == "keypair":
        mapped = _KPG_FAMILIES.get(upper) or _KPG_FAMILIES.get(upper.replace("-", ""))
        if mapped is None:
            col.add(family="Unknown", name=f"UNKNOWN ({alg})", file=rel, line=line, evidence=ev,
                    extra=extra, confidence="low")
            return None
        family, padding = mapped
        return _Generator(tag="keypair", family=family, alg=alg, line=line, evidence=ev,
                          padding=padding, extra=extra)

    if tag == "keygen":
        family = _KEYGEN_FAMILIES.get(upper)
        if family:
            return _Generator(tag="keygen", family=family, alg=alg, line=line, evidence=ev,
                              extra=extra)
        info = hash_info(alg[4:]) if upper.startswith("HMAC") else None
        if info:
            col.add(family="HMAC", name=f"HMAC-{info[1]}", file=rel, line=line, evidence=ev,
                    extra={**extra, "hash": info[1]})
            return None
        col.add(family="Unknown", name=f"UNKNOWN ({alg})", file=rel, line=line, evidence=ev,
                extra=extra, confidence="low")
        return None

    if tag == "cipher":
        info = parse_java_transformation(alg)
        if info is None:
            col.add(family="Unknown", name=f"UNKNOWN ({alg})", file=rel, line=line, evidence=ev,
                    extra=extra, confidence="low")
            return None
        col.add(
            family=info["family"],
            key_size=info["key_size"],
            mode=info["mode"],
            padding=info["padding"],
            file=rel, line=line, evidence=ev,
            extra={**extra, **info.get("extra", {}), "transformation": info["raw"]},
        )
        return None

    if tag == "digest":
        info = hash_info(alg)
        if info:
            col.add(family=info[0], name=info[1], file=rel, line=line, evidence=ev, extra=extra)
        else:
            col.add(family="Unknown", name=f"UNKNOWN ({alg})", file=rel, line=line, evidence=ev,
                    extra=extra, confidence="low")
        return None

    if tag == "mac":
        if upper.startswith("HMAC"):
            info = hash_info(alg[4:])
            col.add(
                family="HMAC", name=f"HMAC-{info[1]}" if info else f"HMAC ({alg})",
                file=rel, line=line, evidence=ev, extra={**extra, "hash": info[1] if info else None},
            )
            if info:
                col.add(family=info[0], name=info[1], file=rel, line=line, evidence=ev,
                        extra=extra, confidence="medium")
        elif "CMAC" in upper or "GMAC" in upper or "POLY1305" in upper:
            col.add(family="MAC", name=alg, file=rel, line=line, evidence=ev, extra=extra)
        else:
            col.add(family="MAC", name=alg, file=rel, line=line, evidence=ev, extra=extra,
                    confidence="medium")
        return None

    if tag == "signature":
        _emit_signature(col, alg, rel, line, ev, extra)
        return None

    if tag == "ssl":
        version = tls_version(alg)
        name = version or "TLS"
        col.add(
            family="TLS",
            name=name if name[:3] in ("TLS", "SSL") else f"TLS-{name}",
            kind="protocol",
            mode=version or alg,
            file=rel, line=line, evidence=ev,
            extra={**extra, "version": version},
        )
        return None

    if tag == "secretkeyfactory":
        if upper.startswith("PBKDF2"):
            prf = hash_info(alg.split("With", 1)[-1]) if "With" in alg else None
            col.add(family="PBKDF2", name="PBKDF2", file=rel, line=line, evidence=ev,
                    extra={**extra, "prf": prf[1] if prf else None})
            if prf:
                col.add(family=prf[0], name=prf[1], file=rel, line=line, evidence=ev,
                        extra=extra, confidence="medium")
            return None
        if upper.startswith("PBE"):
            info = parse_java_transformation(alg)
            col.add(
                family=info["family"] if info else "PBE",
                name=alg if not info else None,
                file=rel, line=line, evidence=ev, extra=extra,
            )
            return None
        family = _KEYGEN_FAMILIES.get(upper)
        if family:
            col.add(family=family, file=rel, line=line, evidence=ev, extra=extra,
                    confidence="medium")
        return None

    if tag == "keyagreement":
        mapped = _KPG_FAMILIES.get(upper)
        family = mapped[0] if mapped else ("ECDH" if "EC" in upper else "DH")
        col.add(family=family, file=rel, line=line, evidence=ev, extra=extra)
        return None

    if tag == "keyfactory":
        mapped = _KPG_FAMILIES.get(upper)
        if mapped:
            col.add(family=mapped[0], file=rel, line=line, evidence=ev, extra=extra,
                    confidence="medium")
        return None

    if tag == "certfactory":
        col.add(family="X.509", name=f"{alg} certificate handling", kind="library",
                file=rel, line=line, evidence=ev, extra=extra, confidence="medium")
        return None

    if tag == "random":
        col.add(family="SecureRandom", name=alg, kind="algorithm", file=rel, line=line,
                evidence=ev, extra=extra, confidence="medium")
        return None

    if tag == "keystore":
        col.add(family="KeyStore", name=f"KeyStore-{alg}", kind="library", file=rel, line=line,
                evidence=ev, extra=extra, confidence="medium")
        return None

    if tag == "algparams":
        mapped = _KPG_FAMILIES.get(upper)
        if mapped:
            col.add(family=mapped[0], file=rel, line=line, evidence=ev, extra=extra,
                    confidence="medium")
        return None

    return None


def _emit_signature(col: Collector, alg: str, rel: str, line: int, ev: str, extra: dict) -> None:
    upper = alg.upper()
    match = _SIG_RE.match(alg.strip())
    if match:
        hash_token = match.group("hash")
        alg_token = match.group("alg").upper()
        info = hash_info(hash_token) if hash_token.upper() != "NONE" else None
        family_map = {
            "RSA": "RSA", "DSA": "DSA", "ECDSA": "ECDSA", "ECDDSA": "ECDSA",
            "RSAANDMGF1": "RSA", "ED25519": "Ed25519", "ED448": "Ed448", "SM2": "SM2",
        }
        family = family_map.get(alg_token, alg_token.title())
        padding = None
        if match.group("mgf") or "PSS" in upper:
            padding = "PSS"
        elif family == "RSA":
            padding = "PKCS1-v1_5"
        col.add(
            family=family,
            name=f"{family}-{info[1]}" if info and family in ("RSA", "DSA", "ECDSA") else None,
            padding=padding,
            file=rel, line=line, evidence=ev,
            extra={**extra, "signature_alg": alg, "hash": info[1] if info else None},
        )
        if info:
            col.add(family=info[0], name=info[1], file=rel, line=line, evidence=ev,
                    extra=extra, confidence="medium")
        return
    mapped = _KPG_FAMILIES.get(upper)
    if mapped:
        col.add(family=mapped[0], padding=mapped[1], file=rel, line=line, evidence=ev,
                extra={**extra, "signature_alg": alg})
        return
    if upper.startswith("RSASSA-PSS"):
        col.add(family="RSA", padding="PSS", file=rel, line=line, evidence=ev,
                extra={**extra, "signature_alg": alg})
        return
    col.add(family="Unknown", name=f"UNKNOWN ({alg})", file=rel, line=line, evidence=ev,
            extra=extra, confidence="low")


def _apply_init(record: _Generator, site: CallSite, bound_curves: set[str]) -> None:
    for arg in site.args:
        size = lit_int(arg)
        if size is not None and 16 <= size <= 65536:
            record.key_size = size
            continue
        curve = None
        spec = re.search(r"new\s+\w*(?:ECGenParameterSpec|NamedParameterSpec)\s*\(([^)]*)\)", arg)
        if spec:
            value = lit_str(spec.group(1))
            curve = normalize_curve(value) if value else None
        elif "NamedParameterSpec." in arg:
            token = arg.rsplit(".", 1)[-1].strip(" ),;")
            curve = normalize_curve(token)
        if curve:
            record.curve = curve
            bound_curves.add(curve)
            if curve in ("X25519", "X448") and record.family == "XDH":
                record.family = curve
            elif curve in ("Ed25519", "Ed448") and record.family in ("XDH", "ECDSA"):
                record.family = curve
            continue
        rsa_spec = re.search(r"new\s+RSAKeyGenParameterSpec\s*\(\s*([0-9_]+)", arg)
        if rsa_spec:
            record.key_size = lit_int(rsa_spec.group(1))


def _emit_generator(col: Collector, record: _Generator, rel: str) -> None:
    family = record.family
    if family in ("X25519", "X448", "Ed25519", "Ed448", "XDH"):
        col.add(family=family, name=family, file=rel, line=record.line, evidence=record.evidence,
                extra=record.extra, confidence=record.confidence)
        return
    col.add(
        family=family,
        key_size=record.key_size,
        curve=record.curve,
        padding=record.padding,
        file=rel,
        line=record.line,
        evidence=record.evidence,
        extra=record.extra,
        confidence=record.confidence,
    )


def _handle_tls_setter(col: Collector, site: CallSite, rel: str) -> None:
    values: list[str] = []
    for arg in site.args:
        values.extend(all_strings(arg))
    line, ev = site.line, site.evidence
    if site.base in ("setEnabledProtocols", "setProtocols"):
        for value in values:
            version = tls_version(value)
            if not version:
                continue
            col.add(
                family="TLS",
                name=version if version[:3] in ("TLS", "SSL") else f"TLS-{version}",
                kind="protocol",
                mode=version,
                file=rel, line=line, evidence=ev,
                extra={"api": site.base, "version": version},
            )
        return
    weak = [v for v in values if re.search(r"_RC4_|_DES_|_3DES_|DES_CBC|_NULL_|EXPORT|_MD5|anon", v)]
    if values:
        col.add(
            family="TLS", name="TLS (cipher suite list)", kind="protocol", mode="ciphers",
            file=rel, line=line, evidence=ev,
            extra={"api": site.base, "ciphers": values, "weak_suites": weak},
            confidence="high" if weak else "medium",
        )
    for value in weak:
        upper = value.upper()
        if "3DES" in upper or "DES_EDE" in upper:
            col.add(family="3DES", key_size=168, mode="CBC", file=rel, line=line, evidence=ev,
                    extra={"api": site.base, "cipher_suite": value})
        elif "RC4" in upper:
            col.add(family="RC4", file=rel, line=line, evidence=ev,
                    extra={"api": site.base, "cipher_suite": value})
        elif "_DES_" in upper or upper.endswith("_DES_CBC_SHA"):
            col.add(family="DES", key_size=56, mode="CBC", file=rel, line=line, evidence=ev,
                    extra={"api": site.base, "cipher_suite": value})


# --------------------------------------------------------------------------
# imports
# --------------------------------------------------------------------------
def _scan_imports(col: Collector, masked: Masked, rel: str) -> None:
    for m in _IMPORT_RE.finditer(masked.code):
        package = m.group(1)
        line = masked.line_of(m.start())
        evidence = masked.evidence(m.start())
        pqc = pqc_info(package)
        if pqc:
            col.add(
                family=pqc["family"], name=pqc["name"], kind="library",
                file=rel, line=line, evidence=evidence,
                extra={"package": package, "source": "import", "standardised": pqc["standardised"]},
            )
            continue
        for prefix, family, display in _JAVA_LIBS:
            if package == prefix or package.startswith(prefix + "."):
                col.add(
                    family="Library" if family == "Library" else family,
                    name=display,
                    kind="library",
                    file=rel, line=line, evidence=evidence,
                    extra={"package": package, "ecosystem": "maven"},
                    confidence="high",
                )
                break
