"""JavaScript / TypeScript cryptographic-asset detector.

Parses every ``.js/.mjs/.cjs/.ts/.tsx/.jsx`` file with tree-sitter (grammar
``tree_sitter_javascript``) when it is installed and *also* with the masked
tokenizer from :mod:`._srcutil`; the two call-site lists are unioned and
de-duplicated.  That keeps recall high on TypeScript-only syntax (which the JS
grammar parses with ERROR nodes) while keeping the precision of a real parse on
plain JavaScript.

Covered surfaces
----------------
* ``node:crypto`` -- ``generateKeyPair(Sync)``, ``createHash``, ``createHmac``,
  ``createCipheriv``/``createDecipheriv``, ``createSign``/``createVerify``,
  ``createECDH``, ``createDiffieHellman``, ``diffieHellman``, ``pbkdf2``,
  ``scrypt``, ``publicEncrypt``/``privateDecrypt``, ``sign``/``verify``.
* WebCrypto -- ``crypto.subtle.generateKey|importKey|deriveKey|deriveBits|
  sign|verify|encrypt|decrypt|wrapKey|digest``.
* ``jsonwebtoken`` / ``jose`` -- ``algorithm``/``algorithms``/``alg`` options.
* ``node-forge``, ``crypto-js``, ``elliptic``, ``tweetnacl``.
* TLS configuration -- ``tls.connect``, ``https.Agent``, ``minVersion``,
  ``secureProtocol``, ``rejectUnauthorized: false``.
* Post-quantum packages/identifiers -- ml-kem, ml-dsa, kyber, dilithium,
  falcon, sphincs+, ...

``detect(root_path, policy) -> (artefacts, files_scanned, errors)``
"""

from __future__ import annotations

import re
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
    lit_bool,
    lit_int,
    lit_str,
    load_ts_parser,
    mask_source,
    node_text,
    normalize_curve,
    obj_prop,
    parse_jwt_alg,
    parse_openssl_cipher,
    pqc_info,
    snippet,
    tls_version,
    walk_nodes,
)

__all__ = ["detect", "FILE_EXTS", "DETECTOR"]

DETECTOR = "source_js"
FILE_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")

_KEYTYPE_FAMILY = {
    "rsa": "RSA",
    "rsa-pss": "RSA",
    "dsa": "DSA",
    "ec": "ECDSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
    "dh": "DH",
}

_CRYPTOJS_ALGOS = {
    "MD5": ("hash", "MD5"),
    "SHA1": ("hash", "SHA1"),
    "SHA224": ("hash", "SHA224"),
    "SHA256": ("hash", "SHA256"),
    "SHA384": ("hash", "SHA384"),
    "SHA512": ("hash", "SHA512"),
    "SHA3": ("hash", "SHA3-512"),
    "RIPEMD160": ("hash", "RIPEMD160"),
    "HmacMD5": ("hmac", "MD5"),
    "HmacSHA1": ("hmac", "SHA1"),
    "HmacSHA256": ("hmac", "SHA256"),
    "HmacSHA512": ("hmac", "SHA512"),
    "AES": ("cipher", "AES"),
    "TripleDES": ("cipher", "3DES"),
    "DES": ("cipher", "DES"),
    "RC4": ("cipher", "RC4"),
    "RC4Drop": ("cipher", "RC4"),
    "Rabbit": ("cipher", "Rabbit"),
    "RabbitLegacy": ("cipher", "Rabbit"),
    "PBKDF2": ("kdf", "PBKDF2"),
    "EvpKDF": ("kdf", "EVP-KDF"),
}

_JS_LIBS = {
    "node-forge": ("Library", "node-forge"),
    "crypto-js": ("Library", "crypto-js"),
    "jsonwebtoken": ("Library", "jsonwebtoken"),
    "jose": ("Library", "jose"),
    "jws": ("Library", "jws"),
    "bcrypt": ("bcrypt", "bcrypt"),
    "bcryptjs": ("bcrypt", "bcryptjs"),
    "argon2": ("Argon2", "argon2"),
    "elliptic": ("Library", "elliptic"),
    "sjcl": ("Library", "sjcl"),
    "tweetnacl": ("Library", "tweetnacl"),
    "libsodium-wrappers": ("Library", "libsodium"),
    "libsodium": ("Library", "libsodium"),
    "openpgp": ("Library", "openpgp"),
    "node-rsa": ("Library", "node-rsa"),
    "ursa": ("Library", "ursa"),
    "md5": ("MD5", "md5"),
    "sha1": ("SHA-1", "sha1"),
    "@noble/curves": ("Library", "@noble/curves"),
    "@noble/hashes": ("Library", "@noble/hashes"),
    "@noble/ciphers": ("Library", "@noble/ciphers"),
    "@peculiar/webcrypto": ("Library", "@peculiar/webcrypto"),
    "pkijs": ("Library", "pkijs"),
    "asn1js": ("Library", "asn1js"),
}

_IMPORT_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)(['"])([^'"\n]{1,200})\1"""
)
_TLS_OPTION_RE = re.compile(
    r"\b(minVersion|maxVersion|secureProtocol|rejectUnauthorized|ciphers|secureOptions)\s*:"
)
_FORGE_MD_RE = re.compile(r"\bforge\s*\.\s*md\s*\.\s*([A-Za-z0-9_]+)")
_CRYPTOJS_RE = re.compile(r"\bCryptoJS\s*\.\s*([A-Za-z0-9_]+)")
_CRYPTOJS_MODE_RE = re.compile(r"mode\s*:\s*CryptoJS\s*\.\s*mode\s*\.\s*([A-Za-z0-9_]+)")
_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def detect(root_path: str | Path, policy: Any = None) -> tuple[list, int, list[str]]:
    """Scan ``root_path`` for JavaScript/TypeScript cryptographic assets."""
    pv = PolicyView(policy)
    col = Collector(DETECTOR)
    errors: list[str] = []
    files_scanned = 0
    parser = load_ts_parser("tree_sitter_javascript", "javascript")

    for _path, rel, src in iter_source_files(root_path, FILE_EXTS, pv, errors):
        files_scanned += 1
        try:
            masked = mask_source(src, "js")
        except Exception as exc:  # pragma: no cover - masking is total
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

        tls_lines: set[int] = set()
        for site in _dedupe(calls):
            try:
                _handle_call(col, site, rel, tls_lines)
            except Exception as exc:
                errors.append(f"{rel}:{site.line}: handler error ({type(exc).__name__}: {exc})")
        try:
            _scan_imports(col, masked, rel)
            _scan_identifiers(col, masked, rel, tls_lines)
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
        if node.type not in ("call_expression", "new_expression"):
            continue
        func = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        if func is None:
            continue
        callee_raw = collapse_ws(node_text(src_bytes, func))
        receiver_call = None
        if func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            base = node_text(src_bytes, prop) if prop is not None else ""
            if obj is not None and obj.type in ("call_expression", "new_expression"):
                receiver_call = collapse_ws(node_text(src_bytes, obj))
                receiver = "<call>"
                callee = f"<call>.{base}"
            else:
                receiver = collapse_ws(node_text(src_bytes, obj)) if obj is not None else ""
                callee = f"{receiver}.{base}" if receiver else base
        else:
            callee = callee_raw
            base = callee_raw.rsplit(".", 1)[-1]
            receiver = callee_raw.rsplit(".", 1)[0] if "." in callee_raw else ""

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
            if parent.type in ("await_expression", "parenthesized_expression"):
                parent = parent.parent
                continue
            break

        line = node.start_point[0] + 1
        calls.append(
            CallSite(
                callee=("new " + callee) if node.type == "new_expression" else callee,
                base=base,
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
# small emit helpers
# --------------------------------------------------------------------------
def _add_hash(
    col: Collector,
    value: str | None,
    rel: str,
    line: int,
    evidence: str,
    api: str,
    confidence: str = "high",
) -> bool:
    info = hash_info(value)
    if not info:
        return False
    family, name = info
    col.add(
        family=family,
        name=name,
        file=rel,
        line=line,
        evidence=evidence,
        extra={"api": api},
        confidence=confidence,
    )
    return True


def _add_unknown(col: Collector, api: str, rel: str, line: int, evidence: str) -> None:
    col.add(
        family="Unknown",
        name=f"UNKNOWN ({api})",
        file=rel,
        line=line,
        evidence=evidence,
        extra={"api": api, "reason": "algorithm selected at runtime (non-literal argument)"},
        confidence="low",
    )


def _add_pqc(
    col: Collector,
    token: str,
    rel: str,
    line: int,
    evidence: str,
    kind: str = "algorithm",
    confidence: str = "high",
    source: str = "identifier",
) -> bool:
    info = pqc_info(token)
    if not info:
        return False
    col.add(
        family=info["family"],
        name=info["name"],
        kind=kind,
        file=rel,
        line=line,
        evidence=evidence,
        extra={
            "matched": info["matched"],
            "source": source,
            "standardised": info["standardised"],
        },
        confidence=confidence,
    )
    return True


def _tls_from_options(
    col: Collector, text: str, rel: str, line: int, evidence: str, api: str, tls_lines: set[int]
) -> bool:
    """Emit TLS protocol artefacts from an options object (any API)."""
    found = False
    versions: list[str] = []
    for prop in ("minVersion", "maxVersion", "secureProtocol"):
        raw = obj_prop(text, prop)
        if raw is None:
            continue
        version = tls_version(lit_str(raw) or raw)
        if version:
            versions.append(version)
            col.add(
                family="TLS",
                name=version if version[:3] in ("TLS", "SSL") else f"TLS-{version}",
                kind="protocol",
                mode=version,
                file=rel,
                line=line,
                evidence=evidence,
                extra={"api": api, "option": prop, "version": version},
                confidence="high",
            )
            found = True
    reject = obj_prop(text, "rejectUnauthorized")
    if lit_bool(reject or "") is False:
        col.add(
            family="TLS",
            name="TLS (certificate validation disabled)",
            kind="protocol",
            mode="rejectUnauthorized=false",
            file=rel,
            line=line,
            evidence=evidence,
            extra={"api": api, "rejectUnauthorized": False},
            confidence="high",
        )
        found = True
    ciphers = obj_prop(text, "ciphers")
    cipher_value = lit_str(ciphers) if ciphers else None
    if cipher_value:
        weak = [
            token
            for token in re.split(r"[:,\s]+", cipher_value)
            if re.search(r"RC4|3DES|DES|NULL|EXPORT|MD5|anon", token, re.I)
        ]
        col.add(
            family="TLS",
            name="TLS (cipher suite list)",
            kind="protocol",
            mode="ciphers",
            file=rel,
            line=line,
            evidence=evidence,
            extra={"api": api, "ciphers": cipher_value, "weak_suites": weak},
            confidence="medium" if not weak else "high",
        )
        found = True
    if found:
        tls_lines.add(line)
    return found


def _jwt_from_options(col: Collector, text: str, rel: str, line: int, evidence: str) -> bool:
    found = False
    for prop in ("algorithm", "algorithms", "alg"):
        raw = obj_prop(text, prop)
        if raw is None:
            continue
        candidates = all_strings(raw) or ([raw.strip()] if raw else [])
        for candidate in candidates:
            info = parse_jwt_alg(candidate)
            if not info:
                continue
            col.add(
                family=info["family"],
                name=info["name"],
                key_size=info.get("key_size"),
                curve=info.get("curve"),
                mode=info.get("mode"),
                padding=info.get("padding"),
                file=rel,
                line=line,
                evidence=evidence,
                extra={"api": "JWT/JOSE", "jwt_alg": candidate.upper(), "hash": info.get("hash")},
                confidence="high",
            )
            if info.get("hash"):
                _add_hash(col, info["hash"], rel, line, evidence, "JWT/JOSE")
            found = True
    return found


# --------------------------------------------------------------------------
# main call dispatch
# --------------------------------------------------------------------------
_NEEDS_ARGS = frozenset(
    {
        "generateKeyPair", "generateKeyPairSync", "generateKey", "generateKeySync",
        "createHash", "createHmac", "createCipheriv", "createDecipheriv",
        "createCipher", "createDecipher", "createSign", "createVerify",
        "createECDH", "digest", "sign", "verify", "encrypt", "decrypt",
    }
)


def _handle_call(col: Collector, site: CallSite, rel: str, tls_lines: set[int]) -> None:
    base = site.base
    if base in _NEEDS_ARGS and not site.args:
        return  # a zero-argument call of that name is a definition, not a use
    callee_l = site.callee.lower()
    line, ev = site.line, site.evidence
    is_subtle = "subtle" in callee_l or "webcrypto" in callee_l

    # --- node-forge (checked first: it reuses node:crypto method names)
    if base in ("generateKeyPair", "generateKeyPairSync") and (
        "forge" in callee_l or callee_l.endswith("rsa.generatekeypair")
        or callee_l.endswith("rsa.generatekeypairsync")
    ):
        bits = lit_int(obj_prop(site.arg(0), "bits")) or lit_int(site.arg(0))
        col.add(family="RSA", key_size=bits, file=rel, line=line, evidence=ev,
                extra={"api": "forge.pki.rsa.generateKeyPair"})
        return

    # --- node:crypto key generation -----------------------------------
    if base in ("generateKeyPairSync", "generateKeyPair"):
        _node_keypair(col, site, rel)
        return

    if base in ("generateKey", "generateKeySync"):
        algo = _webcrypto_name(site.arg(0))
        if is_subtle or (algo and "-" in algo) or (algo or "").upper() in (
            "ECDSA", "ECDH", "HMAC", "ED25519", "X25519", "ED448", "X448", "PBKDF2", "HKDF"
        ):
            if algo:
                _webcrypto(col, algo, site.arg(0), rel, line, ev, "crypto.subtle.generateKey")
                return
        kind = (lit_str(site.arg(0)) or "").lower()
        length = lit_int(obj_prop(site.arg(1), "length"))
        if kind == "aes":
            col.add(
                family="AES", key_size=length, file=rel, line=line, evidence=ev,
                extra={"api": "crypto.generateKey"},
            )
            return
        if kind == "hmac":
            col.add(
                family="HMAC", name="HMAC", key_size=length, file=rel, line=line, evidence=ev,
                extra={"api": "crypto.generateKey"},
            )
            return
        if algo:
            _webcrypto(col, algo, site.arg(0), rel, line, ev, "crypto.subtle.generateKey")
        return

    if base in ("importKey", "deriveKey", "deriveBits", "wrapKey", "unwrapKey") and is_subtle:
        for arg in site.args:
            algo = _webcrypto_name(arg)
            if algo:
                _webcrypto(col, algo, arg, rel, line, ev, f"crypto.subtle.{base}", "medium")
        return

    if base in ("encrypt", "decrypt", "sign", "verify") and is_subtle:
        algo = _webcrypto_name(site.arg(0))
        if algo:
            _webcrypto(col, algo, site.arg(0), rel, line, ev, f"crypto.subtle.{base}", "medium")
            return

    if base == "digest" and is_subtle:
        value = lit_str(site.arg(0)) or _webcrypto_name(site.arg(0))
        if not _add_hash(col, value, rel, line, ev, "crypto.subtle.digest"):
            _add_unknown(col, "crypto.subtle.digest", rel, line, ev)
        return

    # --- node:crypto primitives ---------------------------------------
    if base == "createHash":
        value = lit_str(site.arg(0))
        if value is None:
            _add_unknown(col, "crypto.createHash", rel, line, ev)
        elif not _add_hash(col, value, rel, line, ev, "crypto.createHash"):
            _add_unknown(col, "crypto.createHash", rel, line, ev)
        return

    if base == "createHmac":
        value = lit_str(site.arg(0))
        info = hash_info(value) if value else None
        if info:
            col.add(
                family="HMAC",
                name=f"HMAC-{info[1]}",
                file=rel, line=line, evidence=ev,
                extra={"api": "crypto.createHmac", "hash": info[1]},
            )
            _add_hash(col, value, rel, line, ev, "crypto.createHmac", "medium")
        else:
            _add_unknown(col, "crypto.createHmac", rel, line, ev)
        return

    if base in ("createCipheriv", "createDecipheriv", "createCipher", "createDecipher"):
        api = f"forge.cipher.{base}" if "forge" in callee_l else f"crypto.{base}"
        value = lit_str(site.arg(0))
        info = parse_openssl_cipher(value) if value else None
        if info:
            col.add(
                family=info["family"],
                key_size=info["key_size"],
                mode=info["mode"],
                file=rel, line=line, evidence=ev,
                extra={"api": api, "cipher_string": info["raw"]},
            )
        else:
            _add_unknown(col, api, rel, line, ev)
        return

    if base in ("createSign", "createVerify"):
        value = lit_str(site.arg(0))
        if value:
            _openssl_signature(col, value, rel, line, ev, f"crypto.{base}")
        else:
            _add_unknown(col, f"crypto.{base}", rel, line, ev)
        return

    if base in ("sign", "verify") and site.receiver.split(".")[-1] in ("crypto", "node:crypto"):
        value = lit_str(site.arg(0))
        if value:
            _openssl_signature(col, value, rel, line, ev, f"crypto.{base}")
        return

    if base == "createECDH":
        curve = normalize_curve(lit_str(site.arg(0)) or "")
        col.add(
            family="ECDH", curve=curve, file=rel, line=line, evidence=ev,
            extra={"api": "crypto.createECDH"},
        )
        return

    if base == "createDiffieHellman" or base == "getDiffieHellman":
        size = lit_int(site.arg(0))
        group = lit_str(site.arg(0))
        col.add(
            family="DH", key_size=size, file=rel, line=line, evidence=ev,
            extra={"api": f"crypto.{base}", "group": group} if group else {"api": f"crypto.{base}"},
        )
        return

    if base == "diffieHellman":
        col.add(
            family="DH", name="DiffieHellman (key agreement)", file=rel, line=line, evidence=ev,
            extra={"api": "crypto.diffieHellman"}, confidence="medium",
        )
        return

    if base in ("pbkdf2", "pbkdf2Sync"):
        digest = lit_str(site.arg(4)) or lit_str(site.arg(3))
        iterations = lit_int(site.arg(2))
        info = hash_info(digest) if digest else None
        col.add(
            family="PBKDF2", name="PBKDF2", kind="algorithm", file=rel, line=line, evidence=ev,
            extra={
                "api": f"crypto.{base}",
                "prf": info[1] if info else None,
                "iterations": iterations,
            },
        )
        if digest:
            _add_hash(col, digest, rel, line, ev, f"crypto.{base}", "medium")
        return

    if base in ("scrypt", "scryptSync"):
        col.add(family="scrypt", name="scrypt", file=rel, line=line, evidence=ev,
                extra={"api": f"crypto.{base}"})
        return

    if base in ("hkdf", "hkdfSync"):
        digest = lit_str(site.arg(0))
        col.add(family="HKDF", name="HKDF", file=rel, line=line, evidence=ev,
                extra={"api": f"crypto.{base}", "hash": digest})
        return

    if base in ("publicEncrypt", "privateDecrypt", "privateEncrypt", "publicDecrypt"):
        padding = None
        joined = site.arg_text
        if "RSA_PKCS1_OAEP_PADDING" in joined:
            padding = "OAEP"
        elif "RSA_PKCS1_PSS_PADDING" in joined:
            padding = "PSS"
        elif "RSA_PKCS1_PADDING" in joined:
            padding = "PKCS1-v1_5"
        elif "RSA_NO_PADDING" in joined:
            padding = "NoPadding"
        col.add(
            family="RSA", padding=padding, file=rel, line=line, evidence=ev,
            extra={"api": f"crypto.{base}"}, confidence="high",
        )
        return

    if base in ("X509Certificate", "createPublicKey", "createPrivateKey") and "new " in site.callee:
        col.add(
            family="X.509", name="X.509 certificate handling", kind="library",
            file=rel, line=line, evidence=ev, extra={"api": base}, confidence="medium",
        )
        return

    # --- node-forge certificates ---------------------------------------
    if "forge.pki" in callee_l and base in (
        "certificateFromPem", "createCertificate", "certificateToPem", "certificationRequestFromPem"
    ):
        col.add(family="X.509", name="X.509 certificate handling", kind="library",
                file=rel, line=line, evidence=ev, extra={"api": f"forge.pki.{base}"},
                confidence="medium")
        return

    # --- elliptic / tweetnacl -----------------------------------------
    if site.callee.startswith("new ") and base in ("EC", "ec", "eddsa"):
        curve = normalize_curve(lit_str(site.arg(0)) or "")
        if base == "eddsa":
            col.add(family="Ed25519", file=rel, line=line, evidence=ev,
                    extra={"api": "elliptic.eddsa"})
        elif curve:
            col.add(family="ECDSA", curve=curve, file=rel, line=line, evidence=ev,
                    extra={"api": "elliptic.ec"})
        return

    if "nacl.box" in callee_l:
        col.add(family="X25519", name="X25519", file=rel, line=line, evidence=ev,
                extra={"api": "tweetnacl.box"}, confidence="medium")
        return
    if "nacl.sign" in callee_l:
        col.add(family="Ed25519", name="Ed25519", file=rel, line=line, evidence=ev,
                extra={"api": "tweetnacl.sign"}, confidence="medium")
        return
    if "nacl.secretbox" in callee_l:
        col.add(family="Salsa20", name="XSalsa20-Poly1305", key_size=256, mode="AEAD",
                file=rel, line=line, evidence=ev, extra={"api": "tweetnacl.secretbox"},
                confidence="medium")
        return

    # --- password hashing ---------------------------------------------
    if site.receiver.split(".")[-1] in ("bcrypt", "bcryptjs") or base in ("hashSync", "genSaltSync"):
        if base in ("hash", "hashSync", "compare", "compareSync", "genSalt", "genSaltSync"):
            cost = lit_int(site.arg(1)) if base in ("hash", "hashSync") else lit_int(site.arg(0))
            col.add(family="bcrypt", name="bcrypt", file=rel, line=line, evidence=ev,
                    extra={"api": f"bcrypt.{base}", "cost": cost}, confidence="medium")
            return

    # --- JWT / JOSE and TLS options anywhere in the arguments ---------
    for arg in site.args:
        if not arg or (":" not in arg and "=" not in arg):
            continue
        _jwt_from_options(col, arg, rel, line, ev)
        if _TLS_OPTION_RE.search(arg):
            api = site.callee if site.callee else "options"
            _tls_from_options(col, arg, rel, line, ev, api, tls_lines)

    # --- post-quantum APIs --------------------------------------------
    if pqc_info(site.callee):
        _add_pqc(col, site.callee, rel, line, ev, source="call")


def _node_keypair(col: Collector, site: CallSite, rel: str) -> None:
    kind = (lit_str(site.arg(0)) or "").strip().lower()
    opts = site.arg(1)
    line, ev = site.line, site.evidence
    api = f"crypto.{site.base}"
    if not kind:
        if pqc_info(site.arg(0)):
            _add_pqc(col, site.arg(0), rel, line, ev, source="call")
        else:
            _add_unknown(col, api, rel, line, ev)
        return
    info = pqc_info(kind)
    if info:
        _add_pqc(col, kind, rel, line, ev, source="call")
        return
    family = _KEYTYPE_FAMILY.get(kind)
    if family is None:
        _add_unknown(col, api, rel, line, ev)
        return
    if family in ("RSA", "DSA"):
        size = lit_int(obj_prop(opts, "modulusLength")) or lit_int(obj_prop(opts, "primeLength"))
        extra = {"api": api}
        if kind == "rsa-pss":
            extra["scheme"] = "RSA-PSS"
            hash_prop = lit_str(obj_prop(opts, "hashAlgorithm") or "")
            if hash_prop:
                extra["hash"] = hash_prop
        col.add(family=family, key_size=size, padding="PSS" if kind == "rsa-pss" else None,
                file=rel, line=line, evidence=ev, extra=extra)
        return
    if family == "ECDSA":
        curve = normalize_curve(lit_str(obj_prop(opts, "namedCurve") or "") or "")
        col.add(family="ECDSA", curve=curve, file=rel, line=line, evidence=ev, extra={"api": api})
        return
    if family == "DH":
        size = lit_int(obj_prop(opts, "primeLength"))
        group = lit_str(obj_prop(opts, "group") or "")
        col.add(family="DH", key_size=size, file=rel, line=line, evidence=ev,
                extra={"api": api, "group": group})
        return
    col.add(family=family, name=family, file=rel, line=line, evidence=ev, extra={"api": api})


def _webcrypto_name(arg: str) -> str | None:
    if not arg:
        return None
    value = lit_str(arg)
    if value:
        return value
    prop = obj_prop(arg, "name")
    if prop:
        return lit_str(prop)
    return None


def _webcrypto(
    col: Collector,
    algo: str,
    arg_text: str,
    rel: str,
    line: int,
    evidence: str,
    api: str,
    confidence: str = "high",
) -> None:
    name = algo.strip().upper()
    hash_prop = obj_prop(arg_text, "hash")
    hash_value = lit_str(hash_prop or "") or (
        lit_str(obj_prop(hash_prop or "", "name") or "") if hash_prop else None
    )
    if name in ("RSASSA-PKCS1-V1_5", "RSA-PSS", "RSA-OAEP"):
        padding = {
            "RSASSA-PKCS1-V1_5": "PKCS1-v1_5", "RSA-PSS": "PSS", "RSA-OAEP": "OAEP",
        }[name]
        size = lit_int(obj_prop(arg_text, "modulusLength"))
        col.add(family="RSA", key_size=size, padding=padding, file=rel, line=line,
                evidence=evidence, extra={"api": api, "webcrypto": algo, "hash": hash_value},
                confidence=confidence)
        if hash_value:
            _add_hash(col, hash_value, rel, line, evidence, api, "medium")
        return
    if name in ("ECDSA", "ECDH"):
        curve = normalize_curve(lit_str(obj_prop(arg_text, "namedCurve") or "") or "")
        col.add(family=name, curve=curve, file=rel, line=line, evidence=evidence,
                extra={"api": api, "webcrypto": algo}, confidence=confidence)
        if hash_value:
            _add_hash(col, hash_value, rel, line, evidence, api, "medium")
        return
    if name in ("ED25519", "X25519", "ED448", "X448"):
        proper = {"ED25519": "Ed25519", "X25519": "X25519", "ED448": "Ed448", "X448": "X448"}[name]
        col.add(family=proper, name=proper, file=rel, line=line, evidence=evidence,
                extra={"api": api, "webcrypto": algo}, confidence=confidence)
        return
    if name.startswith("AES-"):
        mode = name.split("-", 1)[1]
        length = lit_int(obj_prop(arg_text, "length"))
        col.add(family="AES", key_size=length, mode=mode, file=rel, line=line, evidence=evidence,
                extra={"api": api, "webcrypto": algo}, confidence=confidence)
        return
    if name == "HMAC":
        info = hash_info(hash_value) if hash_value else None
        col.add(family="HMAC", name=f"HMAC-{info[1]}" if info else "HMAC",
                key_size=lit_int(obj_prop(arg_text, "length")), file=rel, line=line,
                evidence=evidence, extra={"api": api, "hash": info[1] if info else None},
                confidence=confidence)
        if hash_value:
            _add_hash(col, hash_value, rel, line, evidence, api, "medium")
        return
    if name in ("PBKDF2", "HKDF"):
        col.add(family=name, name=name, file=rel, line=line, evidence=evidence,
                extra={
                    "api": api,
                    "hash": hash_value,
                    "iterations": lit_int(obj_prop(arg_text, "iterations")),
                },
                confidence=confidence)
        if hash_value:
            _add_hash(col, hash_value, rel, line, evidence, api, "medium")
        return
    if hash_info(name):
        _add_hash(col, name, rel, line, evidence, api, confidence)
        return
    if pqc_info(name):
        _add_pqc(col, name, rel, line, evidence, source="webcrypto", confidence=confidence)
        return


def _openssl_signature(
    col: Collector, value: str, rel: str, line: int, evidence: str, api: str
) -> None:
    text = value.lower()
    hash_match = re.search(r"(sha3-?\d{3}|sha-?\d{3}|sha-?1|sha|md5|md4)", text)
    hash_name = hash_match.group(1) if hash_match else None
    family = None
    curve = None
    if "ecdsa" in text:
        family = "ECDSA"
    elif "ed25519" in text:
        family = "Ed25519"
        curve = "Ed25519"
    elif "ed448" in text:
        family = "Ed448"
    elif "dsa" in text:
        family = "DSA"
    elif "rsa" in text:
        family = "RSA"
    if family:
        info = hash_info(hash_name) if hash_name else None
        col.add(
            family=family,
            name=(f"{family}-{info[1]}" if info and family in ("RSA", "DSA", "ECDSA") else None),
            curve=curve,
            padding=("PSS" if "pss" in text else ("PKCS1-v1_5" if family == "RSA" else None)),
            file=rel, line=line, evidence=evidence,
            extra={"api": api, "signature_alg": value, "hash": info[1] if info else None},
        )
    if hash_name:
        _add_hash(col, hash_name, rel, line, evidence, api, "medium")
    elif not family:
        _add_unknown(col, api, rel, line, evidence)


# --------------------------------------------------------------------------
# import / identifier passes
# --------------------------------------------------------------------------
def _scan_imports(col: Collector, masked: Masked, rel: str) -> None:
    for m in _IMPORT_RE.finditer(masked.text):
        if not masked.is_code(m.start(), m.start() + 4):
            continue
        module = m.group(2).strip()
        if not module:
            continue
        line = masked.line_of(m.start())
        evidence = masked.evidence(m.start())
        clean = module[2:] if module.startswith("node:") else module
        if _add_pqc(col, module, rel, line, evidence, kind="library", source="import"):
            continue
        entry = _JS_LIBS.get(clean)
        if entry is None:
            for prefix, value in _JS_LIBS.items():
                if clean == prefix or clean.startswith(prefix + "/"):
                    entry = value
                    break
        if entry is None:
            continue
        family, name = entry
        col.add(
            family=family,
            name=name,
            kind="library",
            file=rel,
            line=line,
            evidence=evidence,
            extra={"package": module, "ecosystem": "npm"},
            confidence="high",
        )


def _scan_identifiers(col: Collector, masked: Masked, rel: str, tls_lines: set[int]) -> None:
    code = masked.code

    for m in _FORGE_MD_RE.finditer(code):
        line = masked.line_of(m.start())
        _add_hash(col, m.group(1), rel, line, masked.evidence(m.start()), "forge.md")

    for m in _CRYPTOJS_RE.finditer(code):
        entry = _CRYPTOJS_ALGOS.get(m.group(1))
        if entry is None:
            continue
        kind, value = entry
        line = masked.line_of(m.start())
        evidence = masked.evidence(m.start())
        line_text = masked.line_text(line)
        if kind == "hash":
            _add_hash(col, value, rel, line, evidence, "crypto-js")
        elif kind == "hmac":
            info = hash_info(value)
            col.add(family="HMAC", name=f"HMAC-{info[1]}" if info else "HMAC",
                    file=rel, line=line, evidence=evidence,
                    extra={"api": "crypto-js", "hash": info[1] if info else None})
        elif kind == "cipher":
            mode_match = _CRYPTOJS_MODE_RE.search(line_text)
            mode = mode_match.group(1).upper() if mode_match else None
            col.add(family=value, mode=mode, file=rel, line=line, evidence=evidence,
                    extra={
                        "api": "crypto-js",
                        "note": None if mode else "crypto-js defaults to CBC with an EVP-KDF key",
                    })
        else:
            col.add(family=value, name=value, file=rel, line=line, evidence=evidence,
                    extra={"api": "crypto-js"})

    for m in _TLS_OPTION_RE.finditer(masked.text):
        line = masked.line_of(m.start())
        if line in tls_lines or not masked.is_code(m.start(), m.end()):
            continue
        chunk = masked.text[m.start() : m.start() + 400]
        if _tls_from_options(col, chunk, rel, line, masked.evidence(m.start()),
                             "tls options object", tls_lines):
            continue

    for m in _IDENT_RE.finditer(code):
        token = m.group(0)
        if len(token) < 4:
            continue
        info = pqc_info(token)
        if not info:
            continue
        line = masked.line_of(m.start())
        _add_pqc(col, token, rel, line, masked.evidence(m.start()),
                 confidence="medium", source="identifier")
