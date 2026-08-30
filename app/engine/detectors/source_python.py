"""ECDAT -- semantic detector for cryptography used in Python source files.

This detector is *semantic*, not textual.  Every file is parsed into a syntax
tree (``tree_sitter`` + ``tree_sitter_python``; the CPython ``ast`` module is
used as an automatic fallback when the tree-sitter wheels are unavailable).
From that tree we build a small, parser-independent intermediate
representation (:class:`_Unit`):

* ``aliases``      -- from ``import x as y`` / ``from a.b import c as d``
* ``star_modules`` -- from ``from a.b import *``
* ``calls``        -- callee dotted name, positional args, keyword args, position
* ``refs``         -- maximal dotted name references that are *not* callees
                      (``ssl.PROTOCOL_TLSv1``, ``digestmod=hashlib.sha1`` ...)
* ``consts``       -- module level ``NAME = <int|str>`` bindings, used to fold
                      ``generate_private_key(key_size=KEY_BITS)``

Alias maps are built from the imports, every callee / reference is resolved
through them (so ``h.md5()`` and ``hashlib.md5()`` both resolve to
``hashlib.md5``), and the rules then run over resolved names only.

Because the analysis never looks at raw text, comments and docstrings can not
produce findings at all: they are separate nodes that contain no call or
identifier nodes.  Strings that *are* real API arguments (``hashlib.new("md5")``,
``jwt.decode(..., algorithms=["HS256"])``) are honoured, while strings used as
exception / logging messages are suppressed explicitly via the parse tree
(``raise`` ancestry and message-style callees).

Traversal invariants
--------------------
Both front ends walk the tree with an **explicit stack**, never by recursing
per node, so a 20 000-term expression or a 3 000-deep literal cannot exhaust
the C stack and silently cost us a whole file.  The only recursive step left is
the argument builder, which is bounded by :data:`_MAX_EXPR_DEPTH`; past that
depth an argument degrades to a plain text ``_Arg`` instead of blowing up.  A
``RecursionError`` that still escapes (CPython's own parser has limits of its
own) is reported as one distinct, actionable error rather than two identical
stack-overflow messages.

Path and policy invariants
--------------------------
* ``Occurrence.file`` is always a POSIX path **relative to the scan root**.
* Exclusions come from the policy.  A ``Policy`` object is used through its
  ``is_ignored()`` method; a plain mapping is probed for the usual key names
  (``ignore_paths`` included).  Glob matching is delegated to
  ``app.engine.policy.glob_match`` so ``**/`` and ``/**`` mean the same thing
  here as everywhere else in the engine.

Public API
----------
``FILE_EXTS``                       -- file extensions this detector claims
``detect(root_path, policy)``       -- ``(artefacts, files_scanned, errors)``
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional

try:  # normal package import
    from ..models import Artefact, Occurrence, Params
except Exception:  # pragma: no cover - direct / flat execution
    from app.engine.models import Artefact, Occurrence, Params  # type: ignore

# Glob matching is owned by the policy module so that every component of the
# engine agrees on what ``**/vendor/**`` means.  The fallback below is only for
# stand-alone execution of this file.
try:  # pragma: no cover - import shape depends on how the package is loaded
    from ..policy import glob_match as _engine_glob_match  # type: ignore
except Exception:  # pragma: no cover
    try:
        from app.engine.policy import glob_match as _engine_glob_match  # type: ignore
    except Exception:
        _engine_glob_match = None  # type: ignore[assignment]


DETECTOR = "source_python"
FILE_EXTS = (".py", ".pyw")

_MAX_EVIDENCE = 180
_DEFAULT_MAX_BYTES = 2_000_000

# Maximum nesting the argument builder will descend into.  Beyond this an
# argument is recorded as opaque text; the enclosing call is still analysed.
_MAX_EXPR_DEPTH = 40

_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".bzr", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", ".eggs", "node_modules", "site-packages",
    "dist-packages", ".idea", ".vscode", ".venv", "venv", "env", ".env",
    "bower_components", ".next", ".nuxt", ".terraform",
}


# --------------------------------------------------------------------------- #
# Knowledge tables
# --------------------------------------------------------------------------- #

# curve token (lower-case, punctuation stripped) -> (canonical name, bits)
_CURVES: dict[str, tuple[str, int]] = {}


def _reg_curve(canon: str, bits: int, *aliases: str) -> None:
    _CURVES[canon.lower()] = (canon, bits)
    for a in aliases:
        _CURVES[a.lower()] = (canon, bits)


_reg_curve("secp192r1", 192, "prime192v1", "p-192", "p192", "nistp192", "nist p-192")
_reg_curve("secp224r1", 224, "p-224", "p224", "nistp224")
_reg_curve("secp256r1", 256, "prime256v1", "p-256", "p256", "nistp256", "nist p-256")
_reg_curve("secp384r1", 384, "p-384", "p384", "nistp384", "nist p-384")
_reg_curve("secp521r1", 521, "p-521", "p521", "nistp521", "nist p-521")
_reg_curve("secp192k1", 192)
_reg_curve("secp224k1", 224)
_reg_curve("secp256k1", 256, "p-256k1")
_reg_curve("sect163k1", 163)
_reg_curve("sect163r2", 163)
_reg_curve("sect233k1", 233)
_reg_curve("sect233r1", 233)
_reg_curve("sect283k1", 283)
_reg_curve("sect283r1", 283)
_reg_curve("sect409k1", 409)
_reg_curve("sect409r1", 409)
_reg_curve("sect571k1", 571)
_reg_curve("sect571r1", 571)
_reg_curve("brainpoolP256R1", 256, "brainpoolp256r1")
_reg_curve("brainpoolP384R1", 384, "brainpoolp384r1")
_reg_curve("brainpoolP512R1", 512, "brainpoolp512r1")

# symmetric algorithm class -> (family, canonical base name, fixed key bits|None)
_SYM: dict[str, tuple[str, str, Optional[int]]] = {
    "aes": ("AES", "AES", None),
    "aes128": ("AES", "AES", 128),
    "aes256": ("AES", "AES", 256),
    "aesgcm": ("AES", "AES", None),
    "aesccm": ("AES", "AES", None),
    "aessiv": ("AES", "AES", None),
    "aesocb3": ("AES", "AES", None),
    "aesgcmsiv": ("AES", "AES", None),
    "tripledes": ("3DES", "3DES", 168),
    "des3": ("3DES", "3DES", 168),
    "des": ("DES", "DES", 56),
    "arc4": ("RC4", "RC4", None),
    "rc4": ("RC4", "RC4", None),
    "arc2": ("RC2", "RC2", None),
    "rc2": ("RC2", "RC2", None),
    "blowfish": ("Blowfish", "Blowfish", None),
    "cast5": ("CAST5", "CAST5", None),
    "cast": ("CAST5", "CAST5", None),
    "idea": ("IDEA", "IDEA", None),
    "seed": ("SEED", "SEED", 128),
    "sm4": ("SM4", "SM4", 128),
    "camellia": ("Camellia", "Camellia", None),
    "chacha20": ("ChaCha20", "ChaCha20", 256),
    "chacha20poly1305": ("ChaCha20", "ChaCha20-Poly1305", 256),
    "chacha20_poly1305": ("ChaCha20", "ChaCha20-Poly1305", 256),
    "salsa20": ("Salsa20", "Salsa20", None),
}

# AEAD one-shot helper classes -> implied mode
_AEAD_MODE = {
    "aesgcm": "GCM",
    "aesccm": "CCM",
    "aessiv": "SIV",
    "aesocb3": "OCB3",
    "aesgcmsiv": "GCM-SIV",
    "chacha20poly1305": "Poly1305",
    "chacha20_poly1305": "Poly1305",
}

_MODES = {
    "gcm": "GCM", "cbc": "CBC", "ecb": "ECB", "ctr": "CTR", "ofb": "OFB",
    "cfb": "CFB", "cfb8": "CFB8", "xts": "XTS", "ccm": "CCM", "siv": "SIV",
    "ocb3": "OCB3", "eax": "EAX", "kw": "KW", "kwp": "KWP", "openpgp": "OpenPGP",
    "poly1305": "Poly1305", "gcm_siv": "GCM-SIV",
}

# pycryptodome cipher modules whose ``.new()`` we understand
_PYCRYPTO_CIPHERS = {
    "aes", "des", "des3", "arc2", "arc4", "blowfish", "cast", "chacha20",
    "chacha20_poly1305", "salsa20",
}

# hash token -> (family, canonical name)
_HASHES: dict[str, tuple[str, str]] = {
    "md2": ("MD2", "MD2"),
    "md4": ("MD4", "MD4"),
    "md5": ("MD5", "MD5"),
    "md5sha1": ("MD5", "MD5-SHA-1"),
    "md5_sha1": ("MD5", "MD5-SHA-1"),
    "sha": ("SHA-1", "SHA-1"),
    "sha1": ("SHA-1", "SHA-1"),
    "sha_1": ("SHA-1", "SHA-1"),
    "sha224": ("SHA-2", "SHA-224"),
    "sha256": ("SHA-2", "SHA-256"),
    "sha384": ("SHA-2", "SHA-384"),
    "sha512": ("SHA-2", "SHA-512"),
    "sha512_224": ("SHA-2", "SHA-512/224"),
    "sha512_256": ("SHA-2", "SHA-512/256"),
    "sha3_224": ("SHA-3", "SHA3-224"),
    "sha3_256": ("SHA-3", "SHA3-256"),
    "sha3_384": ("SHA-3", "SHA3-384"),
    "sha3_512": ("SHA-3", "SHA3-512"),
    "shake_128": ("SHA-3", "SHAKE128"),
    "shake128": ("SHA-3", "SHAKE128"),
    "shake_256": ("SHA-3", "SHAKE256"),
    "shake256": ("SHA-3", "SHAKE256"),
    "blake2b": ("BLAKE2", "BLAKE2b"),
    "blake2s": ("BLAKE2", "BLAKE2s"),
    "blake2b512": ("BLAKE2", "BLAKE2b"),
    "ripemd160": ("RIPEMD-160", "RIPEMD-160"),
    "ripemd": ("RIPEMD-160", "RIPEMD-160"),
    "sm3": ("SM3", "SM3"),
    "whirlpool": ("Whirlpool", "Whirlpool"),
}

# canonical hash name -> digest length in bits.
#
# This is the discriminating parameter for a hash artefact, and it is recorded
# on ``Params.key_size`` (as well as ``extra['digest_size']``).  Without it the
# whole SHA-2 family collapses to one artefact keyed ``SHA-2|None|None|None``
# and every downstream classifier that asks "how long is this digest?" has to
# answer "unknown".  SHAKE is deliberately absent: its output length is chosen
# by the caller, so we record a security level instead of inventing a size.
_HASH_BITS: dict[str, int] = {
    "MD2": 128, "MD4": 128, "MD5": 128, "MD5-SHA-1": 288,
    "SHA-1": 160,
    "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
    "SHA-512/224": 224, "SHA-512/256": 256,
    "SHA3-224": 224, "SHA3-256": 256, "SHA3-384": 384, "SHA3-512": 512,
    "BLAKE2b": 512, "BLAKE2s": 256,
    "RIPEMD-160": 160, "SM3": 256, "Whirlpool": 512,
}

# ``_norm_token`` strips punctuation, so every table that is probed with a
# normalised token needs a normalised key too ("sha3_256" -> "sha3256").
for _k, _v in list(_HASHES.items()):
    _HASHES.setdefault("".join(ch for ch in _k.lower() if ch.isalnum()), _v)
for _k, _v in list(_MODES.items()):
    _MODES.setdefault("".join(ch for ch in _k.lower() if ch.isalnum()), _v)
for _k, _v in list(_SYM.items()):
    _SYM.setdefault("".join(ch for ch in _k.lower() if ch.isalnum()), _v)
del _k, _v

# SHAKE security levels (FIPS 202: capacity 256 / 512 bits gives 128- / 256-bit
# security).  Recorded as an extra, never as a key size.
_XOF_SECURITY = {"SHAKE128": 128, "SHAKE256": 256}

# modules of pycryptodome's Crypto.Hash package
_PYCRYPTO_HASH_MODULES = {
    "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
    "ripemd160", "shake128", "shake256", "sm3", "keccak", "poly1305", "cmac",
}

# TLS / SSL protocol constants -> canonical protocol name
_TLS_CONST: dict[str, str] = {
    "protocol_sslv2": "SSLv2",
    "protocol_sslv3": "SSLv3",
    "protocol_sslv23": "SSLv23 (auto-negotiate)",
    "protocol_tls": "TLS (auto-negotiate)",
    "protocol_tls_client": "TLS (auto-negotiate, client)",
    "protocol_tls_server": "TLS (auto-negotiate, server)",
    "protocol_tlsv1": "TLSv1.0",
    "protocol_tlsv1_1": "TLSv1.1",
    "protocol_tlsv1_2": "TLSv1.2",
    "protocol_tlsv1_3": "TLSv1.3",
    "sslv2_method": "SSLv2",
    "sslv3_method": "SSLv3",
    "sslv23_method": "SSLv23 (auto-negotiate)",
    "tlsv1_method": "TLSv1.0",
    "tlsv1_1_method": "TLSv1.1",
    "tlsv1_2_method": "TLSv1.2",
    "tls_method": "TLS (auto-negotiate)",
}

# ssl.TLSVersion.<X>
_TLS_VERSION_ENUM = {
    "sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1_1": "TLSv1.1",
    "tlsv1_2": "TLSv1.2", "tlsv1_3": "TLSv1.3",
    "minimum_supported": "TLS (library minimum)",
    "maximum_supported": "TLS (library maximum)",
}

# protocol name -> the version number, so consumers do not have to re-parse the
# display name to know which wire version was requested
_TLS_VERSION_NUMBER = {
    "SSLv2": "2.0", "SSLv3": "3.0", "TLSv1.0": "1.0", "TLSv1.1": "1.1",
    "TLSv1.2": "1.2", "TLSv1.3": "1.3",
}

# JWS / JWE "alg" values -> the artefact they imply.  Keys are lower-case; the
# value may carry family, name, key_size, curve, mode, padding and extra.
_JWT_ALG: dict[str, dict[str, Any]] = {
    "none": {"family": "None", "name": "JWT-alg-none",
             "extra": {"insecure": True, "note": "unsigned JWT"}},
    "hs256": {"family": "HMAC", "name": "HMAC-SHA-256", "extra": {"hash": "SHA-256"}},
    "hs384": {"family": "HMAC", "name": "HMAC-SHA-384", "extra": {"hash": "SHA-384"}},
    "hs512": {"family": "HMAC", "name": "HMAC-SHA-512", "extra": {"hash": "SHA-512"}},
    "rs256": {"family": "RSA", "name": "RSA-PKCS1v15", "padding": "PKCS1v15",
              "extra": {"hash": "SHA-256", "usage": "signature"}},
    "rs384": {"family": "RSA", "name": "RSA-PKCS1v15", "padding": "PKCS1v15",
              "extra": {"hash": "SHA-384", "usage": "signature"}},
    "rs512": {"family": "RSA", "name": "RSA-PKCS1v15", "padding": "PKCS1v15",
              "extra": {"hash": "SHA-512", "usage": "signature"}},
    "ps256": {"family": "RSA", "name": "RSA-PSS", "padding": "PSS",
              "extra": {"hash": "SHA-256", "usage": "signature"}},
    "ps384": {"family": "RSA", "name": "RSA-PSS", "padding": "PSS",
              "extra": {"hash": "SHA-384", "usage": "signature"}},
    "ps512": {"family": "RSA", "name": "RSA-PSS", "padding": "PSS",
              "extra": {"hash": "SHA-512", "usage": "signature"}},
    "es256": {"family": "ECDSA", "name": "ECDSA-secp256r1", "curve": "secp256r1",
              "key_size": 256, "extra": {"usage": "signature"}},
    "es256k": {"family": "ECDSA", "name": "ECDSA-secp256k1", "curve": "secp256k1",
               "key_size": 256, "extra": {"usage": "signature"}},
    "es384": {"family": "ECDSA", "name": "ECDSA-secp384r1", "curve": "secp384r1",
              "key_size": 384, "extra": {"usage": "signature"}},
    "es512": {"family": "ECDSA", "name": "ECDSA-secp521r1", "curve": "secp521r1",
              "key_size": 521, "extra": {"usage": "signature"}},
    "eddsa": {"family": "Ed25519", "name": "Ed25519", "key_size": 256,
              "extra": {"jose_alg": "EdDSA", "usage": "signature"}},
    "ed25519": {"family": "Ed25519", "name": "Ed25519", "key_size": 256,
                "extra": {"usage": "signature"}},
    "ed448": {"family": "Ed448", "name": "Ed448", "key_size": 448,
              "extra": {"usage": "signature"}},
    "rsa1_5": {"family": "RSA", "name": "RSA-PKCS1v15", "padding": "PKCS1v15",
               "extra": {"usage": "key wrap"}},
    "rsa-oaep": {"family": "RSA", "name": "RSA-OAEP", "padding": "OAEP",
                 "extra": {"usage": "key wrap"}},
    "rsa-oaep-256": {"family": "RSA", "name": "RSA-OAEP", "padding": "OAEP",
                     "extra": {"usage": "key wrap", "hash": "SHA-256"}},
    "a128kw": {"family": "AES", "name": "AES-128-KW", "key_size": 128, "mode": "KW"},
    "a192kw": {"family": "AES", "name": "AES-192-KW", "key_size": 192, "mode": "KW"},
    "a256kw": {"family": "AES", "name": "AES-256-KW", "key_size": 256, "mode": "KW"},
    "a128gcmkw": {"family": "AES", "name": "AES-128-GCM", "key_size": 128, "mode": "GCM"},
    "a256gcmkw": {"family": "AES", "name": "AES-256-GCM", "key_size": 256, "mode": "GCM"},
    "a128gcm": {"family": "AES", "name": "AES-128-GCM", "key_size": 128, "mode": "GCM"},
    "a192gcm": {"family": "AES", "name": "AES-192-GCM", "key_size": 192, "mode": "GCM"},
    "a256gcm": {"family": "AES", "name": "AES-256-GCM", "key_size": 256, "mode": "GCM"},
    "a128cbc-hs256": {"family": "AES", "name": "AES-128-CBC", "key_size": 128, "mode": "CBC"},
    "a256cbc-hs512": {"family": "AES", "name": "AES-256-CBC", "key_size": 256, "mode": "CBC"},
    "ecdh-es": {"family": "ECDH", "name": "ECDH-ES", "extra": {"usage": "key agreement"}},
    "ecdh-es+a128kw": {"family": "ECDH", "name": "ECDH-ES",
                       "extra": {"usage": "key agreement"}},
    "ecdh-es+a256kw": {"family": "ECDH", "name": "ECDH-ES",
                       "extra": {"usage": "key agreement"}},
}

# post-quantum tokens: (token prefix, family, display base, distinctive?).
# "distinctive" tokens are safe to recognise anywhere in a dotted path; the
# others are ordinary English words (bike, falcon, lms ...) and are only
# accepted when they arrive as an explicit algorithm selector string.
_PQC_FAMILIES: list[tuple[str, str, str, bool]] = [
    ("mlkem", "ML-KEM", "ML-KEM", True),
    ("mldsa", "ML-DSA", "ML-DSA", True),
    ("slhdsa", "SLH-DSA", "SLH-DSA", True),
    ("sphincs", "SLH-DSA", "SPHINCS+", True),
    ("kyber", "Kyber", "Kyber", True),
    ("dilithium", "Dilithium", "Dilithium", True),
    ("frodokem", "FrodoKEM", "FrodoKEM", True),
    ("mceliece", "Classic-McEliece", "Classic-McEliece", True),
    ("xmss", "XMSS", "XMSS", True),
    ("xwing", "X-Wing", "X-Wing", True),
    ("sidh", "SIKE", "SIDH", True),
    ("sike", "SIKE", "SIKE", True),
    ("rainbow", "Rainbow", "Rainbow", True),
    ("hqc", "HQC", "HQC", False),
    ("ntru", "NTRU", "NTRU", False),
    ("falcon", "Falcon", "Falcon", False),
    ("bike", "BIKE", "BIKE", False),
    ("lms", "LMS", "LMS", False),
]

_PQC_STANDARDISED = {
    "Kyber": "ML-KEM", "Dilithium": "ML-DSA", "SPHINCS+": "SLH-DSA",
}

# schemes with a fatal caveat the downstream classifier must not have to guess
_PQC_STATEFUL = {"XMSS", "LMS"}
_PQC_CLASSICALLY_BROKEN = {"SIKE", "Rainbow"}

# names we accept even when we could not resolve them through an import
# (covers ``from ... import *`` and re-exported helpers)
_UNAMBIGUOUS = {
    "ed25519privatekey", "ed25519publickey", "ed448privatekey", "ed448publickey",
    "x25519privatekey", "x25519publickey", "x448privatekey", "x448publickey",
    "aesgcm", "aesccm", "aessiv", "aesocb3", "aesgcmsiv", "chacha20poly1305",
    "pbkdf2hmac", "hkdf", "hkdfexpand", "scrypt", "tripledes", "generate_private_key",
    "set_ciphers",
}

# trailing segments of modules that are commonly wildcard-imported
_STAR_TAILS = {
    "algorithms", "modes", "aead", "hashes", "padding", "asymmetric",
    "rsa", "ec", "dsa", "dh", "ed25519", "ed448", "x25519", "x448",
    "ciphers", "primitives", "kdf",
}

# callee names whose string arguments are human messages, never API selectors
_MESSAGE_CALLEES = {
    "print", "format", "warn", "warns", "log", "debug", "info", "warning",
    "error", "critical", "exception", "fail", "skip", "xfail", "assert_",
    "abort", "raise_for_status", "deprecated", "showwarning", "join", "write",
}


# --------------------------------------------------------------------------- #
# Intermediate representation
# --------------------------------------------------------------------------- #

@dataclass
class _Ref:
    """A maximal dotted name reference that is not a call callee."""
    dotted: str
    line: int
    text: str
    consumed: bool = False


@dataclass
class _Arg:
    text: str = ""
    kw: Optional[str] = None
    string: Optional[str] = None
    number: Optional[Any] = None
    name: Optional[str] = None
    call: Optional["_Call"] = None
    ref: Optional[_Ref] = None
    items: list["_Arg"] = field(default_factory=list)


@dataclass
class _Call:
    func_dotted: Optional[str]
    args: list[_Arg]
    kwargs: dict[str, _Arg]
    line: int
    col: int
    text: str
    in_message: bool = False
    consumed: bool = False


@dataclass
class _Unit:
    """Everything one parsed source file contributes."""
    path: str
    rel: str
    aliases: dict[str, str] = field(default_factory=dict)
    star_modules: list[str] = field(default_factory=list)
    consts: dict[str, Any] = field(default_factory=dict)
    calls: list[_Call] = field(default_factory=list)
    refs: list[_Ref] = field(default_factory=list)


def _clean(text: str, limit: int = _MAX_EVIDENCE) -> str:
    out = " ".join(text.split())
    if len(out) > limit:
        out = out[: limit - 3] + "..."
    return out


# --------------------------------------------------------------------------- #
# Front end 1: tree-sitter
# --------------------------------------------------------------------------- #

_TS_STATE: dict[str, Any] = {"tried": False, "parser": None, "error": None}


def _ts_parser():
    """Return a configured tree-sitter parser, or ``None`` if unavailable."""
    if _TS_STATE["tried"]:
        return _TS_STATE["parser"]
    _TS_STATE["tried"] = True
    try:
        import tree_sitter as ts  # type: ignore
        import tree_sitter_python as tsp  # type: ignore

        lang = None
        raw = None
        try:
            raw = tsp.language()
        except Exception:
            raw = None
        for build in (
            lambda: ts.Language(raw),
            lambda: ts.Language(raw, "python"),
            lambda: ts.Language(tsp.language_python()),  # very old wheels
        ):
            try:
                lang = build()
                break
            except Exception:
                continue
        if lang is None:
            raise RuntimeError("could not construct tree_sitter Language for python")

        parser = None
        try:
            parser = ts.Parser(lang)
        except Exception:
            parser = ts.Parser()
            try:
                parser.language = lang
            except Exception:
                parser.set_language(lang)
        _TS_STATE["parser"] = parser
    except Exception as exc:  # pragma: no cover - depends on environment
        _TS_STATE["parser"] = None
        _TS_STATE["error"] = f"{type(exc).__name__}: {exc}"
    return _TS_STATE["parser"]


class _TSBuilder:
    """Walks a tree-sitter tree and fills a :class:`_Unit`.

    The walk is iterative (explicit stack).  Only :meth:`build_arg` /
    :meth:`build_call` recurse, and they carry a depth budget.
    """

    def __init__(self, unit: _Unit, src: bytes) -> None:
        self.u = unit
        self.src = src

    # -- helpers ---------------------------------------------------------- #
    def txt(self, node) -> str:
        return self.src[node.start_byte: node.end_byte].decode("utf-8", "replace")

    def field(self, node, name: str):
        try:
            return node.child_by_field_name(name)
        except Exception:
            return None

    def fields(self, node, name: str) -> list:
        try:
            return list(node.children_by_field_name(name))
        except Exception:
            one = self.field(node, name)
            return [one] if one is not None else []

    def dotted(self, node) -> Optional[str]:
        """Flatten ``a.b.c`` iteratively -- attribute chains can be long."""
        parts: list[str] = []
        cur = node
        while True:
            t = cur.type
            if t == "identifier":
                parts.append(self.txt(cur))
                break
            if t == "dotted_name":
                names = [self.txt(c) for c in cur.children if c.type == "identifier"]
                if not names:
                    return None
                parts.append(".".join(names))
                break
            if t == "attribute":
                att = self.field(cur, "attribute")
                obj = self.field(cur, "object")
                if att is None or obj is None:
                    return None
                parts.append(self.txt(att))
                cur = obj
                continue
            return None
        parts.reverse()
        return ".".join(parts)

    def string_value(self, node) -> Optional[str]:
        if node.type == "concatenated_string":
            out = []
            for c in node.children:
                if c.type == "string":
                    v = self.string_value(c)
                    if v is None:
                        return None
                    out.append(v)
            return "".join(out)
        if node.type != "string":
            return None
        parts: list[str] = []
        for c in node.children:
            if c.type == "interpolation":
                return None
            if c.type == "string_content":
                parts.append(self.txt(c))
            elif c.type == "escape_sequence":
                parts.append(self.txt(c))
        return "".join(parts)

    def number_value(self, node) -> Optional[Any]:
        try:
            if node.type == "integer":
                return int(self.txt(node).replace("_", ""), 0)
            if node.type == "float":
                return float(self.txt(node).replace("_", ""))
        except Exception:
            return None
        return None

    # -- imports ---------------------------------------------------------- #
    def handle_import(self, node) -> None:
        if node.type == "import_statement":
            for n in self.fields(node, "name"):
                if n.type == "aliased_import":
                    mod = self.dotted(self.field(n, "name") or n)
                    alias_node = self.field(n, "alias")
                    alias = self.txt(alias_node) if alias_node is not None else None
                    if mod and alias:
                        self.u.aliases[alias] = mod
                else:
                    mod = self.dotted(n)
                    if mod:
                        self.u.aliases[mod.split(".")[0]] = mod.split(".")[0]
                        self.u.aliases.setdefault(mod, mod)
            return
        if node.type == "import_from_statement":
            mod_node = self.field(node, "module_name")
            module = self.dotted(mod_node) if mod_node is not None else None
            if module is None:
                module = ""  # relative import
            for c in node.children:
                if c.type == "wildcard_import":
                    if module:
                        self.u.star_modules.append(module)
            for n in self.fields(node, "name"):
                if n.type == "aliased_import":
                    sub = self.dotted(self.field(n, "name") or n)
                    alias_node = self.field(n, "alias")
                    alias = self.txt(alias_node) if alias_node is not None else None
                    if sub and alias:
                        self.u.aliases[alias] = f"{module}.{sub}" if module else sub
                else:
                    sub = self.dotted(n)
                    if sub:
                        self.u.aliases[sub.split(".")[0]] = (
                            f"{module}.{sub}" if module else sub
                        )

    # -- traversal -------------------------------------------------------- #
    def walk(self, root, in_message: bool = False) -> None:
        """Iterative pre-order walk (no recursion limits on huge files)."""
        stack: list[tuple[Any, bool]] = [(root, in_message)]
        while stack:
            node, msg = stack.pop()
            t = node.type
            if t in ("comment", "string", "concatenated_string"):
                # docstrings / bare strings contribute nothing on their own
                continue
            if t in ("import_statement", "import_from_statement"):
                self.handle_import(node)
                continue
            if t == "raise_statement":
                for c in reversed(node.children):
                    stack.append((c, True))
                continue
            if t == "assignment":
                left = self.field(node, "left")
                right = self.field(node, "right")
                if left is not None and left.type == "identifier" and right is not None:
                    val = self.number_value(right)
                    if val is None:
                        val = self.string_value(right)
                    if val is not None:
                        self.u.consts.setdefault(self.txt(left), val)
                for c in reversed(node.children):
                    stack.append((c, msg))
                continue
            if t == "call":
                self.build_call(node, msg, 0)
                continue
            if t in ("attribute", "identifier"):
                dotted = self.dotted(node)
                if dotted and "." in dotted:
                    self.u.refs.append(
                        _Ref(dotted, node.start_point[0] + 1, _clean(self.txt(node)))
                    )
                    continue
                if dotted:
                    continue
            for c in reversed(node.children):
                stack.append((c, msg))

    def build_call(self, node, in_message: bool, depth: int) -> _Call:
        fn = self.field(node, "function")
        dotted = self.dotted(fn) if fn is not None else None
        call = _Call(
            func_dotted=dotted,
            args=[],
            kwargs={},
            line=node.start_point[0] + 1,
            col=node.start_point[1],
            text=_clean(self.txt(node)),
            in_message=in_message,
        )
        self.u.calls.append(call)
        msg_ctx = in_message or _is_message_callee(dotted)
        if depth >= _MAX_EXPR_DEPTH:
            # Too deep to model faithfully.  The callee is still recorded, so
            # ``rsa.generate_private_key(...)`` is found even 40 levels down;
            # only its arguments are left unanalysed.
            return call
        if fn is not None and dotted is None:
            # e.g. ``obj.method().other()`` -- still explore the receiver
            self.walk(fn, in_message)
        arglist = self.field(node, "arguments")
        if arglist is not None:
            for c in arglist.children:
                if c.type in ("(", ")", ",", "comment"):
                    continue
                if c.type == "keyword_argument":
                    name_node = self.field(c, "name")
                    val_node = self.field(c, "value")
                    if name_node is None or val_node is None:
                        continue
                    arg = self.build_arg(val_node, msg_ctx, depth + 1)
                    arg.kw = self.txt(name_node)
                    call.kwargs[arg.kw] = arg
                elif c.type in ("list_splat", "dictionary_splat"):
                    self.walk(c, msg_ctx)
                else:
                    call.args.append(self.build_arg(c, msg_ctx, depth + 1))
        return call

    def build_arg(self, node, in_message: bool, depth: int) -> _Arg:
        arg = _Arg(text=_clean(self.txt(node), 80))
        if depth >= _MAX_EXPR_DEPTH:
            return arg
        t = node.type
        if t == "call":
            arg.call = self.build_call(node, in_message, depth + 1)
            return arg
        if t in ("string", "concatenated_string"):
            arg.string = self.string_value(node)
            return arg
        if t in ("integer", "float"):
            arg.number = self.number_value(node)
            return arg
        if t == "unary_operator":
            inner = self.field(node, "argument")
            if inner is not None:
                sub = self.build_arg(inner, in_message, depth + 1)
                if isinstance(sub.number, (int, float)) and self.txt(node).startswith("-"):
                    arg.number = -sub.number
            return arg
        if t in ("identifier", "attribute"):
            dotted = self.dotted(node)
            if dotted:
                arg.name = dotted
                if "." in dotted:
                    ref = _Ref(dotted, node.start_point[0] + 1, _clean(self.txt(node)))
                    self.u.refs.append(ref)
                    arg.ref = ref
                return arg
            self.walk(node, in_message)
            return arg
        if t in ("list", "tuple", "set", "parenthesized_expression"):
            for c in node.children:
                if c.type in ("[", "]", "(", ")", "{", "}", ",", "comment"):
                    continue
                arg.items.append(self.build_arg(c, in_message, depth + 1))
            if len(arg.items) == 1 and t == "parenthesized_expression":
                inner = arg.items[0]
                inner.text = arg.text
                return inner
            return arg
        self.walk(node, in_message)
        return arg


def _parse_tree_sitter(unit: _Unit, data: bytes) -> tuple[bool, bool]:
    """Parse with tree-sitter.  Returns ``(parsed, had_syntax_errors)``."""
    parser = _ts_parser()
    if parser is None:
        return False, False
    tree = parser.parse(data)
    root = tree.root_node
    _TSBuilder(unit, data).walk(root, False)
    try:
        broken = bool(root.has_error)
    except Exception:
        broken = False
    return True, broken


# --------------------------------------------------------------------------- #
# Front end 2: CPython ``ast`` fallback (used when tree-sitter is missing)
# --------------------------------------------------------------------------- #

def _parse_ast(unit: _Unit, data: bytes) -> None:
    import ast

    tree = ast.parse(data)
    text = data.decode("utf-8", "replace")
    # ``col_offset`` is a UTF-8 byte offset, so index the UTF-8 bytes.  A line
    # offset table makes evidence extraction O(1) per node instead of the O(n)
    # rescan that ``ast.get_source_segment`` performs.
    btext = text.encode("utf-8")
    blines = btext.splitlines(keepends=True)
    offsets: list[int] = [0]
    for bl in blines:
        offsets.append(offsets[-1] + len(bl))

    def seg(node) -> str:
        l1 = getattr(node, "lineno", None)
        c1 = getattr(node, "col_offset", None)
        l2 = getattr(node, "end_lineno", None)
        c2 = getattr(node, "end_col_offset", None)
        try:
            if l1 and l2 and c1 is not None and c2 is not None:
                start = offsets[l1 - 1] + c1
                end = offsets[l2 - 1] + c2
                if 0 <= start < end <= len(btext):
                    return _clean(btext[start:end].decode("utf-8", "replace"))
            if l1 and 1 <= l1 <= len(blines):
                return _clean(blines[l1 - 1].decode("utf-8", "replace"))
        except Exception:
            pass
        return ""

    def dotted(node) -> Optional[str]:
        parts: list[str] = []
        cur = node
        while True:
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                break
            if isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
                continue
            return None
        parts.reverse()
        return ".".join(parts)

    def const_value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, str)):
            if isinstance(node.value, bool):
                return None
            return node.value
        return None

    def build_arg(node, in_message: bool, depth: int) -> _Arg:
        arg = _Arg(text=_clean(seg(node), 80))
        if depth >= _MAX_EXPR_DEPTH:
            return arg
        if isinstance(node, ast.Call):
            arg.call = build_call(node, in_message, depth + 1)
            return arg
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                arg.string = node.value
            elif isinstance(node.value, bytes):
                arg.string = node.value.decode("utf-8", "replace")
            elif isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
                arg.number = node.value
            return arg
        if isinstance(node, ast.JoinedStr):
            return arg
        if isinstance(node, (ast.Name, ast.Attribute)):
            d = dotted(node)
            if d:
                arg.name = d
                if "." in d:
                    ref = _Ref(d, getattr(node, "lineno", 0), _clean(seg(node)))
                    unit.refs.append(ref)
                    arg.ref = ref
                return arg
            walk(node, in_message)
            return arg
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                arg.items.append(build_arg(e, in_message, depth + 1))
            return arg
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            sub = build_arg(node.operand, in_message, depth + 1)
            if isinstance(sub.number, (int, float)):
                arg.number = -sub.number
            return arg
        walk(node, in_message)
        return arg

    def build_call(node: "ast.Call", in_message: bool, depth: int) -> _Call:
        d = dotted(node.func)
        call = _Call(
            func_dotted=d,
            args=[],
            kwargs={},
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            text=_clean(seg(node)),
            in_message=in_message,
        )
        unit.calls.append(call)
        msg_ctx = in_message or _is_message_callee(d)
        if depth >= _MAX_EXPR_DEPTH:
            return call
        if d is None:
            walk(node.func, in_message)
        for a in node.args:
            if isinstance(a, ast.Starred):
                walk(a, msg_ctx)
                continue
            call.args.append(build_arg(a, msg_ctx, depth + 1))
        for kw in node.keywords:
            if kw.arg is None:
                walk(kw.value, msg_ctx)
                continue
            arg = build_arg(kw.value, msg_ctx, depth + 1)
            arg.kw = kw.arg
            call.kwargs[kw.arg] = arg
        return call

    def walk(root, in_message: bool = False) -> None:
        """Iterative pre-order walk, mirroring the tree-sitter front end."""
        stack: list[tuple[Any, bool]] = [(root, in_message)]
        while stack:
            node, msg = stack.pop()
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        unit.aliases[a.asname] = a.name
                    else:
                        head = a.name.split(".")[0]
                        unit.aliases[head] = head
                        unit.aliases.setdefault(a.name, a.name)
                continue
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for a in node.names:
                    if a.name == "*":
                        if module:
                            unit.star_modules.append(module)
                        continue
                    target = f"{module}.{a.name}" if module else a.name
                    unit.aliases[a.asname or a.name.split(".")[0]] = target
                continue
            if isinstance(node, ast.Raise):
                for c in reversed(list(ast.iter_child_nodes(node))):
                    stack.append((c, True))
                continue
            if isinstance(node, ast.Assign):
                v = const_value(node.value)
                if v is not None:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            unit.consts.setdefault(t.id, v)
                for c in reversed(list(ast.iter_child_nodes(node))):
                    stack.append((c, msg))
                continue
            if isinstance(node, ast.Call):
                build_call(node, msg, 0)
                continue
            if isinstance(node, (ast.Name, ast.Attribute)):
                d = dotted(node)
                if d and "." in d:
                    unit.refs.append(_Ref(d, getattr(node, "lineno", 0), _clean(seg(node))))
                    continue
                if d:
                    continue
            if isinstance(node, (ast.Constant, ast.JoinedStr)):
                continue
            for c in reversed(list(ast.iter_child_nodes(node))):
                stack.append((c, msg))

    walk(tree, False)


def _is_message_callee(dotted: Optional[str]) -> bool:
    if not dotted:
        return False
    last = dotted.rsplit(".", 1)[-1]
    low = last.lower()
    if low in _MESSAGE_CALLEES:
        return True
    return (
        last[:1].isupper()
        and (last.endswith("Error") or last.endswith("Exception") or last.endswith("Warning"))
    )


# --------------------------------------------------------------------------- #
# Semantic analysis
# --------------------------------------------------------------------------- #

def _norm_token(tok: str) -> str:
    return "".join(ch for ch in tok.lower() if ch.isalnum())


def _pqc_lookup(token: str, strict: bool = True) -> Optional[dict[str, Any]]:
    """Recognise a post-quantum algorithm token such as ``ML-KEM-768``.

    ``strict`` (the default) only accepts the distinctive tokens, so scanning
    every segment of every dotted name cannot mistake ``bike_share.Model()``
    for the BIKE KEM.  Explicit selector strings -- ``oqs.Signature("Falcon-512")``
    -- are looked up with ``strict=False``.
    """
    norm = _norm_token(token)
    if not norm:
        return None
    for prefix, family, base, distinctive in _PQC_FAMILIES:
        if strict and not distinctive:
            continue
        if prefix not in norm:
            continue
        if not distinctive and not norm.startswith(prefix):
            continue
        # Digit groups are read off the RAW token (which still has its
        # separators) rather than the normalised one, because normalising
        # "SHA2_10_256" to "sha210256" would fuse three numbers into one.
        alnum_idx = [i for i, ch in enumerate(token) if ch.isalnum()]
        cut = norm.find(prefix) + len(prefix)
        raw_tail = token[alnum_idx[cut]:] if cut < len(alnum_idx) else ""
        # A parameter set is a single digit group ("768", "87", "128s").  A
        # compound label such as XMSS-SHA2_10_256 carries several groups and is
        # not a number at all, so we keep the raw token instead of gluing the
        # digits together into a meaningless "210256".
        groups = re.findall(r"\d+", raw_tail)
        level = groups[0] if len(groups) == 1 else ""
        name = f"{base}-{level}" if level else base
        extra: dict[str, Any] = {"pqc": True, "raw_token": token}
        if level:
            # NIST parameter-set label (768, 87, ...) -- deliberately NOT a key
            # size: it is a security-category selector, not a bit length.
            extra["parameter_set"] = level
        elif groups:
            extra["parameter_set"] = token.strip()
        std = _PQC_STANDARDISED.get(base)
        if std:
            extra["pre_standard"] = True
            extra["standardised_as"] = f"{std}-{level}" if level else std
        if base in _PQC_STATEFUL:
            extra["stateful"] = True
        if family in _PQC_CLASSICALLY_BROKEN:
            extra["classically_broken"] = True
        if base == "SPHINCS+" and ("shake" in norm or "sha2" in norm):
            extra["hash_variant"] = "SHAKE" if "shake" in norm else "SHA-2"
        return {"family": family, "name": name, "extra": extra}
    return None


def _parse_cipher_suite(token: str) -> dict[str, Any]:
    """Very light structural parse of an OpenSSL / IANA cipher-suite name."""
    up = token.upper()
    parts = [p for p in up.replace("_", "-").split("-") if p]
    info: dict[str, Any] = {"suite": up}
    kx = [p for p in parts if p in ("ECDHE", "DHE", "EDH", "ECDH", "DH", "RSA", "PSK",
                                    "SRP", "ADH", "AECDH", "KRB5", "EXPORT", "EXP")]
    enc = [p for p in parts if p.startswith(("AES", "CAMELLIA", "SEED", "CHACHA",
                                             "RC4", "RC2", "DES", "3DES", "IDEA", "NULL"))]
    mac = [p for p in parts if p in ("SHA", "SHA1", "SHA256", "SHA384", "SHA512",
                                     "MD5", "POLY1305", "GCM", "CCM", "CCM8")]
    if kx:
        info["kx"] = kx[0]
    if enc:
        info["enc"] = enc[0]
    if mac:
        info["mac"] = mac[-1]
    return info


class _Analyzer:
    """Applies the crypto rule set to one parsed :class:`_Unit`."""

    def __init__(self, unit: _Unit, sink: "_Sink") -> None:
        self.u = unit
        self.sink = sink

    # -- resolution ------------------------------------------------------- #
    def resolve(self, dotted: str) -> tuple[str, bool]:
        """Map a dotted name through the file's import aliases.

        Returns ``(resolved, resolved_via_import)``.  Rules only fire on names
        that really came from an import, which is what keeps ``self.sha1`` or
        ``user.generate_private_key`` out of the results.
        """
        parts = dotted.split(".")
        head = parts[0]
        target = self.u.aliases.get(head)
        if target:
            return ".".join([target] + parts[1:]), True
        if self.u.star_modules:
            # ``from cryptography...algorithms import *`` -- accept a bare class
            # name when it is one we know, and re-attach the wildcard module so
            # the parent-segment rules still apply.
            nhead = _norm_token(head)
            known = (
                nhead in _UNAMBIGUOUS or nhead in _SYM or nhead in _HASHES
                or nhead in _CURVES or head.lower() in _CURVES
            )
            if known:
                module = self.u.star_modules[0]
                for cand in self.u.star_modules:
                    if cand.rsplit(".", 1)[-1] in _STAR_TAILS:
                        module = cand
                        break
                return f"{module}.{dotted}", True
        return dotted, False

    # -- value extraction ------------------------------------------------- #
    def take(self, arg: Optional[_Arg]) -> Optional[_Arg]:
        if arg is None:
            return None
        if arg.call is not None:
            arg.call.consumed = True
        if arg.ref is not None:
            arg.ref.consumed = True
        return arg

    def pick(self, call: _Call, kw_names: Iterable[str], index: Optional[int]) -> Optional[_Arg]:
        for n in kw_names:
            if n in call.kwargs:
                return self.take(call.kwargs[n])
        if index is not None and 0 <= index < len(call.args):
            return self.take(call.args[index])
        return None

    def int_of(self, arg: Optional[_Arg]) -> tuple[Optional[int], str]:
        """Return ``(value, confidence)`` for an integer-valued argument."""
        if arg is None:
            return None, "medium"
        if isinstance(arg.number, int):
            return arg.number, "high"
        if arg.name and "." not in arg.name:
            v = self.u.consts.get(arg.name)
            if isinstance(v, int):
                return v, "high"
            if isinstance(v, str) and v.isdigit():
                return int(v), "high"
        if arg.string and arg.string.isdigit():
            return int(arg.string), "high"
        return None, "medium"

    def str_of(self, arg: Optional[_Arg]) -> tuple[Optional[str], str]:
        if arg is None:
            return None, "medium"
        if arg.string is not None:
            return arg.string, "high"
        if arg.name and "." not in arg.name:
            v = self.u.consts.get(arg.name)
            if isinstance(v, str):
                return v, "high"
        return None, "medium"

    def strings_of(self, arg: Optional[_Arg]) -> list[str]:
        if arg is None:
            return []
        out: list[str] = []
        if arg.string is not None:
            out.append(arg.string)
        for item in arg.items:
            out.extend(self.strings_of(item))
        if not out and arg.name and "." not in arg.name:
            v = self.u.consts.get(arg.name)
            if isinstance(v, str):
                out.append(v)
        return out

    def curve_of(self, arg: Optional[_Arg]) -> tuple[Optional[str], Optional[int], str]:
        """Resolve an elliptic-curve argument to ``(curve, bits, confidence)``."""
        if arg is None:
            return None, None, "medium"
        token: Optional[str] = None
        if arg.call is not None and arg.call.func_dotted:
            token = arg.call.func_dotted.rsplit(".", 1)[-1]
        elif arg.name:
            token = arg.name.rsplit(".", 1)[-1]
            if token not in _CURVES and _norm_token(token) not in _CURVES:
                v = self.u.consts.get(arg.name) if "." not in arg.name else None
                token = v if isinstance(v, str) else token
        elif arg.string:
            token = arg.string
        if not token:
            return None, None, "medium"
        hit = _CURVES.get(token.lower()) or _CURVES.get(_norm_token(token))
        if hit:
            return hit[0], hit[1], "high"
        return None, None, "medium"

    def hash_of(self, arg: Optional[_Arg]) -> tuple[Optional[str], Optional[str], str]:
        """Resolve a hash argument to ``(family, name, confidence)``."""
        if arg is None:
            return None, None, "medium"
        token: Optional[str] = None
        if arg.call is not None and arg.call.func_dotted:
            token = arg.call.func_dotted.rsplit(".", 1)[-1]
        elif arg.name:
            token = arg.name.rsplit(".", 1)[-1]
        elif arg.string:
            token = arg.string
        if not token:
            return None, None, "medium"
        hit = _HASHES.get(token.lower()) or _HASHES.get(_norm_token(token))
        if hit:
            return hit[0], hit[1], "high"
        return None, None, "medium"

    def digest_bits(self, c: _Call, name: str, index: Optional[int] = None) -> Optional[int]:
        """Digest length in bits for a hash call, honouring ``digest_size=``."""
        n, _conf = self.int_of(self.pick(c, ("digest_size",), index))
        if n is not None and 1 <= n <= 64:
            return n * 8
        return _HASH_BITS.get(name)

    # -- emission --------------------------------------------------------- #
    def emit(
        self,
        family: str,
        name: str,
        line: int,
        evidence: str,
        *,
        kind: str = "algorithm",
        key_size: Optional[int] = None,
        curve: Optional[str] = None,
        mode: Optional[str] = None,
        padding: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
        confidence: str = "high",
    ) -> None:
        self.sink.add(
            family=family,
            name=name,
            kind=kind,
            key_size=key_size,
            curve=curve,
            mode=mode,
            padding=padding,
            extra=dict(extra or {}),
            occurrence=Occurrence(
                file=self.u.rel,
                line=line,
                evidence=evidence,
                detector=DETECTOR,
                confidence=confidence,
            ),
        )

    def emit_hash(
        self,
        family: str,
        name: str,
        line: int,
        evidence: str,
        *,
        extra: Optional[dict[str, Any]] = None,
        confidence: str = "high",
        digest_bits: Optional[int] = None,
    ) -> None:
        """Emit a hash artefact carrying its digest length as a parameter.

        The digest length *is* the discriminating parameter for a hash, so it
        goes on ``Params.key_size`` (and ``extra['digest_size']``) rather than
        being left implicit in the display name.  Consumers that group on
        ``Artefact.key()`` then keep SHA-256 and SHA-512 apart, and classifiers
        that ask for a length get one instead of degrading to UNKNOWN.
        """
        ex = dict(extra or {})
        bits = digest_bits if digest_bits is not None else _HASH_BITS.get(name)
        ex.setdefault("variant", name)
        if bits:
            ex.setdefault("digest_size", bits)
        level = _XOF_SECURITY.get(name)
        if level:
            ex.setdefault("xof", True)
            ex.setdefault("security_level", level)
        self.emit(family, name, line, evidence, key_size=bits, extra=ex,
                  confidence=confidence)

    # -- driver ----------------------------------------------------------- #
    def run(self) -> None:
        for call in list(self.u.calls):
            try:
                self.rule_call(call)
            except Exception:
                # a single malformed construct must never abort the scan
                continue
        for ref in self.u.refs:
            if ref.consumed:
                continue
            try:
                self.rule_ref(ref)
            except Exception:
                continue

    # -- call rules ------------------------------------------------------- #
    def rule_call(self, c: _Call) -> None:
        if c.func_dotted is None:
            return
        res, via = self.resolve(c.func_dotted)
        low = res.lower()
        parts = low.split(".")
        last = parts[-1]
        prev = parts[-2] if len(parts) >= 2 else ""
        tail2 = ".".join(parts[-2:])
        nlast = _norm_token(last)

        # ---- things that are meaningful even inside another call --------- #
        if self.rule_pqc(c, res, parts, via):
            return
        if last == "set_ciphers":
            self.rule_set_ciphers(c)
            return

        if c.consumed:
            return
        if not via and nlast not in _UNAMBIGUOUS:
            return

        # ---- asymmetric key generation ----------------------------------- #
        if tail2 == "rsa.generate_private_key" or (
            last == "generate_private_key" and "rsa" in parts
        ):
            bits, conf = self.int_of(self.pick(c, ("key_size", "bits"), 1))
            exp, _ = self.int_of(self.pick(c, ("public_exponent",), 0))
            extra: dict[str, Any] = {"api": "cryptography"}
            if exp is not None:
                extra["public_exponent"] = exp
            self.emit("RSA", _sized("RSA", bits), c.line, c.text,
                      key_size=bits, extra=extra, confidence=conf)
            return

        if last == "generate" and prev == "rsa":
            bits, conf = self.int_of(self.pick(c, ("bits",), 0))
            self.emit("RSA", _sized("RSA", bits), c.line, c.text,
                      key_size=bits, extra={"api": "pycryptodome"}, confidence=conf)
            return

        if tail2 == "rsa.newkeys":
            bits, conf = self.int_of(self.pick(c, ("nbits",), 0))
            self.emit("RSA", _sized("RSA", bits), c.line, c.text,
                      key_size=bits, extra={"api": "rsa"}, confidence=conf)
            return

        if tail2 == "dsa.generate_private_key" or (last == "generate" and prev == "dsa"):
            bits, conf = self.int_of(self.pick(c, ("key_size", "bits"), 0))
            self.emit("DSA", _sized("DSA", bits), c.line, c.text,
                      key_size=bits, extra={"usage": "signature"}, confidence=conf)
            return

        if tail2 == "dh.generate_parameters" or (
            last == "generate_parameters" and "dh" in parts
        ):
            bits, conf = self.int_of(self.pick(c, ("key_size",), 1))
            gen, _ = self.int_of(self.pick(c, ("generator",), 0))
            extra = {"usage": "key agreement"}
            if gen is not None:
                extra["generator"] = gen
            self.emit("DH", _sized("DH", bits), c.line, c.text,
                      key_size=bits, extra=extra, confidence=conf)
            return

        if tail2 in ("ec.generate_private_key", "ec.derive_private_key") or (
            last in ("generate_private_key", "derive_private_key") and "ec" in parts
        ):
            idx = 0 if last == "generate_private_key" else 1
            curve, bits, conf = self.curve_of(self.pick(c, ("curve",), idx))
            self.emit("ECDSA", _curved("ECDSA", curve), c.line, c.text,
                      key_size=bits, curve=curve,
                      extra={"api": "cryptography"}, confidence=conf)
            return

        if last == "generate" and prev == "ecc":
            curve, bits, conf = self.curve_of(self.pick(c, ("curve",), 0))
            self.emit("ECDSA", _curved("ECDSA", curve), c.line, c.text,
                      key_size=bits, curve=curve,
                      extra={"api": "pycryptodome"}, confidence=conf)
            return

        if last == "ecdh" or tail2 == "ec.ecdh":
            self.emit("ECDH", "ECDH", c.line, c.text,
                      extra={"usage": "key agreement"}, confidence="medium")
            return

        if last == "ecdsa" and prev == "ec":
            _, hname, _hconf = self.hash_of(self.pick(c, ("algorithm",), 0))
            extra = {"usage": "signature"}
            if hname:
                extra["hash"] = hname
            self.emit("ECDSA", "ECDSA", c.line, c.text, extra=extra, confidence="medium")
            return

        # ---- curve classes used stand-alone ------------------------------ #
        if nlast in _CURVES or last in _CURVES:
            hit = _CURVES.get(last) or _CURVES[nlast]
            self.emit("ECDSA", _curved("ECDSA", hit[0]), c.line, c.text,
                      key_size=hit[1], curve=hit[0], confidence="medium")
            return

        # ---- Edwards / Montgomery keys ----------------------------------- #
        edx = _edx_family(parts)
        if edx:
            fam, bits = edx
            usage = "signature" if fam.startswith("Ed") else "key agreement"
            self.emit(fam, fam, c.line, c.text, key_size=bits, extra={"usage": usage})
            return
        if tail2 in ("signing.signingkey", "signing.verifykey") or (
            last in ("signingkey", "verifykey") and "nacl" in parts
        ):
            self.emit("Ed25519", "Ed25519", c.line, c.text, key_size=256,
                      extra={"api": "PyNaCl", "usage": "signature"})
            return
        if "nacl" in parts and last in ("privatekey", "publickey", "box"):
            self.emit("X25519", "X25519", c.line, c.text, key_size=256,
                      extra={"api": "PyNaCl", "usage": "key agreement"})
            return

        # ---- block ciphers ----------------------------------------------- #
        if last == "cipher" and ("ciphers" in parts or "cryptography" in parts or via):
            self.rule_cipher(c)
            return

        if nlast in _AEAD_MODE and (prev in ("aead", "ciphers", "primitives") or via):
            fam, base, bits = _SYM[nlast]
            mode = _AEAD_MODE[nlast]
            ks, _conf = self.int_of(self.pick(c, ("key_size",), None))
            ks = ks if ks is not None else bits
            self.emit(fam, _sym_name(base, ks, mode), c.line, c.text,
                      key_size=ks, mode=mode, extra={"api": "cryptography (AEAD)"})
            return

        if prev == "algorithms" and nlast in _SYM:
            fam, base, bits = _SYM[nlast]
            self.emit(fam, _sym_name(base, bits, None), c.line, c.text, key_size=bits,
                      confidence="medium")
            return

        if last == "new" and prev in _PYCRYPTO_CIPHERS:
            self.rule_pycrypto_cipher(c, prev)
            return

        # ---- hashes ------------------------------------------------------ #
        if prev == "hashlib" and nlast in _HASHES:
            fam, name = _HASHES[nlast]
            extra = {"api": "hashlib"}
            ufs = c.kwargs.get("usedforsecurity")
            if ufs is not None:
                extra["usedforsecurity"] = ufs.text
            self.emit_hash(fam, name, c.line, c.text, extra=extra,
                           digest_bits=self.digest_bits(c, name))
            return
        if tail2 == "hashlib.new":
            token, conf = self.str_of(self.pick(c, ("name",), 0))
            if token and not c.in_message:
                hit = _HASHES.get(token.lower()) or _HASHES.get(_norm_token(token))
                if hit:
                    self.emit_hash(hit[0], hit[1], c.line, c.text,
                                   extra={"api": "hashlib.new"}, confidence=conf,
                                   digest_bits=self.digest_bits(c, hit[1]))
            return
        if prev == "hashes" and nlast in _HASHES:
            fam, name = _HASHES[nlast]
            self.emit_hash(fam, name, c.line, c.text, extra={"api": "cryptography"},
                           digest_bits=self.digest_bits(c, name, index=0))
            return
        if last in ("blake2b", "blake2s"):
            fam, name = _HASHES[nlast]
            self.emit_hash(fam, name, c.line, c.text, confidence="medium",
                           digest_bits=self.digest_bits(c, name))
            return
        if last == "new" and prev in _PYCRYPTO_HASH_MODULES and nlast != "cmac":
            hit = _HASHES.get(prev) or _HASHES.get(_norm_token(prev))
            if hit:
                self.emit_hash(hit[0], hit[1], c.line, c.text,
                               extra={"api": "pycryptodome"},
                               digest_bits=self.digest_bits(c, hit[1]))
                return

        # ---- HMAC / KDF -------------------------------------------------- #
        if tail2 == "hmac.new" or (last == "new" and prev == "hmac"):
            _, name, conf = self.hash_of(self.pick(c, ("digestmod", "digest_module"), 2))
            self.rule_emit_hmac(c, name, conf)
            return
        if last == "hmac" and prev == "hmac":
            _, name, conf = self.hash_of(self.pick(c, ("algorithm",), 1))
            self.rule_emit_hmac(c, name, conf)
            return
        if tail2 == "hashlib.pbkdf2_hmac":
            token, conf = self.str_of(self.pick(c, ("hash_name",), 0))
            iters, _ = self.int_of(self.pick(c, ("iterations",), 3))
            hit = _HASHES.get((token or "").lower()) if token else None
            extra = {"api": "hashlib", "usage": "kdf"}
            if hit:
                extra["hash"] = hit[1]
            if iters is not None:
                extra["iterations"] = iters
            self.emit("PBKDF2", f"PBKDF2-HMAC-{hit[1]}" if hit else "PBKDF2",
                      c.line, c.text, extra=extra, confidence=conf)
            return
        if nlast == "pbkdf2hmac" or tail2 == "kdf.pbkdf2" or last == "pbkdf2":
            _, name, conf = self.hash_of(self.pick(c, ("algorithm", "hmac_hash_module"), 0))
            iters, _ = self.int_of(self.pick(c, ("iterations", "count"), None))
            extra = {"usage": "kdf"}
            if name:
                extra["hash"] = name
            if iters is not None:
                extra["iterations"] = iters
            self.emit("PBKDF2", f"PBKDF2-HMAC-{name}" if name else "PBKDF2",
                      c.line, c.text, extra=extra, confidence=conf if name else "medium")
            return
        if nlast in ("hkdf", "hkdfexpand"):
            _, name, conf = self.hash_of(self.pick(c, ("algorithm",), 0))
            extra = {"usage": "kdf"}
            if name:
                extra["hash"] = name
            self.emit("HKDF", f"HKDF-{name}" if name else "HKDF", c.line, c.text,
                      extra=extra, confidence=conf if name else "medium")
            return
        if nlast == "scrypt":
            self.emit("Scrypt", "scrypt", c.line, c.text, extra={"usage": "kdf"})
            return
        if nlast in ("passwordhasher", "hash_secret", "hash_secret_raw"):
            self.emit("Argon2", "Argon2", c.line, c.text, extra={"usage": "kdf"},
                      confidence="medium")
            return

        # ---- RSA padding ------------------------------------------------- #
        if nlast in ("pkcs1v15", "oaep", "pss") and (
            prev == "padding" or "asymmetric" in parts or nlast in ("pkcs1v15", "pss")
        ):
            pad = {"pkcs1v15": "PKCS1v15", "oaep": "OAEP", "pss": "PSS"}[nlast]
            extra = {"api": "cryptography"}
            if nlast == "oaep":
                _, name, _c = self.hash_of(self.pick(c, ("algorithm",), None))
                if name:
                    extra["hash"] = name
                extra["usage"] = "encryption"
            elif nlast == "pss":
                extra["usage"] = "signature"
            self.emit("RSA", f"RSA-{pad}", c.line, c.text, padding=pad, extra=extra)
            return
        if last == "new" and prev in ("pkcs1_15", "pkcs1_v1_5", "pkcs1_oaep", "pss"):
            pad = {"pkcs1_15": "PKCS1v15", "pkcs1_v1_5": "PKCS1v15",
                   "pkcs1_oaep": "OAEP", "pss": "PSS"}[prev]
            extra = {"api": "pycryptodome"}
            if pad == "OAEP":
                extra["usage"] = "encryption"
            elif prev in ("pkcs1_15", "pss"):
                extra["usage"] = "signature"
            self.emit("RSA", f"RSA-{pad}", c.line, c.text, padding=pad, extra=extra)
            return

        # ---- JWT ---------------------------------------------------------- #
        if last in ("encode", "decode") and ("jwt" in parts or "jose" in parts):
            self.rule_jwt(c)
            return

        # ---- TLS ----------------------------------------------------------- #
        if nlast == "sslcontext" or (last == "context" and "ssl" in parts):
            self.rule_ssl_context(c)
            return
        if last == "wrap_socket":
            arg = self.pick(c, ("ssl_version",), None)
            proto = _tls_from_token(arg.name.rsplit(".", 1)[-1]) if (arg and arg.name) else None
            if proto:
                self.emit_tls(proto, c.line, c.text)
            return

    # -- specific call rules ---------------------------------------------- #
    def emit_tls(self, proto: str, line: int, evidence: str,
                 confidence: str = "high") -> None:
        extra: dict[str, Any] = {"protocol": proto}
        ver = _TLS_VERSION_NUMBER.get(proto)
        if ver:
            extra["version"] = ver
        self.emit("TLS", proto, line, evidence, kind="protocol", extra=extra,
                  confidence=confidence)

    def rule_emit_hmac(self, c: _Call, name: Optional[str], conf: str) -> None:
        """Emit an HMAC artefact.

        ``Params.key_size`` is deliberately left unset: for HMAC that field
        would mean the *key* length, and we have not measured one.  The inner
        digest travels in ``extra['hash']`` / ``extra['digest_size']`` so a
        classifier never has to read the key length as if it were a digest.
        """
        extra: dict[str, Any] = {"usage": "mac"}
        if name:
            extra["hash"] = name
            bits = _HASH_BITS.get(name)
            if bits:
                extra["digest_size"] = bits
        self.emit("HMAC", f"HMAC-{name}" if name else "HMAC", c.line, c.text,
                  extra=extra, confidence=conf if name else "medium")

    def rule_cipher(self, c: _Call) -> None:
        alg = self.pick(c, ("algorithm",), 0)
        mod = self.pick(c, ("mode",), 1)

        mode_name: Optional[str] = None
        if mod is not None:
            tok = None
            if mod.call is not None and mod.call.func_dotted:
                tok = mod.call.func_dotted.rsplit(".", 1)[-1]
            elif mod.name:
                tok = mod.name.rsplit(".", 1)[-1]
            if tok:
                mode_name = _MODES.get(tok.lower()) or _MODES.get(_norm_token(tok))

        fam, base, bits = "AES", "AES", None
        conf = "high"
        tok = None
        if alg is not None:
            if alg.call is not None and alg.call.func_dotted:
                tok = alg.call.func_dotted.rsplit(".", 1)[-1]
            elif alg.name:
                tok = alg.name.rsplit(".", 1)[-1]
        hit = _SYM.get((tok or "").lower()) or _SYM.get(_norm_token(tok or ""))
        if hit:
            fam, base, bits = hit
        else:
            conf = "medium"
            if tok is None:
                return
            fam = base = tok.upper()
        # a literal key of known length tightens the key size
        if alg is not None and alg.call is not None and bits is None:
            klen, _ = self.int_of(alg.call.args[0] if alg.call.args else None)
            if klen in (16, 24, 32):
                bits = klen * 8
        self.emit(fam, _sym_name(base, bits, mode_name), c.line, c.text,
                  key_size=bits, mode=mode_name,
                  extra={"api": "cryptography"}, confidence=conf)

    def rule_pycrypto_cipher(self, c: _Call, module: str) -> None:
        fam, base, bits = _SYM[module]
        mode_name: Optional[str] = None
        arg = self.pick(c, ("mode",), 1)
        if arg is not None and arg.name:
            tok = arg.name.rsplit(".", 1)[-1]
            if tok.lower().startswith("mode_"):
                mode_name = _MODES.get(tok[5:].lower()) or tok[5:].upper()
        if module in ("chacha20", "chacha20_poly1305", "salsa20", "arc4"):
            mode_name = mode_name or _AEAD_MODE.get(module)
        key = self.pick(c, ("key",), 0)
        if key is not None and bits is None:
            klen, _ = self.int_of(key)
            if klen in (16, 24, 32):
                bits = klen * 8
        self.emit(fam, _sym_name(base, bits, mode_name), c.line, c.text,
                  key_size=bits, mode=mode_name, extra={"api": "pycryptodome"})

    def rule_jwt(self, c: _Call) -> None:
        if c.in_message:
            return
        tokens: list[str] = []
        one = self.pick(c, ("algorithm",), None)
        if one is not None:
            tokens.extend(self.strings_of(one))
        many = self.pick(c, ("algorithms",), None)
        if many is not None:
            tokens.extend(self.strings_of(many))
        if not tokens and len(c.args) >= 3:
            tokens.extend(self.strings_of(self.take(c.args[2])))
        for tok in tokens:
            spec = _JWT_ALG.get(tok.strip().lower())
            if not spec:
                continue
            extra = dict(spec.get("extra") or {})
            extra["jose_alg"] = tok.strip()
            self.emit(
                spec["family"], spec["name"], c.line, c.text,
                key_size=spec.get("key_size"), curve=spec.get("curve"),
                mode=spec.get("mode"), padding=spec.get("padding"), extra=extra,
            )

    def rule_ssl_context(self, c: _Call) -> None:
        arg = self.pick(c, ("protocol", "method"), 0)
        proto = None
        if arg is not None and arg.name:
            proto = _tls_from_token(arg.name.rsplit(".", 1)[-1])
        if proto:
            self.emit_tls(proto, c.line, c.text)
        else:
            self.emit_tls("TLS (version unspecified)", c.line, c.text,
                          confidence="medium")

    def rule_set_ciphers(self, c: _Call) -> None:
        arg = self.pick(c, ("ciphers", "cipherlist"), 0)
        value, conf = self.str_of(arg)
        if not value or c.in_message:
            return
        for raw in value.split(":"):
            tok = raw.strip()
            if not tok or tok.startswith("!") or tok.startswith("-"):
                continue
            tok = tok.lstrip("+@")
            up = tok.upper()
            if up in ("ALL", "DEFAULT", "COMPLEMENTOFALL", "COMPLEMENTOFDEFAULT",
                      "HIGH", "MEDIUM", "LOW", "EXPORT", "EXPORT40", "EXPORT56",
                      "NULL", "ANULL", "ENULL", "ADH", "AECDH", "RC4", "MD5",
                      "DES", "3DES", "SSLV3", "SSLV2", "TLSV1", "SEED", "IDEA",
                      "PSK", "SRP", "KRB5", "ARIA", "CAMELLIA", "CHACHA20",
                      "AES", "AESGCM", "AESCCM", "ECDH", "ECDHE", "DH", "DHE",
                      "KRSA", "ARSA", "EDH", "TLSV1.2", "TLSV1.3", "SUITEB128",
                      "SUITEB192", "AGOST", "GOST"):
                self.emit("TLS-CipherString", f"OpenSSL:{up}", c.line, c.text,
                          kind="protocol",
                          extra={"openssl_keyword": True, "cipher_string": value},
                          confidence=conf)
                continue
            if len(up) >= 6 and ("-" in up or "_" in up):
                self.emit("TLS-CipherSuite", up, c.line, c.text, kind="protocol",
                          extra=_parse_cipher_suite(up), confidence=conf)

    def rule_pqc(self, c: _Call, res: str, parts: list[str], via: bool) -> bool:
        """Return True when the call was recognised as post-quantum."""
        # liboqs style factories take the mechanism name as a string
        last = parts[-1]
        if last in ("keyencapsulation", "signature", "kem", "sig") or "oqs" in parts:
            arg = c.args[0] if c.args else (
                c.kwargs.get("alg_name") or c.kwargs.get("algorithm"))
            token, conf = self.str_of(arg)
            if token and not c.in_message:
                spec = _pqc_lookup(token, strict=False)
                if spec:
                    self.take(arg)
                    extra = dict(spec["extra"])
                    extra["api"] = "liboqs" if "oqs" in parts else res.split(".")[0]
                    self.emit(spec["family"], spec["name"], c.line, c.text,
                              extra=extra, confidence=conf)
                    return True
        for seg in parts:
            spec = _pqc_lookup(seg, strict=True)
            if spec:
                extra = dict(spec["extra"])
                if via:
                    extra["module"] = res
                self.emit(spec["family"], spec["name"], c.line, c.text,
                          extra=extra, confidence="high" if via else "medium")
                return True
        return False

    # -- reference rules --------------------------------------------------- #
    def rule_ref(self, ref: _Ref) -> None:
        res, via = self.resolve(ref.dotted)
        parts = res.lower().split(".")
        last = parts[-1]
        prev = parts[-2] if len(parts) >= 2 else ""
        nlast = _norm_token(last)

        # TLS protocol constants
        proto = _tls_from_token(last)
        if proto and ("ssl" in parts or "openssl" in parts or prev == "tlsversion" or via):
            self.emit_tls(proto, ref.line, ref.text)
            return
        if prev == "tlsversion":
            name = _TLS_VERSION_ENUM.get(last)
            if name:
                self.emit_tls(name, ref.line, ref.text)
                return

        # post-quantum identifiers
        for seg in parts:
            spec = _pqc_lookup(seg, strict=True)
            if spec:
                self.emit(spec["family"], spec["name"], ref.line, ref.text,
                          extra=dict(spec["extra"]),
                          confidence="high" if via else "medium")
                return

        if not via:
            return

        edx = _edx_family(parts)
        if edx:
            fam, bits = edx
            usage = "signature" if fam.startswith("Ed") else "key agreement"
            self.emit(fam, fam, ref.line, ref.text, key_size=bits,
                      extra={"usage": usage}, confidence="medium")
            return
        if prev in ("hashlib", "hashes") and nlast in _HASHES:
            fam, name = _HASHES[nlast]
            self.emit_hash(fam, name, ref.line, ref.text, confidence="medium")
            return
        if prev == "ec" and (last in _CURVES or nlast in _CURVES):
            hit = _CURVES.get(last) or _CURVES[nlast]
            self.emit("ECDSA", _curved("ECDSA", hit[0]), ref.line, ref.text,
                      key_size=hit[1], curve=hit[0], confidence="medium")
            return
        if prev == "algorithms" and nlast in _SYM:
            fam, base, bits = _SYM[nlast]
            self.emit(fam, _sym_name(base, bits, None), ref.line, ref.text,
                      key_size=bits, confidence="medium")
            return


# --------------------------------------------------------------------------- #
# Naming helpers
# --------------------------------------------------------------------------- #

def _sized(base: str, bits: Optional[int]) -> str:
    return f"{base}-{bits}" if bits else base


def _curved(base: str, curve: Optional[str]) -> str:
    return f"{base}-{curve}" if curve else base


# ciphers whose key length actually varies, so it belongs in the display name
_SIZED_BASES = {"AES", "Camellia", "Blowfish", "RC4", "RC2", "CAST5"}


def _sym_name(base: str, bits: Optional[int], mode: Optional[str]) -> str:
    out = base
    if bits and base in _SIZED_BASES:
        out = f"{out}-{bits}"
    if mode and not out.upper().endswith(mode.upper()):
        out = f"{out}-{mode}"
    return out


def _tls_from_token(token: str) -> Optional[str]:
    return _TLS_CONST.get(token.lower())


def _edx_family(parts: list[str]) -> Optional[tuple[str, int]]:
    """Recognise Ed25519 / Ed448 / X25519 / X448 anywhere in a dotted path."""
    joined = "".join(_norm_token(p) for p in parts)
    for token, fam, bits in (
        ("ed25519", "Ed25519", 256),
        ("ed448", "Ed448", 448),
        ("x25519", "X25519", 256),
        ("x448", "X448", 448),
    ):
        if token in joined:
            return fam, bits
    return None


# --------------------------------------------------------------------------- #
# Artefact aggregation
# --------------------------------------------------------------------------- #

class _Sink:
    """Collects emissions and merges them into unique artefacts."""

    def __init__(self) -> None:
        self._by_key: dict[tuple, Artefact] = {}
        self._seen: dict[tuple, set[tuple]] = {}
        self._order: list[tuple] = []

    def add(
        self,
        *,
        family: str,
        name: str,
        kind: str,
        key_size: Optional[int],
        curve: Optional[str],
        mode: Optional[str],
        padding: Optional[str],
        extra: dict[str, Any],
        occurrence: Occurrence,
    ) -> None:
        key = (family, name, kind, key_size, curve, mode, padding)
        art = self._by_key.get(key)
        if art is None:
            art = Artefact(
                name=name,
                family=family,
                kind=kind,
                params=Params(
                    key_size=key_size,
                    curve=curve,
                    mode=mode,
                    padding=padding,
                    not_after=None,
                    extra=dict(extra),
                ),
                occurrences=[],
            )
            self._by_key[key] = art
            self._seen[key] = set()
            self._order.append(key)
        else:
            _merge_extra(art.params.extra, extra)
        sig = (occurrence.file, occurrence.line, occurrence.evidence)
        if sig in self._seen[key]:
            # keep the strongest confidence we ever saw for this exact site
            for existing in art.occurrences:
                if (existing.file, existing.line, existing.evidence) == sig:
                    if existing.confidence != "high" and occurrence.confidence == "high":
                        existing.confidence = "high"
                    break
            return
        self._seen[key].add(sig)
        art.occurrences.append(occurrence)

    def artefacts(self) -> list[Artefact]:
        out = [self._by_key[k] for k in self._order]
        out.sort(key=lambda a: (a.family.lower(), a.name.lower(),
                                a.params.key_size or 0, len(a.occurrences) * -1))
        for a in out:
            a.occurrences.sort(key=lambda o: (o.file, o.line or 0))
        return out


def _merge_extra(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
            continue
        cur = dst[k]
        if cur == v:
            continue
        if isinstance(cur, list):
            if v not in cur:
                cur.append(v)
        else:
            dst[k] = [cur, v]


# --------------------------------------------------------------------------- #
# Glob matching (delegated to the policy module when it is importable)
# --------------------------------------------------------------------------- #

_GLOB_CACHE: dict[str, "re.Pattern[str]"] = {}


def _compile_glob(pattern: str) -> "re.Pattern[str]":
    """Fallback path-glob compiler with proper ``**`` semantics.

    ``*`` and ``?`` never cross a ``/``; ``**/`` matches zero or more leading
    directories; a trailing ``/**`` matches the directory itself and everything
    under it.  This is the same contract ``app.engine.policy`` implements, and
    it is only used when that module cannot be imported.
    """
    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    p = pattern.replace(os.sep, "/").strip()
    out: list[str] = ["^"]
    i = 0
    n = len(p)
    while i < n:
        ch = p[i]
        if ch == "*":
            if p[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if p[i:i + 3] == "/**":
                out.append("(?:/.*)?")
                i += 3
                continue
            if p[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append("[^/]")
            i += 1
            continue
        if ch == "[":
            close = p.find("]", i + 1)
            if close > i + 1:
                body = p[i + 1:close]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = close + 1
                continue
        out.append(re.escape(ch))
        i += 1
    out.append("$")
    rx = re.compile("".join(out))
    _GLOB_CACHE[pattern] = rx
    return rx


def _fallback_glob_match(path: str, pattern: str) -> bool:
    return bool(_compile_glob(pattern).match(path.replace(os.sep, "/")))


def _select_glob_matcher() -> Callable[[str, str], bool]:
    """Prefer the engine's own matcher, but only if it behaves as documented."""
    fn = _engine_glob_match
    if fn is None:
        return _fallback_glob_match
    try:
        ok = (
            fn("node_modules/x.js", "**/node_modules/**")
            and fn("a/b/node_modules/x.js", "**/node_modules/**")
            and not fn("src/monkeys/a.py", "**/keys/**")
        )
    except Exception:
        return _fallback_glob_match
    return fn if ok else _fallback_glob_match


_glob_match: Callable[[str, str], bool] = _select_glob_matcher()


def _matches(rel: str, patterns: Iterable[str]) -> bool:
    posix = rel.replace(os.sep, "/")
    base = posix.rsplit("/", 1)[-1]
    for pat in patterns:
        p = str(pat).replace(os.sep, "/").strip()
        if not p:
            continue
        if p.endswith("/"):
            p = p[:-1] + "/**"
        if _glob_match(posix, p):
            return True
        # a bare name ("build", "*.min.py") matches at any depth
        if "/" not in p:
            if _glob_match(base, p) or _glob_match(posix, f"**/{p}"):
                return True
        elif _glob_match(posix, f"**/{p}"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Policy handling
# --------------------------------------------------------------------------- #

_EXCLUDE_KEYS = (
    "ignore_paths", "exclude", "excludes", "exclude_globs", "exclude_paths",
    "ignore", "ignores", "ignore_globs", "skip",
)
_INCLUDE_KEYS = ("include", "includes", "include_globs", "include_paths")


def _policy_get(policy: Any, names: Iterable[str], default: Any = None) -> Any:
    """Read a value out of a policy object, mapping or ``.get()`` provider."""
    if policy is None:
        return default
    data = getattr(policy, "data", None)
    for name in names:
        try:
            if isinstance(policy, dict):
                if name in policy:
                    return policy[name]
                continue
            if isinstance(data, dict) and name in data:
                return data[name]
            val = getattr(policy, name, None)
            if val is not None and not callable(val):
                return val
            getter = getattr(policy, "get", None)
            if callable(getter):
                got = getter(name)
                if got is not None:
                    return got
        except Exception:
            continue
    return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k in value.keys()]
    try:
        return [str(v) for v in value]
    except TypeError:
        return []


class _Exclusions:
    """Decides which paths the policy wants skipped.

    A real :class:`app.engine.policy.Policy` keeps its globs behind
    ``is_ignored()``; a plain mapping keeps them under one of a handful of key
    names.  Both are supported, and both are consulted -- an object may expose
    ``is_ignored`` *and* carry readable keys.
    """

    def __init__(self, policy: Any) -> None:
        self.is_ignored: Optional[Callable[[str], bool]] = None
        fn = getattr(policy, "is_ignored", None)
        if callable(fn):
            self.is_ignored = fn
        self.excludes = _as_list(_policy_get(policy, _EXCLUDE_KEYS))
        self.includes = _as_list(_policy_get(policy, _INCLUDE_KEYS))

    def _policy_says_ignore(self, rel: str) -> bool:
        if self.is_ignored is None:
            return False
        try:
            return bool(self.is_ignored(rel))
        except Exception:
            return False

    def file_excluded(self, rel: str) -> bool:
        if self._policy_says_ignore(rel):
            return True
        if self.excludes and _matches(rel, self.excludes):
            return True
        if self.includes and not _matches(rel, self.includes):
            return True
        return False

    def dir_pruned(self, rel: str) -> bool:
        """Prune a whole directory only when we are sure everything under it goes.

        When in doubt we descend and let :meth:`file_excluded` decide per file,
        which is slower but never drops a file the policy wanted scanned.
        """
        if self._policy_says_ignore(rel) or self._policy_says_ignore(rel + "/"):
            return True
        if self.excludes and _matches(rel, self.excludes):
            return True
        return False


# --------------------------------------------------------------------------- #
# File walking
# --------------------------------------------------------------------------- #

def _iter_files(root: str, ex: _Exclusions,
                follow_symlinks: bool) -> Iterator[tuple[str, str]]:
    if os.path.isfile(root):
        rel = os.path.basename(root)
        if root.lower().endswith(FILE_EXTS) and not ex.file_excluded(rel):
            yield root, rel
        return
    seen_dirs: set[tuple[int, int]] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        if follow_symlinks:
            # cheap symlink-loop guard
            try:
                st = os.stat(dirpath)
                ident = (st.st_dev, st.st_ino)
                if ident in seen_dirs:
                    dirnames[:] = []
                    continue
                seen_dirs.add(ident)
            except OSError:
                pass
        pruned = []
        for d in dirnames:
            if d in _SKIP_DIRS or d.startswith("."):
                continue
            rel_dir = os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/")
            if ex.dir_pruned(rel_dir):
                continue
            pruned.append(d)
        dirnames[:] = pruned
        for fn in filenames:
            if not fn.lower().endswith(FILE_EXTS):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if ex.file_excluded(rel):
                continue
            yield full, rel


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def detect(root_path: str, policy: Any = None) -> tuple[list[Artefact], int, list[str]]:
    """Scan ``root_path`` for cryptographic usage in Python source files.

    Returns ``(artefacts, files_scanned, errors)``.  Never raises: every
    per-file failure is captured in ``errors``.  ``Occurrence.file`` is always
    a POSIX path relative to ``root_path``.
    """
    errors: list[str] = []
    sink = _Sink()
    files_scanned = 0

    root = os.path.abspath(os.path.expanduser(str(root_path)))
    if not os.path.exists(root):
        return [], 0, [f"{root_path}: path does not exist"]

    ex = _Exclusions(policy)
    max_bytes = _policy_get(policy, ("max_file_bytes", "max_file_size", "max_bytes"),
                            _DEFAULT_MAX_BYTES)
    try:
        max_bytes = int(max_bytes)
    except Exception:
        max_bytes = _DEFAULT_MAX_BYTES
    follow_symlinks = bool(_policy_get(policy, ("follow_symlinks",), False))

    use_ts = _ts_parser() is not None
    if not use_ts and _TS_STATE.get("error"):
        errors.append(
            f"{DETECTOR}: tree-sitter unavailable ({_TS_STATE['error']}); "
            "falling back to the built-in ast parser"
        )

    for full, rel in _iter_files(root, ex, follow_symlinks):
        try:
            size = os.path.getsize(full)
        except OSError as exc:
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue
        if max_bytes and size > max_bytes:
            errors.append(f"{rel}: skipped, {size} bytes exceeds limit {max_bytes}")
            continue
        try:
            with open(full, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue

        unit = _Unit(path=full, rel=rel)
        parsed = False
        broken = False
        exhausted = False
        if use_ts:
            try:
                parsed, broken = _parse_tree_sitter(unit, data)
            except RecursionError:
                exhausted = True
                unit = _Unit(path=full, rel=rel)
                parsed = False
            except Exception as exc:
                errors.append(
                    f"{rel}: tree-sitter parse failed: {type(exc).__name__}: {exc}"
                )
                unit = _Unit(path=full, rel=rel)
                parsed = False
        if not parsed or broken:
            # Either tree-sitter is unavailable, or it recovered from syntax
            # errors.  CPython's own parser is the authority on whether the
            # file is really malformed: if it parses, the tree-sitter grammar
            # simply predates this syntax and we use the ast result instead of
            # crying wolf; if it does not, we report a precise SyntaxError.
            fresh = _Unit(path=full, rel=rel)
            try:
                _parse_ast(fresh, data)
                unit = fresh
                parsed = True
                exhausted = False
            except RecursionError:
                exhausted = True
                if not parsed:
                    unit = _Unit(path=full, rel=rel)
            except SyntaxError as exc:
                if parsed:
                    errors.append(
                        f"{rel}: SyntaxError: {exc.msg} (line {exc.lineno}); "
                        "reporting partial results from error-tolerant parse"
                    )
                else:
                    errors.append(f"{rel}: SyntaxError: {exc.msg} (line {exc.lineno})")
            except MemoryError as exc:
                if not parsed:
                    errors.append(f"{rel}: {type(exc).__name__}: {exc}")
            except Exception as exc:
                if not parsed:
                    errors.append(f"{rel}: {type(exc).__name__}: {exc}")
        if exhausted and not parsed:
            errors.append(
                f"{rel}: skipped, expression nesting exceeds the interpreter's "
                "recursion limit (generated, minified or machine-written source); "
                "no artefacts were collected from this file"
            )
        if not parsed:
            continue

        files_scanned += 1
        try:
            _Analyzer(unit, sink).run()
        except RecursionError:
            errors.append(
                f"{rel}: analysis stopped, expression nesting exceeds the "
                "interpreter's recursion limit; results for this file are partial"
            )
        except Exception as exc:  # defensive: analysis must never kill the scan
            errors.append(f"{rel}: analysis failed: {type(exc).__name__}: {exc}")

    return sink.artefacts(), files_scanned, errors


__all__ = ["FILE_EXTS", "DETECTOR", "detect"]
