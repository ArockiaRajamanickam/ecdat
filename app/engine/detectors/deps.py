"""Dependency-manifest detector for ECDAT.

Source scanning only sees the crypto a project *writes*.  A very large share of
real cryptography is *inherited*: an application that never types the word "RSA"
still ships RSA because it depends on ``node-forge`` or ``bcprov-jdk15on``.
This detector reads the manifests and reports those inherited assets.

Supported manifests
-------------------
    requirements*.txt / constraints*.txt   (pip)
    pyproject.toml / Pipfile               (PEP 621, poetry, pipenv)
    package.json                           (npm / yarn / pnpm)
    pom.xml                                (maven, with ${property} resolution)
    build.gradle / build.gradle.kts        (gradle)
    go.mod                                 (go modules)
    Cargo.toml                             (rust)

Artefact shape
--------------
Every hit is an ``Artefact`` with ``kind="library"``.  ``family`` is the
canonical *library* identity (e.g. "BouncyCastle", "liboqs"), not an algorithm
family, because one library provides many algorithms.  The risk engine should
therefore read these two ``params.extra`` fields:

    extra["threat_hint"]  one of the Threat values, the library's dominant
                          quantum posture ("shor_broken", "pqc", ...)
    extra["algorithms"]   the algorithm families the library provides

``params.extra["version"]`` holds the version exactly as declared, and
``extra["version_parsed"]`` the numeric tuple used for advisory comparison.
Weak defaults and known advisories are appended to the occurrence evidence.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

try:  # package-relative first (normal case)
    from ..models import Artefact, Occurrence, Params
except ImportError:  # pragma: no cover - standalone / script execution
    from app.engine.models import Artefact, Occurrence, Params  # type: ignore


NAME = "deps"
DETECTOR = "deps"

MAX_BYTES = 4 * 1024 * 1024

#: exact filenames this detector claims
FILE_NAMES: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "pipfile",
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "cargo.toml",
        "setup.py",
    }
)

#: regexes for filenames with variable parts (requirements-dev.txt, ...)
FILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^requirements[\w.\-]*\.txt$"),
    re.compile(r"^constraints[\w.\-]*\.txt$"),
    re.compile(r"^requirements[\w.\-]*\.in$"),
)


# --------------------------------------------------------------------------- #
# knowledge base
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LibInfo:
    """One crypto-relevant package."""

    display: str
    family: str
    category: str  # asymmetric | symmetric | hash | tls | ssh | jwt | pqc | password | general
    algorithms: tuple[str, ...]
    threat_hint: str  # shor_broken | legacy_broken | grover_weakened | quantum_safe | pqc | unknown
    note: str = ""  # weak default / posture, always reported
    min_safe: Optional[str] = None  # advisory floor
    advisory: str = ""  # text used when version < min_safe (or always, if no floor)


def _L(*args: Any, **kw: Any) -> LibInfo:
    return LibInfo(*args, **kw)


# --- Python ---------------------------------------------------------------- #
PYTHON_LIBS: dict[str, LibInfo] = {
    "cryptography": _L(
        "cryptography", "OpenSSL", "general",
        ("RSA", "ECDSA", "Ed25519", "X25519", "AES", "SHA-2", "DH"),
        "shor_broken",
        "Broad primitive surface: RSA/ECDSA defaults are Shor-breakable; "
        "no PQC KEM/signature support in the stable API.",
        min_safe="42.0.0",
        advisory="Versions below 42.0.0 bundle OpenSSL builds with known CVEs.",
    ),
    "pycryptodome": _L(
        "pycryptodome", "PyCryptodome", "general",
        ("RSA", "DSA", "ECDSA", "AES", "SHA-2", "3DES"),
        "shor_broken",
        "Exposes ECB mode and PKCS#1 v1.5 as first-class APIs; both are common "
        "misuse sinks. No PQC support.",
    ),
    "pycryptodomex": _L(
        "pycryptodomex", "PyCryptodome", "general",
        ("RSA", "DSA", "ECDSA", "AES", "SHA-2", "3DES"),
        "shor_broken",
        "Exposes ECB mode and PKCS#1 v1.5 as first-class APIs. No PQC support.",
    ),
    "pycrypto": _L(
        "pycrypto", "PyCrypto", "general",
        ("RSA", "DSA", "AES", "3DES", "SHA-1"),
        "legacy_broken",
        "ABANDONED since 2014 and never PQC-capable.",
        advisory="CVE-2013-7459 (heap overflow in ALGnew). Replace with pycryptodome.",
    ),
    "pyopenssl": _L(
        "pyOpenSSL", "OpenSSL", "tls",
        ("RSA", "ECDSA", "TLS", "X.509"),
        "shor_broken",
        "TLS/X.509 surface; key exchange and certificate signatures are "
        "classical and Shor-breakable.",
        min_safe="22.0.0",
        advisory="Pre-22.0.0 releases predate several OpenSSL binding fixes.",
    ),
    "rsa": _L(
        "rsa", "python-rsa", "asymmetric",
        ("RSA",),
        "shor_broken",
        "Pure-Python RSA. Defaults to PKCS#1 v1.5; not constant-time.",
        min_safe="4.7",
        advisory="CVE-2020-25658 (Bleichenbacher timing oracle) fixed in 4.7.",
    ),
    "ecdsa": _L(
        "ecdsa", "python-ecdsa", "asymmetric",
        ("ECDSA", "ECDH"),
        "shor_broken",
        "Pure-Python ECDSA; the maintainers state it is NOT side-channel "
        "resistant. Shor-breakable.",
        advisory="CVE-2024-23342 (Minerva timing attack) has no upstream fix; "
                 "prefer 'cryptography'.",
    ),
    "paramiko": _L(
        "paramiko", "Paramiko", "ssh",
        ("RSA", "ECDSA", "Ed25519", "DH", "AES", "SSH"),
        "shor_broken",
        "SSH transport: classical DH/ECDH key exchange, no PQC KEX.",
        min_safe="2.10.1",
        advisory="CVE-2022-24302 (private-key write race) fixed in 2.10.1.",
    ),
    "pynacl": _L(
        "PyNaCl", "libsodium", "general",
        ("X25519", "Ed25519", "XSalsa20-Poly1305", "BLAKE2"),
        "shor_broken",
        "libsodium bindings. Symmetric side is Grover-tolerant, but X25519/"
        "Ed25519 are Shor-breakable.",
    ),
    "nacl": _L(
        "PyNaCl", "libsodium", "general",
        ("X25519", "Ed25519", "XSalsa20-Poly1305"),
        "shor_broken",
        "libsodium bindings; X25519/Ed25519 are Shor-breakable.",
    ),
    "m2crypto": _L(
        "M2Crypto", "OpenSSL", "tls",
        ("RSA", "DSA", "ECDSA", "AES", "TLS"),
        "shor_broken",
        "Legacy OpenSSL bindings; sparsely maintained.",
    ),
    "pyjwt": _L(
        "PyJWT", "PyJWT", "jwt",
        ("HMAC", "RSA", "ECDSA"),
        "shor_broken",
        "JWT signing. RS256/ES256 keys are Shor-breakable; HS256 secrets are "
        "Grover-weakened.",
        min_safe="2.4.0",
        advisory="CVE-2022-29217 (algorithm confusion) fixed in 2.4.0.",
    ),
    "python-jose": _L(
        "python-jose", "python-jose", "jwt",
        ("HMAC", "RSA", "ECDSA", "AES"),
        "shor_broken",
        "JOSE/JWT implementation.",
        min_safe="3.4.0",
        advisory="CVE-2024-33663 (algorithm confusion, ECDSA/HMAC) fixed in 3.4.0.",
    ),
    "jwcrypto": _L(
        "jwcrypto", "jwcrypto", "jwt",
        ("HMAC", "RSA", "ECDSA", "AES"),
        "shor_broken",
        "JWE/JWS implementation; RSA-OAEP and ECDH-ES are Shor-breakable.",
    ),
    "authlib": _L(
        "Authlib", "Authlib", "jwt",
        ("RSA", "ECDSA", "HMAC", "TLS"),
        "shor_broken",
        "OAuth/OIDC stack; JWT signing keys are classical.",
        min_safe="1.3.1",
        advisory="CVE-2024-37568 (JWS algorithm confusion) fixed in 1.3.1.",
    ),
    "bcrypt": _L(
        "bcrypt", "bcrypt", "password",
        ("bcrypt",),
        "quantum_safe",
        "Password hashing, not encryption. Silently truncates inputs at 72 bytes.",
    ),
    "passlib": _L(
        "passlib", "passlib", "password",
        ("bcrypt", "PBKDF2", "argon2", "MD5-crypt"),
        "quantum_safe",
        "Ships legacy schemes (md5_crypt, des_crypt); check the configured "
        "CryptContext, not just the dependency.",
    ),
    "argon2-cffi": _L(
        "argon2-cffi", "argon2", "password", ("Argon2",), "quantum_safe",
        "Memory-hard password hashing; current best practice.",
    ),
    "python-gnupg": _L(
        "python-gnupg", "GnuPG", "general",
        ("RSA", "ElGamal", "AES", "Ed25519"),
        "shor_broken",
        "OpenPGP keys are RSA/ElGamal/ECC by default: all Shor-breakable.",
    ),
    "pgpy": _L(
        "PGPy", "OpenPGP", "general", ("RSA", "DSA", "ElGamal", "AES"),
        "shor_broken", "Pure-Python OpenPGP; classical asymmetric only.",
    ),
    "certifi": _L(
        "certifi", "X.509", "tls", ("X.509", "RSA", "ECDSA"), "shor_broken",
        "Bundled CA roots: RSA/ECDSA trust anchors that must be re-issued for "
        "a PQC PKI.",
    ),
    "pyspx": _L(
        "PySPX", "SPHINCS+", "pqc", ("SLH-DSA",), "pqc",
        "SPHINCS+/SLH-DSA bindings: hash-based, quantum-safe signatures.",
    ),
    "oqs": _L(
        "liboqs-python", "liboqs", "pqc",
        ("ML-KEM", "ML-DSA", "Falcon", "SLH-DSA", "HQC", "BIKE"),
        "pqc",
        "Open Quantum Safe bindings. NOTE: liboqs is explicitly a research "
        "library, not vetted for production key management.",
    ),
    "liboqs-python": _L(
        "liboqs-python", "liboqs", "pqc",
        ("ML-KEM", "ML-DSA", "Falcon", "SLH-DSA"),
        "pqc",
        "Open Quantum Safe bindings; research-grade, not production-vetted.",
    ),
    "pqcrypto": _L(
        "pqcrypto", "PQClean", "pqc",
        ("ML-KEM", "ML-DSA", "Falcon", "SLH-DSA", "HQC"),
        "pqc",
        "PQClean bindings; quantum-safe primitives.",
    ),
    "quantcrypt": _L(
        "QuantCrypt", "PQClean", "pqc", ("ML-KEM", "ML-DSA", "SLH-DSA"),
        "pqc", "PQC primitives over PQClean.",
    ),
    "kyber-py": _L(
        "kyber-py", "ML-KEM", "pqc", ("ML-KEM",), "pqc",
        "Pure-Python Kyber/ML-KEM; reference/teaching code, not constant-time.",
    ),
    "dilithium-py": _L(
        "dilithium-py", "ML-DSA", "pqc", ("ML-DSA",), "pqc",
        "Pure-Python Dilithium/ML-DSA; reference code, not constant-time.",
    ),
    "sslyze": _L(
        "SSLyze", "TLS", "tls", ("TLS",), "unknown",
        "TLS analysis tooling; indicates TLS posture is already being measured.",
    ),
    "requests": _L(
        "requests", "TLS", "tls", ("TLS", "X.509"), "shor_broken",
        "HTTPS client: every outbound TLS session uses a classical, "
        "harvest-now-decrypt-later-exposed handshake.",
    ),
    "urllib3": _L(
        "urllib3", "TLS", "tls", ("TLS", "X.509"), "shor_broken",
        "HTTPS transport; classical TLS handshake.",
    ),
}

# --- Node / npm ------------------------------------------------------------ #
NODE_LIBS: dict[str, LibInfo] = {
    "node-forge": _L(
        "node-forge", "node-forge", "general",
        ("RSA", "AES", "SHA-1", "X.509", "TLS"),
        "shor_broken",
        "Pure-JS TLS/PKI stack. Ships RSA PKCS#1 v1.5, DES and MD5 helpers.",
        min_safe="1.3.0",
        advisory="CVE-2022-24771/24772/24773 (RSA PKCS#1 v1.5 signature "
                 "forgery) fixed in 1.3.0.",
    ),
    "crypto-js": _L(
        "crypto-js", "crypto-js", "symmetric",
        ("AES", "3DES", "RC4", "MD5", "SHA-1"),
        "grover_weakened",
        "WEAK DEFAULTS: string passphrases go through an MD5-based "
        "EVP_BytesToKey KDF, and the default mode is CBC with no "
        "authentication.",
        min_safe="4.2.0",
        advisory="CVE-2023-46233 (PBKDF2 defaulted to 1 iteration of SHA-1) "
                 "fixed in 4.2.0.",
    ),
    "elliptic": _L(
        "elliptic", "elliptic", "asymmetric",
        ("ECDSA", "EdDSA", "ECDH"),
        "shor_broken",
        "Pure-JS elliptic curve library; Shor-breakable.",
        min_safe="6.5.7",
        advisory="CVE-2024-42459/42460/42461 (EDDSA/ECDSA signature "
                 "malleability) fixed in 6.5.7.",
    ),
    "jsonwebtoken": _L(
        "jsonwebtoken", "jsonwebtoken", "jwt",
        ("HMAC", "RSA", "ECDSA"),
        "shor_broken",
        "JWT signing; RS256/ES256 keys are Shor-breakable.",
        min_safe="9.0.0",
        advisory="CVE-2022-23529/23539/23540/23541 (key confusion, insecure "
                 "default algorithms) fixed in 9.0.0.",
    ),
    "jose": _L(
        "jose", "jose", "jwt", ("RSA", "ECDSA", "Ed25519", "AES", "HMAC"),
        "shor_broken", "JOSE implementation; classical asymmetric algorithms.",
    ),
    "jsrsasign": _L(
        "jsrsasign", "jsrsasign", "general",
        ("RSA", "ECDSA", "X.509", "SHA-1"),
        "shor_broken",
        "RSA/X.509 in pure JS; historically permissive about weak algorithms.",
        min_safe="11.0.0",
        advisory="CVE-2024-21484 (prototype pollution) fixed in 11.0.0.",
    ),
    "sjcl": _L(
        "sjcl", "SJCL", "symmetric", ("AES", "PBKDF2", "SHA-2"),
        "grover_weakened",
        "Stanford JS Crypto Library; effectively unmaintained since 2019.",
    ),
    "bcryptjs": _L(
        "bcryptjs", "bcrypt", "password", ("bcrypt",), "quantum_safe",
        "Pure-JS bcrypt; slower than the native binding and truncates at 72 bytes.",
    ),
    "bcrypt": _L(
        "bcrypt", "bcrypt", "password", ("bcrypt",), "quantum_safe",
        "Native bcrypt binding; truncates inputs at 72 bytes.",
    ),
    "tweetnacl": _L(
        "TweetNaCl.js", "NaCl", "general",
        ("X25519", "Ed25519", "XSalsa20-Poly1305"),
        "shor_broken",
        "X25519/Ed25519 are Shor-breakable; the library is in maintenance mode.",
    ),
    "libsodium": _L(
        "libsodium", "libsodium", "general",
        ("X25519", "Ed25519", "XChaCha20-Poly1305", "Argon2"),
        "shor_broken",
        "Modern classical crypto; the asymmetric half is Shor-breakable.",
    ),
    "libsodium-wrappers": _L(
        "libsodium-wrappers", "libsodium", "general",
        ("X25519", "Ed25519", "XChaCha20-Poly1305", "Argon2"),
        "shor_broken", "libsodium (wasm); asymmetric half is Shor-breakable.",
    ),
    "@noble/curves": _L(
        "@noble/curves", "noble", "asymmetric",
        ("ECDSA", "Ed25519", "X25519", "BLS12-381"),
        "shor_broken",
        "Audited, constant-time elliptic curves - but still Shor-breakable.",
    ),
    "@noble/hashes": _L(
        "@noble/hashes", "noble", "hash",
        ("SHA-2", "SHA-3", "BLAKE2", "HMAC"),
        "grover_weakened", "Audited hash primitives.",
    ),
    "@noble/post-quantum": _L(
        "@noble/post-quantum", "noble", "pqc",
        ("ML-KEM", "ML-DSA", "SLH-DSA"),
        "pqc",
        "Audited JS implementation of the NIST PQC standards.",
    ),
    "@peculiar/webcrypto": _L(
        "@peculiar/webcrypto", "WebCrypto", "general",
        ("RSA", "ECDSA", "AES", "SHA-2"), "shor_broken",
        "WebCrypto polyfill; classical algorithm set.",
    ),
    "md5": _L(
        "md5", "MD5", "hash", ("MD5",), "legacy_broken",
        "MD5 is collision-broken; unusable for any security purpose.",
    ),
    "js-md5": _L(
        "js-md5", "MD5", "hash", ("MD5",), "legacy_broken",
        "MD5 is collision-broken.",
    ),
    "sha1": _L(
        "sha1", "SHA-1", "hash", ("SHA-1",), "legacy_broken",
        "SHA-1 is collision-broken (SHAttered, 2017).",
    ),
    "js-sha1": _L(
        "js-sha1", "SHA-1", "hash", ("SHA-1",), "legacy_broken",
        "SHA-1 is collision-broken.",
    ),
    "aes-js": _L(
        "aes-js", "AES", "symmetric", ("AES",), "grover_weakened",
        "Raw AES modes with no AEAD; ECB and CTR are exposed directly.",
    ),
    "node-rsa": _L(
        "node-rsa", "node-rsa", "asymmetric", ("RSA",), "shor_broken",
        "RSA only; defaults to PKCS#1 v1.5 padding in several APIs.",
    ),
    "openpgp": _L(
        "OpenPGP.js", "OpenPGP", "general",
        ("RSA", "ECDSA", "ElGamal", "AES", "Ed25519"),
        "shor_broken", "OpenPGP keys are classical asymmetric.",
    ),
    "pqc-kyber": _L(
        "pqc-kyber", "ML-KEM", "pqc", ("ML-KEM",), "pqc",
        "Kyber/ML-KEM bindings.",
    ),
    "mlkem": _L("mlkem", "ML-KEM", "pqc", ("ML-KEM",), "pqc", "ML-KEM (FIPS 203)."),
    "kyber-crystals": _L(
        "kyber-crystals", "ML-KEM", "pqc", ("ML-KEM",), "pqc", "Kyber/ML-KEM."
    ),
}

# --- Java (maven / gradle), keyed by groupId:artifactId and by artifactId --- #
JAVA_LIBS: dict[str, LibInfo] = {
    "org.bouncycastle:bcprov-jdk15on": _L(
        "BouncyCastle (jdk15on)", "BouncyCastle", "general",
        ("RSA", "ECDSA", "AES", "SHA-2", "DH"),
        "shor_broken",
        "END-OF-LINE ARTEFACT: the jdk15on line is no longer maintained. "
        "Migrate to bcprov-jdk18on, which also carries the PQC provider.",
        min_safe="1.78",
        advisory="Pre-1.78 jdk15on builds carry unpatched issues "
                 "(e.g. CVE-2023-33201 LDAP injection in the PKIX layer).",
    ),
    "org.bouncycastle:bcprov-jdk18on": _L(
        "BouncyCastle", "BouncyCastle", "general",
        ("RSA", "ECDSA", "AES", "SHA-2", "DH", "ML-KEM", "ML-DSA"),
        "shor_broken",
        "Current BC line. Classical by default, but bcprov 1.72+ ships the "
        "NIST PQC algorithms - a migration path exists in-place.",
        min_safe="1.78",
        advisory="Upgrade to 1.78 or later for the PKIX and OpenPGP fixes.",
    ),
    "org.bouncycastle:bcpkix-jdk18on": _L(
        "BouncyCastle PKIX", "BouncyCastle", "tls",
        ("X.509", "RSA", "ECDSA", "CMS"),
        "shor_broken", "Certificate/CMS layer; classical signatures.",
    ),
    "org.bouncycastle:bctls-jdk18on": _L(
        "BouncyCastle TLS", "BouncyCastle", "tls",
        ("TLS", "RSA", "ECDSA", "ECDH"),
        "shor_broken", "TLS provider; classical key exchange by default.",
    ),
    "org.bouncycastle:bcprov-jdk15to18": _L(
        "BouncyCastle (jdk15to18)", "BouncyCastle", "general",
        ("RSA", "ECDSA", "AES"), "shor_broken",
        "Compatibility line for legacy JDKs; prefer jdk18on.",
    ),
    "com.nimbusds:nimbus-jose-jwt": _L(
        "Nimbus JOSE+JWT", "Nimbus", "jwt",
        ("RSA", "ECDSA", "Ed25519", "AES", "HMAC"),
        "shor_broken",
        "JOSE/JWT; RSA-OAEP and ECDH-ES key agreement are Shor-breakable.",
        min_safe="9.37.2",
        advisory="CVE-2023-52428 (denial of service on large PBES2 counts) "
                 "fixed in 9.37.2.",
    ),
    "io.jsonwebtoken:jjwt": _L(
        "JJWT", "JJWT", "jwt", ("HMAC", "RSA", "ECDSA"), "shor_broken",
        "JWT library; classical signing keys.",
    ),
    "io.jsonwebtoken:jjwt-impl": _L(
        "JJWT", "JJWT", "jwt", ("HMAC", "RSA", "ECDSA"), "shor_broken",
        "JWT library; classical signing keys.",
    ),
    "commons-codec:commons-codec": _L(
        "Apache Commons Codec", "Commons Codec", "hash",
        ("MD5", "SHA-1", "SHA-2"), "legacy_broken",
        "DigestUtils exposes md5Hex/sha1Hex, the most common weak-hash sink "
        "in Java code.",
    ),
    "org.apache.santuario:xmlsec": _L(
        "Apache XML Security", "XMLSec", "general",
        ("RSA", "DSA", "SHA-1", "AES"), "shor_broken",
        "XML-DSig/XML-Enc; the specification's default signature method is "
        "RSA-SHA1.",
    ),
    "net.i2p.crypto:eddsa": _L(
        "ed25519-java", "EdDSA", "asymmetric", ("Ed25519",), "shor_broken",
        "Ed25519 in pure Java; archived upstream. Shor-breakable.",
    ),
    "org.connectbot:jbcrypt": _L(
        "jBCrypt", "bcrypt", "password", ("bcrypt",), "quantum_safe",
        "Password hashing only.",
    ),
    "org.mindrot:jbcrypt": _L(
        "jBCrypt", "bcrypt", "password", ("bcrypt",), "quantum_safe",
        "Password hashing only; 72-byte truncation.",
    ),
    "org.bouncycastle:bcpqc-jdk18on": _L(
        "BouncyCastle PQC", "BouncyCastle", "pqc",
        ("ML-KEM", "ML-DSA", "SLH-DSA", "Falcon"), "pqc",
        "BouncyCastle post-quantum provider.",
    ),
    "org.openquantumsafe:liboqs": _L(
        "liboqs-java", "liboqs", "pqc", ("ML-KEM", "ML-DSA", "Falcon"), "pqc",
        "Open Quantum Safe JNI bindings; research-grade.",
    ),
}

# --- Go -------------------------------------------------------------------- #
GO_LIBS: dict[str, LibInfo] = {
    "golang.org/x/crypto": _L(
        "golang.org/x/crypto", "Go x/crypto", "general",
        ("Ed25519", "X25519", "SSH", "ChaCha20-Poly1305", "bcrypt"),
        "shor_broken",
        "SSH and asymmetric primitives; classical key exchange.",
        min_safe="0.17.0",
        advisory="CVE-2023-48795 (Terrapin, SSH transcript truncation) fixed "
                 "in 0.17.0.",
    ),
    "github.com/cloudflare/circl": _L(
        "CIRCL", "CIRCL", "pqc",
        ("ML-KEM", "ML-DSA", "X25519", "Ed25519", "BLS12-381"),
        "pqc",
        "Cloudflare's research library: ships hybrid PQC KEMs (X25519Kyber768) "
        "alongside classical curves.",
    ),
    "github.com/dgrijalva/jwt-go": _L(
        "jwt-go (abandoned)", "jwt-go", "jwt",
        ("HMAC", "RSA", "ECDSA"), "shor_broken",
        "ABANDONED fork; the maintained module is github.com/golang-jwt/jwt.",
        advisory="CVE-2020-26160 (access restriction bypass via 'aud' "
                 "handling) is unfixed on this import path.",
    ),
    "github.com/golang-jwt/jwt": _L(
        "golang-jwt", "golang-jwt", "jwt",
        ("HMAC", "RSA", "ECDSA", "Ed25519"), "shor_broken",
        "JWT signing; classical keys.",
        min_safe="4.5.1",
        advisory="CVE-2024-51744 (bad-token error handling) fixed in 4.5.1/5.2.0.",
    ),
    "github.com/golang-jwt/jwt/v4": _L(
        "golang-jwt v4", "golang-jwt", "jwt",
        ("HMAC", "RSA", "ECDSA", "Ed25519"), "shor_broken",
        "JWT signing; classical keys.",
        min_safe="4.5.1",
        advisory="CVE-2024-51744 fixed in 4.5.1.",
    ),
    "github.com/golang-jwt/jwt/v5": _L(
        "golang-jwt v5", "golang-jwt", "jwt",
        ("HMAC", "RSA", "ECDSA", "Ed25519"), "shor_broken",
        "JWT signing; classical keys.",
    ),
    "filippo.io/edwards25519": _L(
        "edwards25519", "Ed25519", "asymmetric", ("Ed25519",), "shor_broken",
        "Edwards curve arithmetic; Shor-breakable.",
    ),
    "filippo.io/age": _L(
        "age", "age", "general", ("X25519", "ChaCha20-Poly1305"), "shor_broken",
        "File encryption; X25519 recipients are Shor-breakable.",
    ),
    "github.com/open-quantum-safe/liboqs-go": _L(
        "liboqs-go", "liboqs", "pqc", ("ML-KEM", "ML-DSA", "Falcon"), "pqc",
        "Open Quantum Safe Go bindings; research-grade.",
    ),
    "github.com/pion/dtls": _L(
        "pion/dtls", "DTLS", "tls", ("DTLS", "ECDSA", "ECDH", "AES"),
        "shor_broken", "DTLS stack; classical ECDHE key agreement.",
    ),
    "github.com/miekg/pkcs11": _L(
        "miekg/pkcs11", "PKCS#11", "general", ("RSA", "ECDSA", "AES"),
        "shor_broken",
        "HSM binding: keys live in hardware, so migration needs vendor "
        "firmware support for PQC.",
    ),
    "software.sslmate.com/src/go-pkcs12": _L(
        "go-pkcs12", "PKCS#12", "general", ("RSA", "3DES", "X.509"),
        "legacy_broken",
        "PKCS#12 legacy encryption is RC2/3DES based.",
    ),
}

# --- Rust ------------------------------------------------------------------ #
RUST_LIBS: dict[str, LibInfo] = {
    "ring": _L(
        "ring", "ring", "general",
        ("ECDSA", "Ed25519", "X25519", "AES-GCM", "SHA-2"),
        "shor_broken", "BoringSSL-derived primitives; classical asymmetric.",
    ),
    "rustls": _L(
        "rustls", "rustls", "tls", ("TLS", "ECDSA", "X25519", "AES-GCM"),
        "shor_broken",
        "Modern TLS stack. Hybrid PQC key exchange is available via the "
        "rustls-post-quantum crate but is not on by default.",
    ),
    "rustls-post-quantum": _L(
        "rustls-post-quantum", "rustls", "pqc", ("ML-KEM", "X25519MLKEM768"),
        "pqc", "Enables hybrid X25519MLKEM768 key exchange for rustls.",
    ),
    "openssl": _L(
        "openssl (rust)", "OpenSSL", "tls", ("TLS", "RSA", "ECDSA", "AES"),
        "shor_broken", "OpenSSL bindings; classical by default.",
        min_safe="0.10.66",
        advisory="RUSTSEC-2024-0357 (memory issue in MemBio::get_buf) fixed "
                 "in 0.10.66.",
    ),
    "openssl-sys": _L(
        "openssl-sys", "OpenSSL", "tls", ("TLS", "RSA", "ECDSA", "AES"),
        "shor_broken", "Raw OpenSSL FFI.",
    ),
    "rsa": _L(
        "rsa (rust)", "rust-rsa", "asymmetric", ("RSA",), "shor_broken",
        "Pure-Rust RSA.",
        advisory="RUSTSEC-2023-0071 (Marvin timing sidechannel) has NO fixed "
                 "release; key-recovery risk in any decryption oracle.",
    ),
    "ed25519-dalek": _L(
        "ed25519-dalek", "Ed25519", "asymmetric", ("Ed25519",), "shor_broken",
        "Ed25519 signatures; Shor-breakable.",
        min_safe="2.0.0",
        advisory="RUSTSEC-2022-0093 (public-key oracle in the pre-2.0 signing "
                 "API) fixed in 2.0.0.",
    ),
    "curve25519-dalek": _L(
        "curve25519-dalek", "X25519", "asymmetric", ("X25519",), "shor_broken",
        "Curve25519 arithmetic; Shor-breakable.",
        min_safe="4.1.3",
        advisory="RUSTSEC-2024-0344 (timing variability in Scalar29/52 "
                 "subtraction) fixed in 4.1.3.",
    ),
    "aes-gcm": _L(
        "aes-gcm", "AES", "symmetric", ("AES-GCM",), "grover_weakened",
        "AEAD; Grover halves the effective key strength - prefer AES-256.",
    ),
    "aes": _L(
        "aes", "AES", "symmetric", ("AES",), "grover_weakened",
        "Raw block cipher with no AEAD; must be paired with a mode crate.",
    ),
    "chacha20poly1305": _L(
        "chacha20poly1305", "ChaCha20-Poly1305", "symmetric",
        ("ChaCha20-Poly1305",), "grover_weakened", "AEAD; 256-bit keys.",
    ),
    "sha1": _L(
        "sha1 (rust)", "SHA-1", "hash", ("SHA-1",), "legacy_broken",
        "SHA-1 is collision-broken.",
    ),
    "md-5": _L(
        "md-5", "MD5", "hash", ("MD5",), "legacy_broken",
        "MD5 is collision-broken.",
    ),
    "sha2": _L(
        "sha2", "SHA-2", "hash", ("SHA-2",), "grover_weakened",
        "SHA-2 family; Grover halves preimage strength.",
    ),
    "pqcrypto": _L(
        "pqcrypto (rust)", "PQClean", "pqc",
        ("ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "HQC"), "pqc",
        "PQClean bindings.",
    ),
    "pqcrypto-kyber": _L(
        "pqcrypto-kyber", "ML-KEM", "pqc", ("ML-KEM",), "pqc", "Kyber/ML-KEM."
    ),
    "pqcrypto-dilithium": _L(
        "pqcrypto-dilithium", "ML-DSA", "pqc", ("ML-DSA",), "pqc",
        "Dilithium/ML-DSA.",
    ),
    "ml-kem": _L("ml-kem", "ML-KEM", "pqc", ("ML-KEM",), "pqc", "FIPS 203 ML-KEM."),
    "ml-dsa": _L("ml-dsa", "ML-DSA", "pqc", ("ML-DSA",), "pqc", "FIPS 204 ML-DSA."),
    "oqs": _L(
        "oqs (rust)", "liboqs", "pqc", ("ML-KEM", "ML-DSA", "Falcon"), "pqc",
        "Open Quantum Safe Rust bindings; research-grade.",
    ),
    "sodiumoxide": _L(
        "sodiumoxide", "libsodium", "general",
        ("X25519", "Ed25519", "XSalsa20-Poly1305"), "shor_broken",
        "libsodium bindings; deprecated upstream.",
    ),
    "jsonwebtoken": _L(
        "jsonwebtoken (rust)", "jsonwebtoken", "jwt",
        ("HMAC", "RSA", "ECDSA", "Ed25519"), "shor_broken",
        "JWT signing; classical keys.",
    ),
}

#: token-level markers for PQC packages that are not in the tables above
_PQC_TOKENS = {
    "kyber", "mlkem", "dilithium", "mldsa", "falcon", "sphincs", "slhdsa",
    "liboqs", "oqs", "pqcrypto", "pqclean", "ntru", "saber", "frodo",
    "frodokem", "mceliece", "bike", "hqc", "xmss", "picnic", "rainbow",
    "postquantum", "pqc",
}

_ECOSYSTEM_TABLE = {
    "pypi": PYTHON_LIBS,
    "npm": NODE_LIBS,
    "maven": JAVA_LIBS,
    "go": GO_LIBS,
    "cargo": RUST_LIBS,
}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _clip(text: str, limit: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _norm(name: str) -> str:
    return re.sub(r"[_.]+", "-", (name or "").strip().strip("'\"").lower())


def _tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t}


def _parse_version(spec: Optional[str]) -> Optional[tuple[int, ...]]:
    """Pull a comparable numeric tuple out of a version spec.

    "^1.2.3" -> (1,2,3); ">=42.0,<43" -> (42,0); "v0.17.0" -> (0,17,0);
    "*", "latest", "${bcVersion}" -> None.
    """
    if not spec:
        return None
    m = re.search(r"(\d+(?:\.\d+)*)", str(spec))
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


def _vercmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    pa = a + (0,) * (length - len(a))
    pb = b + (0,) * (length - len(b))
    return (pa > pb) - (pa < pb)


def _clean_spec(raw: str) -> str:
    """Normalise a right-hand-side version expression to a short display form."""
    raw = (raw or "").strip().rstrip(",").strip()
    if raw.startswith("{"):  # { version = "1.2", features = [...] }
        m = re.search(r"version\s*=\s*[\"']([^\"']+)[\"']", raw)
        raw = m.group(1) if m else ""
    raw = raw.strip().strip("'\"")
    return raw


# --------------------------------------------------------------------------- #
# manifest parsers -> list of (package, version_spec, line_no, raw_line)
# --------------------------------------------------------------------------- #
Dep = tuple[str, str, int, str]

_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)"
    r"(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<spec>(?:[<>=!~^]=?[^;#\s,]+)(?:\s*,\s*[<>=!~^]=?[^;#\s,]+)*)?"
)


def parse_requirements(text: str) -> list[Dep]:
    deps: list[Dep] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        # "#egg=" is part of a VCS URL, not a comment, so look for it first
        egg = re.search(r"#egg=([A-Za-z0-9._\-]+)", raw)
        line = raw.split("#", 1)[0].strip()
        if egg and ("://" in raw or raw.strip().startswith("-e")):
            deps.append((egg.group(1), "", idx, raw.strip()))
            continue
        if not line or line.startswith("-") or line.endswith("\\"):
            continue
        line = line.split(";", 1)[0].strip()  # drop environment markers
        if "://" in line or line.startswith("."):
            continue
        m = _REQ_LINE.match(line)
        if m and m.group("name"):
            deps.append((m.group("name"), (m.group("spec") or "").strip(), idx, raw.strip()))
    return deps


def _parse_toml_like(text: str, is_dep_section) -> list[Dep]:
    """Shared scanner for pyproject.toml / Cargo.toml / Pipfile.

    Handles both table style (``name = "1.2"`` under a dependency section) and
    PEP 621 array style (``dependencies = ["cryptography>=42"]``).
    """
    deps: list[Dep] = []
    lines = text.splitlines()
    section = ""
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()

        m_sec = re.match(r"^\[+([^\]]+)\]+$", stripped)
        if m_sec:
            section = m_sec.group(1).strip().strip('"')
            i += 1
            continue

        # array style: dependencies = [ "pkg>=1" , ... ].  Inside an
        # optional-dependencies / extras table every key holds such an array,
        # so accept any key name there.
        in_extras = section.lower().endswith(
            ("optional-dependencies", "extras", "dependency-groups")
        )
        m_arr = re.match(
            r"^\s*(?:dependencies|requires|dev-dependencies|all)\s*=\s*\[(.*)$"
            if not in_extras
            else r"^\s*[\"']?[A-Za-z0-9][A-Za-z0-9._\-]*[\"']?\s*=\s*\[(.*)$",
            stripped,
        )
        if m_arr:
            buf = [(m_arr.group(1), i + 1)]
            depth = stripped.count("[") - stripped.count("]")
            j = i
            while depth > 0 and j + 1 < len(lines):
                j += 1
                nxt = lines[j].split("#", 1)[0]
                buf.append((nxt, j + 1))
                depth += nxt.count("[") - nxt.count("]")
            for chunk, lineno in buf:
                for item in re.findall(r"[\"']([^\"']+)[\"']", chunk):
                    parsed = parse_requirements(item)
                    if parsed:
                        deps.append((parsed[0][0], parsed[0][1], lineno, item))
            i = j + 1 if j > i else i + 1
            continue

        if is_dep_section(section):
            m_kv = re.match(
                r"^\s*[\"']?([A-Za-z0-9][A-Za-z0-9._\-]*)[\"']?\s*=\s*(.+)$", stripped
            )
            if m_kv and m_kv.group(1).lower() not in {
                "version", "features", "optional", "path", "git", "branch",
                "tag", "rev", "package", "default-features", "workspace",
                "python", "extras", "markers", "index", "registry", "rustc",
            }:
                deps.append(
                    (m_kv.group(1), _clean_spec(m_kv.group(2)), i + 1, stripped)
                )
        i += 1
    return deps


def parse_pyproject(text: str) -> list[Dep]:
    def is_dep(section: str) -> bool:
        s = section.lower()
        # table style lives under [tool.poetry...dependencies]; the PEP 621
        # [project] arrays are picked up by the array branch of the scanner.
        return s.endswith("dependencies") and s.startswith("tool.")

    return _parse_toml_like(text, is_dep)


def parse_pipfile(text: str) -> list[Dep]:
    def is_dep(section: str) -> bool:
        return section.lower() in ("packages", "dev-packages")

    return _parse_toml_like(text, is_dep)


def parse_cargo(text: str) -> list[Dep]:
    def is_dep(section: str) -> bool:
        s = section.lower()
        return s.endswith("dependencies") or s.endswith("dependencies.*")

    deps = _parse_toml_like(text, is_dep)
    # [dependencies.rustls] style tables
    for m in re.finditer(
        r"^\[(?:workspace\.)?(?:dev-|build-)?dependencies\.([A-Za-z0-9._\-]+)\]",
        text,
        re.MULTILINE,
    ):
        line = text.count("\n", 0, m.start()) + 1
        tail = text[m.end() : m.end() + 400]
        v = re.search(r"version\s*=\s*[\"']([^\"']+)[\"']", tail)
        deps.append((m.group(1), v.group(1) if v else "", line, m.group(0)))
    return deps


def parse_package_json(text: str) -> list[Dep]:
    deps: list[Dep] = []
    try:
        doc = json.loads(text)
    except Exception:
        # Malformed JSON (a merge conflict, a trailing comma) must not blind the
        # scan: fall back to a permissive "key": "value" sweep.  Matching too
        # much is harmless here because every hit is filtered through the
        # crypto knowledge base afterwards.
        for idx, raw in enumerate(text.splitlines(), start=1):
            for m in re.finditer(r'"(@?[\w./\-]+)"\s*:\s*"([^"]*)"', raw):
                deps.append((m.group(1), m.group(2), idx, m.group(0)))
        return deps
    if not isinstance(doc, dict):
        return deps
    lines = text.splitlines()
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
    ):
        block = doc.get(key)
        if not isinstance(block, dict):
            continue
        for pkg, spec in block.items():
            lineno = 1
            needle = f'"{pkg}"'
            for idx, raw in enumerate(lines, start=1):
                if needle in raw:
                    lineno = idx
                    break
            deps.append((str(pkg), str(spec), lineno, f'"{pkg}": "{spec}"'))
    return deps


def parse_pom(text: str) -> list[Dep]:
    deps: list[Dep] = []
    props: dict[str, str] = {}
    for m in re.finditer(r"<([A-Za-z0-9._\-]+)>([^<>]+)</\1>", text):
        key, val = m.group(1), m.group(2).strip()
        if key.endswith(".version") or key.endswith("-version") or key.endswith("Version"):
            props[key] = val
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
        chunk = m.group(1)
        gid = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", chunk)
        aid = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", chunk)
        ver = re.search(r"<version>\s*([^<]+?)\s*</version>", chunk)
        if not (gid and aid):
            continue
        version = ver.group(1) if ver else ""
        pm = re.fullmatch(r"\$\{([^}]+)\}", version.strip())
        if pm:
            version = props.get(pm.group(1), version)
        line = text.count("\n", 0, m.start()) + 1
        deps.append((f"{gid.group(1)}:{aid.group(1)}", version, line, _clip(chunk, 160)))
    return deps


_GRADLE_RE = re.compile(
    r"""(?P<conf>implementation|api|compile|compileOnly|runtimeOnly|testImplementation|
        testCompile|classpath|annotationProcessor|kapt)\s*[\s(]\s*
        ['"](?P<coord>[A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+(?::[^'"]+)?)['"]""",
    re.VERBOSE,
)


def parse_gradle(text: str) -> list[Dep]:
    deps: list[Dep] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0]
        for m in _GRADLE_RE.finditer(line):
            parts = m.group("coord").split(":")
            if len(parts) < 2:
                continue
            name = f"{parts[0]}:{parts[1]}"
            version = parts[2] if len(parts) > 2 else ""
            if version.startswith("$"):
                version = ""
            deps.append((name, version, idx, raw.strip()))
        # group:/name:/version: map notation
        m2 = re.search(
            r"group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*:\s*['\"]([^'\"]+)['\"]"
            r"(?:\s*,\s*version\s*:\s*['\"]([^'\"]+)['\"])?",
            line,
        )
        if m2:
            deps.append(
                (f"{m2.group(1)}:{m2.group(2)}", m2.group(3) or "", idx, raw.strip())
            )
    return deps


def parse_gomod(text: str) -> list[Dep]:
    deps: list[Dep] = []
    in_block = False
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^require\s*\($", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = None
        if in_block:
            m = re.match(r"^([\w./\-~]+(?:\.[\w./\-~]+)*)\s+(v[\w.\-+]+)", line)
        elif line.startswith("require "):
            m = re.match(r"^require\s+([\w./\-~]+)\s+(v[\w.\-+]+)", line)
        if m:
            deps.append((m.group(1), m.group(2), idx, raw.strip()))
    return deps


def parse_setup_py(text: str) -> list[Dep]:
    deps: list[Dep] = []
    for m in re.finditer(
        r"(?:install_requires|setup_requires|tests_require)\s*=\s*\[(.*?)\]",
        text,
        re.DOTALL,
    ):
        base_line = text.count("\n", 0, m.start()) + 1
        for item in re.finditer(r"[\"']([^\"']+)[\"']", m.group(1)):
            line = base_line + m.group(1).count("\n", 0, item.start())
            parsed = parse_requirements(item.group(1))
            if parsed:
                deps.append((parsed[0][0], parsed[0][1], line, item.group(1)))
    return deps


#: filename (lowercased) -> (parser, ecosystem)
_PARSERS: dict[str, tuple[Any, str]] = {
    "pyproject.toml": (parse_pyproject, "pypi"),
    "pipfile": (parse_pipfile, "pypi"),
    "setup.py": (parse_setup_py, "pypi"),
    "package.json": (parse_package_json, "npm"),
    "pom.xml": (parse_pom, "maven"),
    "build.gradle": (parse_gradle, "maven"),
    "build.gradle.kts": (parse_gradle, "maven"),
    "go.mod": (parse_gomod, "go"),
    "cargo.toml": (parse_cargo, "cargo"),
}


def _select_parser(path: str):
    base = os.path.basename(path).lower()
    if base in _PARSERS:
        return _PARSERS[base]
    for pattern in FILE_PATTERNS:
        if pattern.match(base):
            return parse_requirements, "pypi"
    return None, ""


# --------------------------------------------------------------------------- #
# lookup
# --------------------------------------------------------------------------- #
def _lookup(pkg: str, ecosystem: str) -> Optional[LibInfo]:
    table = _ECOSYSTEM_TABLE.get(ecosystem, {})
    norm = _norm(pkg)
    if norm in table:
        return table[norm]
    if pkg.lower() in table:
        return table[pkg.lower()]

    if ecosystem == "maven" and ":" in norm:
        artifact = norm.split(":", 1)[1]
        for key, info in table.items():
            if key.split(":", 1)[-1] == artifact:
                return info
    if ecosystem == "go":
        # go.mod carries the full module path; match the longest known prefix
        best: Optional[LibInfo] = None
        best_len = 0
        for key, info in table.items():
            if (norm == key or norm.startswith(key + "/")) and len(key) > best_len:
                best, best_len = info, len(key)
        if best:
            return best
    if ecosystem == "npm" and norm.startswith("@"):
        return table.get(norm)
    return None


def _pqc_guess(pkg: str) -> Optional[LibInfo]:
    """Catch PQC packages that are not in the tables (the field moves fast)."""
    toks = _tokens(pkg)
    hit = toks & _PQC_TOKENS
    if not hit:
        return None
    marker = sorted(hit)[0]
    algo = (
        "ML-KEM"
        if marker in ("kyber", "mlkem", "frodo", "frodokem", "ntru", "saber",
                      "mceliece", "bike", "hqc")
        else "ML-DSA"
        if marker in ("dilithium", "mldsa", "falcon", "rainbow", "picnic")
        else "SLH-DSA"
        if marker in ("sphincs", "slhdsa", "xmss")
        else "PQC"
    )
    return LibInfo(
        display=pkg,
        family=algo,
        category="pqc",
        algorithms=(algo,),
        threat_hint="pqc",
        note=f"Post-quantum package inferred from the name token '{marker}'. "
        "Confirm the concrete parameter set before claiming FIPS 203/204/205 "
        "compliance.",
    )


# --------------------------------------------------------------------------- #
# artefact construction
# --------------------------------------------------------------------------- #
def _build_artefact(
    info: LibInfo,
    pkg: str,
    spec: str,
    ecosystem: str,
    path: str,
    line: int,
    raw_line: str,
    inferred: bool = False,
) -> Artefact:
    parsed = _parse_version(spec)
    flags: list[str] = []

    if info.note:
        flags.append(info.note)

    if info.advisory:
        if info.min_safe is None:
            flags.append(f"ADVISORY: {info.advisory}")
        else:
            floor = _parse_version(info.min_safe)
            if parsed is None:
                flags.append(
                    f"ADVISORY (version not pinned, verify resolved version): {info.advisory}"
                )
            elif floor and _vercmp(parsed, floor) < 0:
                flags.append(
                    f"ADVISORY: declared {spec or '?'} is below {info.min_safe}. {info.advisory}"
                )

    if not spec or spec.strip() in ("*", "latest", ""):
        flags.append(
            "Unpinned dependency: the resolved version cannot be audited from "
            "the manifest alone."
        )

    manifest = os.path.basename(path)
    evidence = f"{manifest}: {raw_line.strip() or pkg}"
    if flags:
        evidence += " -- " + " ".join(flags)

    exact = re.fullmatch(r"\s*={2,3}\s*([^,\s]+)\s*", spec or "")
    version_display = exact.group(1) if exact else (spec or None)

    extra: dict[str, Any] = {
        "package": pkg,
        "ecosystem": ecosystem,
        "manifest": manifest,
        "version": version_display,
        "version_spec": spec or None,
        "version_parsed": list(parsed) if parsed else None,
        "algorithms": list(info.algorithms),
        "category": info.category,
        "threat_hint": info.threat_hint,
        "notes": info.note or None,
        "advisory": info.advisory or None,
        "min_safe_version": info.min_safe,
        "unpinned": not bool(parsed),
        "inferred": inferred,
    }
    if info.threat_hint == "pqc":
        extra["pqc"] = True

    return Artefact(
        name=info.display,
        family=info.family,
        kind="library",
        params=Params(
            key_size=None, curve=None, mode=None, padding=None, not_after=None,
            extra=extra,
        ),
        occurrences=[
            Occurrence(
                file=path,
                line=line,
                evidence=_clip(evidence),
                detector=DETECTOR,
                confidence="medium" if inferred else "high",
            )
        ],
    )


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
def matches(path: str) -> bool:
    base = os.path.basename(path).lower()
    if base in FILE_NAMES:
        return True
    return any(p.match(base) for p in FILE_PATTERNS)


def scan_file(
    path: str, data: Optional[bytes | str] = None
) -> tuple[list[Artefact], list[str]]:
    """Scan one dependency manifest. Returns ``(artefacts, errors)``; never raises."""
    parser, ecosystem = _select_parser(path)
    if parser is None:
        return [], []

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

    text = raw.decode("utf-8", "replace")
    errors: list[str] = []

    try:
        deps = parser(text)
    except Exception as exc:
        return [], [f"{path}: manifest parse failed: {type(exc).__name__}: {exc}"]

    if os.path.basename(path).lower() == "package.json":
        try:
            json.loads(text)
        except Exception as exc:
            errors.append(
                f"{path}: package.json is not valid JSON ({exc}); "
                "results came from a degraded text scan and may be incomplete"
            )

    artefacts: list[Artefact] = []
    seen: set[tuple[str, int]] = set()
    for pkg, spec, line, raw_line in deps:
        try:
            dedupe = (_norm(pkg), line)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            info = _lookup(pkg, ecosystem)
            inferred = False
            if info is None:
                info = _pqc_guess(pkg)
                inferred = info is not None
            if info is None:
                continue
            artefacts.append(
                _build_artefact(
                    info, pkg, spec, ecosystem, path, line, raw_line, inferred
                )
            )
        except Exception as exc:
            errors.append(f"{path}:{line}: dependency '{pkg}' failed: {exc}")

    return artefacts, errors


def detect(path: str, data: Optional[bytes | str] = None) -> list[Artefact]:
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


def known_packages() -> dict[str, list[str]]:
    """Introspection helper: which packages this detector recognises."""
    return {eco: sorted(table) for eco, table in _ECOSYSTEM_TABLE.items()}


__all__ = [
    "NAME",
    "FILE_NAMES",
    "FILE_PATTERNS",
    "LibInfo",
    "PYTHON_LIBS",
    "NODE_LIBS",
    "JAVA_LIBS",
    "GO_LIBS",
    "RUST_LIBS",
    "matches",
    "scan_file",
    "scan_files",
    "detect",
    "known_packages",
    "parse_requirements",
    "parse_pyproject",
    "parse_package_json",
    "parse_pom",
    "parse_gradle",
    "parse_gomod",
    "parse_cargo",
]
