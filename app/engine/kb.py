"""
ECDAT cryptographic knowledge base.

This module is the single auditable source of truth for "what is this algorithm
and how badly does a cryptographically relevant quantum computer (CRQC) hurt it".

Design goals
------------
1. **Auditable.**  Every entry carries a ``citation`` string naming the standard
   or the public break that justifies the verdict (e.g. "NIST FIPS 203",
   "NIST SP 800-131A r2", "SHAttered, CWI/Google 2017").  Nothing is asserted
   without a source a reviewer can look up.
2. **Parameter aware.**  Verdicts are computed from *parameters*, not from a
   name.  ``RSA-1024`` and ``RSA-4096`` are both Shor-broken but only one of
   them is already broken classically, and the reason text says so.
3. **Total.**  ``classify()`` never raises and never returns ``None``.  An
   unrecognised family degrades to ``Threat.UNKNOWN`` with an honest reason.

Public API
----------
``classify(family, params) -> (Threat, reason)``
``canonical_name(family, params) -> str``      e.g. "RSA-1024", "ECDSA-secp256r1", "AES-256-GCM"
``citation(family, params) -> str``
``entry_for(family, params) -> AlgoEntry | None``
``normalize_family(name) -> str``              canonical KB key, e.g. "rsa", "ml-kem"
``KEY_SIZE_FLOORS``                            minimum acceptable classical sizes
``CURVES``                                     elliptic curve facts table
``all_entries()``                              full KB dump, for the CBOM appendix / audit report

Threat semantics
----------------
``SHOR_BROKEN``     Shor's algorithm solves the underlying hard problem in
                    polynomial time (factoring, finite-field DLP, ECDLP).
                    Security goes to ~0, not "halved".  Harvest-now-decrypt-later
                    applies to every confidentiality use.
``LEGACY_BROKEN``   Already broken or formally disallowed with *classical*
                    computers.  A quantum computer is not required.
``GROVER_WEAKENED`` Security level is reduced (roughly halved for exhaustive
                    search) but the primitive survives at a larger parameter.
``QUANTUM_SAFE``    Believed safe against both classical and quantum attack at
                    the stated parameters (symmetric / hash, >= 256-bit).
``PQC``             A post-quantum primitive: the target state of a migration.
``UNKNOWN``         Not in the KB, or parameters too vague to judge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

try:  # normal package import
    from .models import Params, Threat
except ImportError:  # pragma: no cover - direct execution / flat layout
    from app.engine.models import Params, Threat  # type: ignore

__all__ = [
    "KB_VERSION",
    "AlgoEntry",
    "KB",
    "ALIASES",
    "CURVES",
    "KEY_SIZE_FLOORS",
    "PQC_PARAM_SETS",
    "classify",
    "canonical_name",
    "citation",
    "entry_for",
    "normalize_family",
    "curve_info",
    "is_pqc",
    "all_entries",
]

KB_VERSION = "1.0.0 (2026-08)"

# --------------------------------------------------------------------------
# Citations used repeatedly.  Kept as constants so the report can render a
# bibliography without string-matching prose.
# --------------------------------------------------------------------------
C_FIPS140 = "NIST FIPS 140-3 / SP 800-140C approved algorithms"
C_131A = "NIST SP 800-131A r2 (transitioning cryptographic algorithms, 2019)"
C_57 = "NIST SP 800-57 Part 1 r5 (key management, 2020)"
C_186_5 = "NIST FIPS 186-5 (digital signature standard, 2023)"
C_800_186 = "NIST SP 800-186 (recommended elliptic curves, 2023)"
C_203 = "NIST FIPS 203 (ML-KEM, Aug 2024)"
C_204 = "NIST FIPS 204 (ML-DSA, Aug 2024)"
C_205 = "NIST FIPS 205 (SLH-DSA, Aug 2024)"
C_206 = "NIST FIPS 206 draft (FN-DSA / Falcon)"
C_8547 = "NIST IR 8547 ipd (transition to PQC standards: deprecate 2030, disallow 2035)"
C_8545 = "NIST IR 8545 (round-4 status report; HQC selected Mar 2025)"
C_CNSA2 = "NSA CNSA 2.0 suite (2022, FAQ updated 2024)"
C_SHOR = "Shor 1994/1997, polynomial-time factoring and discrete log"
C_GROVER = "Grover 1996, quadratic speed-up for unstructured search"
C_38A = "NIST SP 800-38A (block cipher modes of operation)"
C_38D = "NIST SP 800-38D (GCM/GMAC)"
C_SHATTERED = "SHAttered, Stevens et al. CWI/Google 2017 (SHA-1 collision)"
C_SHA1_CP = "Leurent & Peyrin 2020 (SHA-1 chosen-prefix collision)"
C_MD5 = "Wang & Yu 2005; Sotirov et al. 2008 (rogue CA via MD5); RFC 6151"
C_SWEET32 = "Sweet32, Bhargavan & Leurent 2016 (CVE-2016-2183)"
C_RC4 = "RFC 7465 (prohibiting RC4); AlFardan et al. 2013"
C_8996 = "RFC 8996 (deprecating TLS 1.0 and TLS 1.1, 2021)"
C_7568 = "RFC 7568 (deprecating SSLv3)"
C_BLEICHENBACHER = "Bleichenbacher 1998; ROBOT 2017 (RSA PKCS#1 v1.5 oracle)"
C_LOGJAM = "Logjam, Adrian et al. 2015 (finite-field DH downgrade / precomputation)"
C_MOSCA = "Mosca 2015, 'Cybersecurity in an era with quantum computers'"

# --------------------------------------------------------------------------
# Entry model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AlgoEntry:
    """One auditable knowledge-base row."""

    key: str                 # canonical KB key, lowercase (e.g. "ml-kem")
    display: str             # pretty name used to build canonical_name (e.g. "ML-KEM")
    family: str              # coarse family label for grouping (e.g. "RSA", "SHA-2")
    category: str            # asymmetric|symmetric|hash|mac|kdf|protocol|mode|padding|prng
    threat: Threat           # default verdict before parameters are considered
    reason: str              # default reason text
    citation: str            # standard or public break justifying the verdict
    replacement: str = ""    # migration hint (the recommender module owns the final call)
    status: str = ""         # standards status, e.g. "FIPS approved", "disallowed after 2023"
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "display": self.display,
            "family": self.family,
            "category": self.category,
            "threat": self.threat.value if isinstance(self.threat, Threat) else str(self.threat),
            "reason": self.reason,
            "citation": self.citation,
            "replacement": self.replacement,
            "status": self.status,
            "notes": self.notes,
        }


def _e(*args, **kwargs) -> AlgoEntry:
    return AlgoEntry(*args, **kwargs)


# --------------------------------------------------------------------------
# Minimum acceptable *classical* sizes (bits).  Below the floor the artefact is
# already weak today, independent of quantum.
#   SP 800-131A r2 / SP 800-57 Part 1 r5 (112-bit security floor).
# --------------------------------------------------------------------------
KEY_SIZE_FLOORS: dict[str, int] = {
    "rsa": 2048,
    "dsa": 2048,
    "dh": 2048,
    "elgamal": 2048,
    "paillier": 2048,
    "ec": 224,
    "ecdsa": 224,
    "ecdh": 224,
    "ecies": 224,
    "ecmqv": 224,
    "sm2": 256,
    "bls": 256,
    "aes": 128,
    "camellia": 128,
    "aria": 128,
    "seed": 128,
    "chacha20": 256,
    "3des": 168,
    "des": 999999,   # no acceptable size
    "rc4": 999999,
    "rc2": 999999,
    "blowfish": 128,
    "hmac": 112,
    "sha-2": 224,
    "sha-3": 224,
    "pbkdf2": 112,
    "ml-kem": 768,
    "ml-dsa": 65,      # parameter-set number, not bits (see PQC_PARAM_SETS)
    "slh-dsa": 128,
    "falcon": 512,
}

# Quantum security floors: NSA CNSA 2.0 requires AES-256 and SHA-384+ for NSS.
CNSA2_SYMMETRIC_FLOOR = 256
CNSA2_HASH_FLOOR = 384

# --------------------------------------------------------------------------
# Elliptic curve facts.  bits = field size; strength = classical security level.
# --------------------------------------------------------------------------
CURVES: dict[str, dict[str, Any]] = {
    # NIST prime curves (FIPS 186-5 / SP 800-186)
    "secp192r1": {"display": "secp192r1", "bits": 192, "strength": 96, "approved": False,
                  "note": "NIST P-192, withdrawn from FIPS 186-5", "citation": C_186_5},
    "secp224r1": {"display": "secp224r1", "bits": 224, "strength": 112, "approved": True,
                  "note": "NIST P-224, at the 112-bit floor only", "citation": C_800_186},
    "secp256r1": {"display": "secp256r1", "bits": 256, "strength": 128, "approved": True,
                  "note": "NIST P-256, the most deployed curve", "citation": C_800_186},
    "secp384r1": {"display": "secp384r1", "bits": 384, "strength": 192, "approved": True,
                  "note": "NIST P-384, CNSA 1.0 curve", "citation": C_CNSA2},
    "secp521r1": {"display": "secp521r1", "bits": 521, "strength": 256, "approved": True,
                  "note": "NIST P-521", "citation": C_800_186},
    "secp160r1": {"display": "secp160r1", "bits": 160, "strength": 80, "approved": False,
                  "note": "80-bit, broken classically by generic ECDLP effort", "citation": C_131A},
    # Koblitz / non-NIST prime
    "secp256k1": {"display": "secp256k1", "bits": 256, "strength": 128, "approved": False,
                  "note": "Bitcoin/Ethereum curve, not NIST approved", "citation": C_800_186},
    # Binary curves (deprecated by SP 800-186)
    "sect163k1": {"display": "sect163k1", "bits": 163, "strength": 80, "approved": False,
                  "note": "binary curve, 80-bit, deprecated", "citation": C_800_186},
    "sect163r2": {"display": "sect163r2", "bits": 163, "strength": 80, "approved": False,
                  "note": "binary curve, 80-bit, deprecated", "citation": C_800_186},
    "sect233k1": {"display": "sect233k1", "bits": 233, "strength": 112, "approved": False,
                  "note": "binary curve, deprecated for new use", "citation": C_800_186},
    "sect283k1": {"display": "sect283k1", "bits": 283, "strength": 128, "approved": False,
                  "note": "binary curve, deprecated for new use", "citation": C_800_186},
    "sect409k1": {"display": "sect409k1", "bits": 409, "strength": 192, "approved": False,
                  "note": "binary curve, deprecated for new use", "citation": C_800_186},
    "sect571k1": {"display": "sect571k1", "bits": 571, "strength": 256, "approved": False,
                  "note": "binary curve, deprecated for new use", "citation": C_800_186},
    # Brainpool (RFC 5639)
    "brainpoolP224r1": {"display": "brainpoolP224r1", "bits": 224, "strength": 112, "approved": False,
                        "note": "RFC 5639, not NIST approved", "citation": "RFC 5639"},
    "brainpoolP256r1": {"display": "brainpoolP256r1", "bits": 256, "strength": 128, "approved": False,
                        "note": "RFC 5639, not NIST approved", "citation": "RFC 5639"},
    "brainpoolP320r1": {"display": "brainpoolP320r1", "bits": 320, "strength": 160, "approved": False,
                        "note": "RFC 5639, not NIST approved", "citation": "RFC 5639"},
    "brainpoolP384r1": {"display": "brainpoolP384r1", "bits": 384, "strength": 192, "approved": False,
                        "note": "RFC 5639, not NIST approved", "citation": "RFC 5639"},
    "brainpoolP512r1": {"display": "brainpoolP512r1", "bits": 512, "strength": 256, "approved": False,
                        "note": "RFC 5639, not NIST approved", "citation": "RFC 5639"},
    # Montgomery / Edwards
    "x25519": {"display": "X25519", "bits": 255, "strength": 128, "approved": True,
               "note": "Curve25519 ECDH, RFC 7748, added in FIPS 186-5 era guidance", "citation": "RFC 7748"},
    "x448": {"display": "X448", "bits": 448, "strength": 224, "approved": True,
             "note": "Curve448 ECDH, RFC 7748", "citation": "RFC 7748"},
    "ed25519": {"display": "Ed25519", "bits": 255, "strength": 128, "approved": True,
                "note": "EdDSA over edwards25519, RFC 8032 / FIPS 186-5", "citation": C_186_5},
    "ed448": {"display": "Ed448", "bits": 448, "strength": 224, "approved": True,
              "note": "EdDSA over edwards448, RFC 8032 / FIPS 186-5", "citation": C_186_5},
    # National / pairing curves
    "sm2p256v1": {"display": "sm2p256v1", "bits": 256, "strength": 128, "approved": False,
                  "note": "Chinese SM2 curve, GB/T 32918", "citation": "GB/T 32918 / ISO/IEC 14888-3"},
    "frp256v1": {"display": "FRP256v1", "bits": 256, "strength": 128, "approved": False,
                 "note": "ANSSI French curve", "citation": "ANSSI FRP256v1"},
    "bls12-381": {"display": "BLS12-381", "bits": 381, "strength": 117, "approved": False,
                  "note": "pairing-friendly curve, ~117-128 bit classical after Kim-Barbulescu",
                  "citation": "Barbulescu & Duquesne 2019 (exTNFS security estimates)"},
    "bn254": {"display": "BN254", "bits": 254, "strength": 100, "approved": False,
              "note": "pairing curve, dropped to ~100-bit by exTNFS",
              "citation": "Kim & Barbulescu 2016 (exTNFS)"},
}

_CURVE_ALIASES: dict[str, str] = {
    "p-192": "secp192r1", "p192": "secp192r1", "prime192v1": "secp192r1", "nistp192": "secp192r1",
    "p-224": "secp224r1", "p224": "secp224r1", "prime224v1": "secp224r1", "nistp224": "secp224r1",
    "p-256": "secp256r1", "p256": "secp256r1", "prime256v1": "secp256r1", "nistp256": "secp256r1",
    "secp256v1": "secp256r1", "nist-p-256": "secp256r1",
    "p-384": "secp384r1", "p384": "secp384r1", "nistp384": "secp384r1", "nist-p-384": "secp384r1",
    "p-521": "secp521r1", "p521": "secp521r1", "nistp521": "secp521r1", "p-512": "secp521r1",
    "k-256": "secp256k1", "secp256k": "secp256k1",
    "curve25519": "x25519", "25519": "x25519", "montgomery25519": "x25519",
    "curve448": "x448", "goldilocks": "x448", "ed448-goldilocks": "ed448",
    "edwards25519": "ed25519", "edwards448": "ed448",
    "brainpoolp256": "brainpoolP256r1", "brainpoolp384": "brainpoolP384r1",
    "brainpoolp512": "brainpoolP512r1", "brainpoolp256t1": "brainpoolP256r1",
    "brainpoolp384t1": "brainpoolP384r1", "brainpoolp512t1": "brainpoolP512r1",
    "sm2": "sm2p256v1", "sm2curve": "sm2p256v1",
    "bls12381": "bls12-381", "bls12_381": "bls12-381", "bls381": "bls12-381",
    "bn_254": "bn254", "bn-254": "bn254", "alt_bn128": "bn254", "bn128": "bn254",
}

# PQC parameter sets -> claimed NIST security category.
PQC_PARAM_SETS: dict[str, dict[str, Any]] = {
    "ml-kem-512": {"category": 1, "citation": C_203},
    "ml-kem-768": {"category": 3, "citation": C_203},
    "ml-kem-1024": {"category": 5, "citation": C_203},
    "ml-dsa-44": {"category": 2, "citation": C_204},
    "ml-dsa-65": {"category": 3, "citation": C_204},
    "ml-dsa-87": {"category": 5, "citation": C_204},
    "slh-dsa-128": {"category": 1, "citation": C_205},
    "slh-dsa-192": {"category": 3, "citation": C_205},
    "slh-dsa-256": {"category": 5, "citation": C_205},
    "falcon-512": {"category": 1, "citation": C_206},
    "falcon-1024": {"category": 5, "citation": C_206},
    "hqc-128": {"category": 1, "citation": C_8545},
    "hqc-192": {"category": 3, "citation": C_8545},
    "hqc-256": {"category": 5, "citation": C_8545},
}

# --------------------------------------------------------------------------
# The knowledge base itself.
# --------------------------------------------------------------------------
_ENTRIES: list[AlgoEntry] = [
    # ---------------- Shor-broken public key ----------------
    _e("rsa", "RSA", "RSA", "asymmetric", Threat.SHOR_BROKEN,
       "RSA security rests on integer factorisation, which Shor's algorithm solves in polynomial time on a CRQC.",
       C_SHOR + "; " + C_8547, "ML-KEM-768 (encryption) or ML-DSA-65 / SLH-DSA (signatures)",
       "deprecated after 2030, disallowed after 2035 (NIST IR 8547)"),
    _e("dsa", "DSA", "DSA", "asymmetric", Threat.SHOR_BROKEN,
       "DSA rests on the finite-field discrete log problem, solved in polynomial time by Shor; FIPS 186-5 also withdrew DSA for signature generation.",
       C_186_5 + "; " + C_SHOR, "ML-DSA-65 or SLH-DSA-SHA2-192s",
       "withdrawn for signature generation (FIPS 186-5)"),
    _e("dh", "DH", "DH", "asymmetric", Threat.SHOR_BROKEN,
       "Finite-field Diffie-Hellman rests on the discrete log problem, solved in polynomial time by Shor; small or shared groups are also weak classically.",
       C_SHOR + "; " + C_LOGJAM, "ML-KEM-768, ideally hybrid X25519+ML-KEM-768 during transition"),
    _e("ecdsa", "ECDSA", "ECDSA", "asymmetric", Threat.SHOR_BROKEN,
       "ECDSA rests on the elliptic-curve discrete log problem; Shor solves ECDLP in polynomial time and needs fewer logical qubits than for equivalent RSA.",
       C_SHOR + "; " + C_186_5, "ML-DSA-65 (FIPS 204) or SLH-DSA for long-lived roots of trust"),
    _e("ecdh", "ECDH", "ECDH", "asymmetric", Threat.SHOR_BROKEN,
       "ECDH key agreement rests on ECDLP; a CRQC recovers the shared secret, so recorded traffic is retro-decryptable (harvest now, decrypt later).",
       C_SHOR + "; " + C_CNSA2, "ML-KEM-768, hybrid X25519MLKEM768 for TLS today"),
    _e("ec", "EC", "EC", "asymmetric", Threat.SHOR_BROKEN,
       "Generic elliptic-curve cryptography rests on ECDLP, which Shor's algorithm breaks in polynomial time.",
       C_SHOR + "; " + C_800_186, "ML-KEM / ML-DSA depending on use"),
    _e("x25519", "X25519", "X25519", "asymmetric", Threat.SHOR_BROKEN,
       "X25519 is ECDH over Curve25519: excellent classical security (128-bit) but ECDLP falls to Shor, so it offers no protection against harvest-now-decrypt-later.",
       "RFC 7748; " + C_SHOR, "hybrid X25519MLKEM768 (RFC 9370 style hybrid), then ML-KEM-768"),
    _e("x448", "X448", "X448", "asymmetric", Threat.SHOR_BROKEN,
       "X448 is ECDH over Curve448; 224-bit classical security but ECDLP is Shor-breakable.",
       "RFC 7748; " + C_SHOR, "ML-KEM-1024 or hybrid X448+ML-KEM-1024"),
    _e("ed25519", "Ed25519", "Ed25519", "asymmetric", Threat.SHOR_BROKEN,
       "Ed25519 (EdDSA over edwards25519) rests on ECDLP; a CRQC forges signatures by recovering the private scalar.",
       "RFC 8032; " + C_186_5 + "; " + C_SHOR, "ML-DSA-65, or SLH-DSA-SHA2-128s where a conservative hash-based signature is preferred"),
    _e("ed448", "Ed448", "Ed448", "asymmetric", Threat.SHOR_BROKEN,
       "Ed448 (EdDSA over edwards448) rests on ECDLP and is Shor-breakable despite its 224-bit classical strength.",
       "RFC 8032; " + C_186_5, "ML-DSA-87"),
    _e("elgamal", "ElGamal", "ElGamal", "asymmetric", Threat.SHOR_BROKEN,
       "ElGamal encryption rests on the finite-field discrete log problem, solved in polynomial time by Shor.",
       C_SHOR + "; " + C_57, "ML-KEM-768"),
    _e("ecies", "ECIES", "ECIES", "asymmetric", Threat.SHOR_BROKEN,
       "ECIES derives its key from an ephemeral ECDH exchange; the ECDLP step is Shor-breakable, so the whole hybrid scheme fails.",
       "SEC 1 v2 / ISO 18033-2; " + C_SHOR, "ML-KEM-768 + AES-256-GCM (KEM/DEM construction)"),
    _e("ecmqv", "ECMQV", "ECMQV", "asymmetric", Threat.SHOR_BROKEN,
       "ECMQV authenticated key agreement rests on ECDLP and is Shor-breakable; it was also removed from SP 800-56A r3.",
       "NIST SP 800-56A r3; " + C_SHOR, "ML-KEM-768 with authenticated transcript binding"),
    _e("sm2", "SM2", "SM2", "asymmetric", Threat.SHOR_BROKEN,
       "SM2 is an elliptic-curve scheme over a 256-bit prime curve; ECDLP is Shor-breakable.",
       "GB/T 32918; ISO/IEC 14888-3; " + C_SHOR, "ML-DSA / ML-KEM equivalents"),
    _e("paillier", "Paillier", "Paillier", "asymmetric", Threat.SHOR_BROKEN,
       "Paillier's additively homomorphic encryption rests on the composite residuosity assumption over an RSA modulus; Shor's factoring breaks it.",
       "Paillier 1999; " + C_SHOR, "lattice-based homomorphic schemes (BFV/CKKS) or ML-KEM where homomorphism is not required"),
    _e("bls", "BLS", "BLS", "asymmetric", Threat.SHOR_BROKEN,
       "BLS signatures rest on pairings over elliptic curves; the underlying ECDLP/pairing DLP is Shor-breakable, and BLS12-381 is already only ~117-128 bit classically.",
       "Boneh-Lynn-Shacham 2001; Barbulescu & Duquesne 2019; " + C_SHOR,
       "ML-DSA-65; note that PQC has no drop-in signature aggregation equivalent yet"),
    _e("dsa-ec-generic", "ECC", "ECC", "asymmetric", Threat.SHOR_BROKEN,
       "Elliptic-curve public-key cryptography rests on ECDLP, broken in polynomial time by Shor.",
       C_SHOR, "ML-KEM / ML-DSA"),
    _e("rsassa-pss", "RSASSA-PSS", "RSA", "asymmetric", Threat.SHOR_BROKEN,
       "RSA-PSS is the sound RSA signature padding, but the underlying RSA trapdoor still falls to Shor's factoring.",
       "RFC 8017; " + C_SHOR, "ML-DSA-65"),
    _e("rsaes-oaep", "RSAES-OAEP", "RSA", "asymmetric", Threat.SHOR_BROKEN,
       "OAEP is the sound RSA encryption padding, but the underlying RSA trapdoor still falls to Shor's factoring.",
       "RFC 8017; " + C_SHOR, "ML-KEM-768"),
    _e("dss", "DSS", "DSA", "asymmetric", Threat.SHOR_BROKEN,
       "The Digital Signature Standard family (DSA/ECDSA) rests on discrete logs and is Shor-breakable.",
       C_186_5, "ML-DSA-65"),

    # ---------------- Legacy / classically broken ----------------
    _e("md5", "MD5", "MD5", "hash", Threat.LEGACY_BROKEN,
       "MD5 collisions are computable in seconds on a laptop; chosen-prefix collisions produced a rogue CA certificate in 2008. No quantum computer needed.",
       C_MD5, "SHA-256 for integrity, SHA-384 for CNSA 2.0 systems", "disallowed for all signature use"),
    _e("md4", "MD4", "MD4", "hash", Threat.LEGACY_BROKEN,
       "MD4 collisions are found by hand-guided differential attacks in under a second; it is broken for every security purpose.",
       "Wang et al. 2005; RFC 6150 (MD4 to historic)", "SHA-256 / SHA-3-256"),
    _e("md2", "MD2", "MD2", "hash", Threat.LEGACY_BROKEN,
       "MD2 has practical preimage (2^73) and collision attacks and was moved to historic status.",
       "RFC 6149 (MD2 to historic); Knudsen et al. 2009", "SHA-256"),
    _e("sha-0", "SHA-0", "SHA-0", "hash", Threat.LEGACY_BROKEN,
       "SHA-0 was withdrawn by NIST in 1996 and collisions were published in 2004; it must never appear in production code.",
       "Joux et al. 2004; NIST withdrawal 1996", "SHA-256 / SHA-3-256"),
    _e("sha-1", "SHA-1", "SHA-1", "hash", Threat.LEGACY_BROKEN,
       "SHA-1 collisions are practical (SHAttered 2017) and chosen-prefix collisions cost roughly 45k USD of GPU time (2020); NIST disallowed SHA-1 entirely after 2030 and for signatures already.",
       C_SHATTERED + "; " + C_SHA1_CP + "; " + C_131A,
       "SHA-256 minimum, SHA-384 for CNSA 2.0", "disallowed for digital signatures; full retirement by 2030"),
    _e("des", "DES", "DES", "symmetric", Threat.LEGACY_BROKEN,
       "DES has a 56-bit key; it has been brute-forced in hours since 1998 and is withdrawn from every NIST standard.",
       C_131A + "; EFF Deep Crack 1998", "AES-256-GCM", "withdrawn"),
    _e("3des", "3DES", "3DES", "symmetric", Threat.LEGACY_BROKEN,
       "Triple-DES has a 64-bit block, which Sweet32 exploits after ~32 GB of traffic on one key; NIST disallowed it for encryption after 2023. Its 112-bit effective key would also drop to ~56 bits under Grover.",
       C_SWEET32 + "; " + C_131A, "AES-256-GCM", "disallowed after 31 Dec 2023"),
    _e("rc4", "RC4", "RC4", "symmetric", Threat.LEGACY_BROKEN,
       "RC4 keystream biases allow plaintext recovery from repeated encryptions; RFC 7465 prohibits it in TLS.",
       C_RC4, "ChaCha20-Poly1305 or AES-256-GCM", "prohibited in TLS"),
    _e("rc2", "RC2", "RC2", "symmetric", Threat.LEGACY_BROKEN,
       "RC2 uses a 64-bit block and was largely deployed with 40-bit export keys; related-key and brute-force attacks are practical.",
       "RFC 2268; " + C_131A, "AES-256-GCM", "withdrawn"),
    _e("blowfish", "Blowfish", "Blowfish", "symmetric", Threat.LEGACY_BROKEN,
       "Blowfish has a 64-bit block and is therefore vulnerable to Sweet32-style birthday attacks; its own author recommends moving off it.",
       C_SWEET32 + "; Schneier public guidance", "AES-256-GCM"),
    _e("rc5", "RC5", "RC5", "symmetric", Threat.LEGACY_BROKEN,
       "RC5 with common parameters uses a 64-bit block and reduced-round variants are broken; it is not FIPS approved.",
       "Biryukov & Kushilevitz 1998", "AES-256-GCM"),
    _e("idea", "IDEA", "IDEA", "symmetric", Threat.LEGACY_BROKEN,
       "IDEA has a 64-bit block (Sweet32 class) and full-round weak-key/meet-in-the-middle results; it is not FIPS approved.",
       C_SWEET32 + "; Khovratovich et al. 2012", "AES-256-GCM"),
    _e("tea", "TEA", "TEA", "symmetric", Threat.LEGACY_BROKEN,
       "TEA has equivalent-key and related-key weaknesses (used to break the original Xbox secure boot).",
       "Kelsey, Schneier & Wagner 1997", "AES-256-GCM"),
    _e("crc32", "CRC32", "CRC", "hash", Threat.LEGACY_BROKEN,
       "CRC32 is an error-detection checksum, not a cryptographic hash; collisions are trivially constructed and it provides no integrity guarantee against an adversary.",
       "no security claim; see RFC 3385", "SHA-256, or HMAC-SHA-256 when a key is available"),
    _e("md5crypt", "md5crypt", "md5crypt", "kdf", Threat.LEGACY_BROKEN,
       "The 1000-iteration MD5-based crypt(3) scheme is brute-forced at billions of guesses per second on GPUs.",
       "Provos & Mazieres 1999; hashcat benchmarks", "Argon2id, or PBKDF2-HMAC-SHA-256 with >= 600k iterations"),
    _e("weak-prng", "Weak PRNG", "PRNG", "prng", Threat.LEGACY_BROKEN,
       "A non-cryptographic pseudo-random generator (Mersenne Twister, java.util.Random, rand()/srand()) is fully predictable after observing a small amount of output, so any key or nonce derived from it is recoverable.",
       "Argyros & Kiayias 2012 (PRNG state recovery); CWE-338",
       "os.urandom / secrets, java.security.SecureRandom, crypto.randomBytes"),
    _e("null-cipher", "NULL", "NULL", "symmetric", Threat.LEGACY_BROKEN,
       "A NULL cipher suite performs no encryption at all; traffic is plaintext on the wire.",
       "RFC 5246 App. A.5 (NULL suites); " + C_8996, "AES-256-GCM or ChaCha20-Poly1305"),
    _e("export-cipher", "EXPORT", "EXPORT", "symmetric", Threat.LEGACY_BROKEN,
       "Export-grade suites are capped at 40-56 bit keys by design and enabled FREAK/Logjam downgrade attacks.",
       "FREAK 2015; " + C_LOGJAM, "AES-256-GCM"),
    _e("anon-kex", "ANON", "ANON", "protocol", Threat.LEGACY_BROKEN,
       "Anonymous (aNULL/ADH) key exchange has no peer authentication and is trivially machine-in-the-middled.",
       "RFC 5246; OWASP TLS guidance", "authenticated ECDHE/ML-KEM hybrid suites"),

    # ---------------- Grover-weakened ----------------
    _e("aes", "AES", "AES", "symmetric", Threat.QUANTUM_SAFE,
       "AES is a symmetric block cipher; Grover's algorithm halves the effective key strength, so the verdict depends on the key size.",
       "FIPS 197; " + C_GROVER + "; " + C_CNSA2, "AES-256-GCM"),
    _e("camellia", "Camellia", "Camellia", "symmetric", Threat.QUANTUM_SAFE,
       "Camellia is a 128-bit block cipher with AES-equivalent structure; Grover halves the key strength, so the verdict depends on key size.",
       "RFC 3713; ISO/IEC 18033-3; " + C_GROVER, "AES-256-GCM or Camellia-256"),
    _e("aria", "ARIA", "ARIA", "symmetric", Threat.QUANTUM_SAFE,
       "ARIA is the Korean block cipher standard with AES-like parameters; Grover halves its effective key strength.",
       "RFC 5794; " + C_GROVER, "AES-256-GCM or ARIA-256"),
    _e("seed", "SEED", "SEED", "symmetric", Threat.GROVER_WEAKENED,
       "SEED is fixed at a 128-bit key, giving only ~64-bit effective strength against Grover, and it is not FIPS approved.",
       "RFC 4269; " + C_GROVER, "AES-256-GCM"),
    _e("sm4", "SM4", "SM4", "symmetric", Threat.GROVER_WEAKENED,
       "SM4 is fixed at a 128-bit key, so Grover reduces it to ~64-bit effective strength.",
       "GB/T 32907; ISO/IEC 18033-3 Amd 1; " + C_GROVER, "AES-256-GCM"),
    _e("cast5", "CAST5", "CAST", "symmetric", Threat.LEGACY_BROKEN,
       "CAST5 (CAST-128) has a 64-bit block and is Sweet32-vulnerable; it is not FIPS approved.",
       "RFC 2144; " + C_SWEET32, "AES-256-GCM"),

    # ---------------- Hashes ----------------
    _e("sha-2", "SHA-2", "SHA-2", "hash", Threat.QUANTUM_SAFE,
       "SHA-2 has no structural break; the verdict depends on digest length because Grover reduces preimage cost to 2^(n/2) and BHT-style collision search is bounded by the classical 2^(n/2) birthday bound.",
       "FIPS 180-4; " + C_GROVER + "; " + C_CNSA2, "SHA-384 or SHA-512"),
    _e("sha-3", "SHA-3", "SHA-3", "hash", Threat.QUANTUM_SAFE,
       "SHA-3 (Keccak) has no structural break; Grover halves preimage resistance, so digests of 384 bits and up are the conservative choice.",
       "FIPS 202; " + C_GROVER, "SHA3-384 / SHA3-512"),
    _e("shake", "SHAKE", "SHA-3", "hash", Threat.QUANTUM_SAFE,
       "SHAKE is the Keccak extendable-output function; its security is capped by the capacity (SHAKE128 = 128-bit, SHAKE256 = 256-bit), so SHAKE128 is Grover-weakened.",
       "FIPS 202", "SHAKE256"),
    _e("blake2", "BLAKE2", "BLAKE2", "hash", Threat.QUANTUM_SAFE,
       "BLAKE2b/2s have no known break; at a 256-bit or larger digest they retain a 128-bit post-quantum preimage margin. Not FIPS approved.",
       "RFC 7693; Aumasson et al. 2013", "SHA-384 where FIPS validation is required"),
    _e("blake3", "BLAKE3", "BLAKE3", "hash", Threat.QUANTUM_SAFE,
       "BLAKE3 has a 256-bit output and no known break; not FIPS approved, so it fails a FIPS 140-3 boundary even though it is quantum-adequate.",
       "O'Connor et al. 2020", "SHA-384 where FIPS validation is required"),
    _e("ripemd", "RIPEMD", "RIPEMD", "hash", Threat.LEGACY_BROKEN,
       "RIPEMD-128 and the original RIPEMD are collision-broken; RIPEMD-160 has only 80-bit collision resistance and is not FIPS approved.",
       "Wang et al. 2004; Mendel et al. 2013", "SHA-256 / SHA-384"),
    _e("whirlpool", "Whirlpool", "Whirlpool", "hash", Threat.GROVER_WEAKENED,
       "Whirlpool has a 512-bit digest and no practical break, but rebound attacks reach 10 of 10 rounds in the compression function and it is not FIPS approved.",
       "Lamberger et al. 2010; ISO/IEC 10118-3", "SHA-512 / SHA3-512"),

    # ---------------- MAC / KDF ----------------
    _e("hmac", "HMAC", "HMAC", "mac", Threat.QUANTUM_SAFE,
       "HMAC's security reduces to the PRF property of the hash rather than collision resistance; with a >= 256-bit key and a modern hash it is quantum-adequate, and Grover only halves the key search.",
       "FIPS 198-1; Bellare 2006; " + C_GROVER, "HMAC-SHA-384 for CNSA 2.0"),
    _e("cmac", "CMAC", "CMAC", "mac", Threat.QUANTUM_SAFE,
       "CMAC inherits the strength of its block cipher; with AES-256 it is quantum-adequate.",
       "NIST SP 800-38B", "AES-256-CMAC"),
    _e("gmac", "GMAC", "GMAC", "mac", Threat.QUANTUM_SAFE,
       "GMAC inherits the strength of its block cipher and requires unique IVs; with AES-256 it is quantum-adequate.",
       C_38D, "AES-256-GMAC"),
    _e("poly1305", "Poly1305", "Poly1305", "mac", Threat.QUANTUM_SAFE,
       "Poly1305 is a one-time Wegman-Carter MAC with information-theoretic bounds; no quantum speed-up applies beyond key search.",
       "RFC 8439", "ChaCha20-Poly1305"),
    _e("pbkdf2", "PBKDF2", "PBKDF2", "kdf", Threat.QUANTUM_SAFE,
       "PBKDF2 is quantum-adequate as a construction, but its cost is linear in iterations only; Grover gives an attacker a quadratic speed-up on the password search, so iteration counts must be high and the underlying hash >= SHA-256.",
       "NIST SP 800-132; OWASP Password Storage Cheat Sheet", "Argon2id, or PBKDF2-HMAC-SHA-256 >= 600000 iterations"),
    _e("bcrypt", "bcrypt", "bcrypt", "kdf", Threat.QUANTUM_SAFE,
       "bcrypt is a memory-light but GPU-resistant password hash; it truncates inputs at 72 bytes and has no quantum-specific break.",
       "Provos & Mazieres 1999", "Argon2id"),
    _e("scrypt", "scrypt", "scrypt", "kdf", Threat.QUANTUM_SAFE,
       "scrypt is a memory-hard password KDF with no quantum-specific break.",
       "RFC 7914", "Argon2id"),
    _e("argon2", "Argon2", "Argon2", "kdf", Threat.QUANTUM_SAFE,
       "Argon2id is the current recommended memory-hard password KDF; no quantum-specific break beyond Grover on the password space.",
       "RFC 9106", "Argon2id (keep as is)"),
    _e("hkdf", "HKDF", "HKDF", "kdf", Threat.QUANTUM_SAFE,
       "HKDF is an extract-then-expand KDF whose security follows the underlying HMAC; quantum-adequate with SHA-256 or better.",
       "RFC 5869", "HKDF-SHA-384"),
    _e("chacha20", "ChaCha20", "ChaCha20", "symmetric", Threat.QUANTUM_SAFE,
       "ChaCha20 uses a 256-bit key, leaving a 128-bit margin after Grover; the best cryptanalysis reaches only 7 of 20 rounds.",
       "RFC 8439; Aumasson et al. 2008", "ChaCha20-Poly1305 (keep as is)"),
    _e("xchacha20", "XChaCha20", "ChaCha20", "symmetric", Threat.QUANTUM_SAFE,
       "XChaCha20 extends ChaCha20 with a 192-bit nonce via HChaCha20; the 256-bit key leaves a 128-bit post-Grover margin.",
       "draft-irtf-cfrg-xchacha", "XChaCha20-Poly1305 (keep as is)"),
    _e("salsa20", "Salsa20", "Salsa20", "symmetric", Threat.QUANTUM_SAFE,
       "Salsa20 with a 256-bit key retains a 128-bit post-Grover margin; ChaCha20 is the preferred successor.",
       "Bernstein 2008 (eSTREAM portfolio)", "ChaCha20-Poly1305"),

    # ---------------- PQC ----------------
    _e("ml-kem", "ML-KEM", "ML-KEM", "asymmetric", Threat.PQC,
       "ML-KEM (formerly CRYSTALS-Kyber) is the NIST-standardised module-lattice KEM; its security rests on Module-LWE, for which no efficient quantum algorithm is known.",
       C_203, "target state - keep, prefer ML-KEM-768 or higher", "FIPS 203 standard"),
    _e("ml-dsa", "ML-DSA", "ML-DSA", "asymmetric", Threat.PQC,
       "ML-DSA (formerly CRYSTALS-Dilithium) is the NIST-standardised module-lattice signature scheme based on Module-LWE/SIS.",
       C_204, "target state - keep, prefer ML-DSA-65 or ML-DSA-87", "FIPS 204 standard"),
    _e("slh-dsa", "SLH-DSA", "SLH-DSA", "asymmetric", Threat.PQC,
       "SLH-DSA (formerly SPHINCS+) is the stateless hash-based signature standard; its security rests only on the hash function, making it the most conservative PQC signature.",
       C_205, "target state - keep; large signatures are the trade-off", "FIPS 205 standard"),
    _e("falcon", "Falcon", "Falcon", "asymmetric", Threat.PQC,
       "Falcon (to be standardised as FN-DSA) is an NTRU-lattice signature with compact signatures; its floating-point sampler is implementation-sensitive.",
       C_206, "acceptable; ML-DSA is the safer default until FIPS 206 is final", "draft standard"),
    _e("hqc", "HQC", "HQC", "asymmetric", Threat.PQC,
       "HQC is a code-based KEM selected by NIST in March 2025 as a backup to ML-KEM, resting on the quasi-cyclic syndrome decoding problem.",
       C_8545, "acceptable as a hedge alongside ML-KEM", "selected 2025, standard in progress"),
    _e("bike", "BIKE", "BIKE", "asymmetric", Threat.PQC,
       "BIKE is a QC-MDPC code-based KEM; it was a round-4 candidate that was not selected, so it is post-quantum but not standardised.",
       C_8545, "ML-KEM-768 for standardised deployments", "not selected"),
    _e("classic-mceliece", "Classic McEliece", "Classic McEliece", "asymmetric", Threat.PQC,
       "Classic McEliece is the most conservative code-based KEM (unbroken since 1978) but has ~1 MB public keys; ISO standardisation is in progress rather than NIST.",
       C_8545 + "; ISO/IEC 18033-2 amendment work", "acceptable where huge keys are tolerable; ML-KEM otherwise"),
    _e("xmss", "XMSS", "XMSS", "asymmetric", Threat.PQC,
       "XMSS is a stateful hash-based signature scheme approved by NIST SP 800-208; state reuse catastrophically breaks it, so key-state management is mandatory.",
       "NIST SP 800-208; RFC 8391", "acceptable for firmware signing with strict state handling; SLH-DSA if statelessness is needed",
       "approved with stateful-key caveats"),
    _e("lms", "LMS", "LMS", "asymmetric", Threat.PQC,
       "LMS/HSS is a stateful hash-based signature scheme approved by NIST SP 800-208, widely used for firmware signing; one-time-key reuse is fatal.",
       "NIST SP 800-208; RFC 8554", "acceptable for firmware signing with strict state handling",
       "approved with stateful-key caveats"),
    _e("ntru", "NTRU", "NTRU", "asymmetric", Threat.PQC,
       "NTRU is a lattice KEM that was a NIST finalist but was not selected for standardisation.",
       "NIST IR 8413 (round-3 report)", "ML-KEM-768", "not selected"),
    _e("frodokem", "FrodoKEM", "FrodoKEM", "asymmetric", Threat.PQC,
       "FrodoKEM is a plain-LWE KEM with conservative (unstructured) lattices and larger keys; recommended by BSI/ANSSI though not NIST-selected.",
       "BSI TR-02102-1; NIST IR 8413", "acceptable as a conservative hedge; ML-KEM-768 for interoperability"),
    _e("sike", "SIKE", "SIKE", "asymmetric", Threat.LEGACY_BROKEN,
       "SIKE/SIDH was broken classically in 2022 by the Castryck-Decru key-recovery attack, which runs in about an hour on one core. It must be removed regardless of quantum timelines.",
       "Castryck & Decru 2022 (EUROCRYPT 2023)", "ML-KEM-768", "withdrawn"),
    _e("rainbow", "Rainbow", "Rainbow", "asymmetric", Threat.LEGACY_BROKEN,
       "The Rainbow multivariate signature scheme was broken classically by Beullens in 2022 (weekend of laptop time at the level-1 parameter set).",
       "Beullens 2022 (CRYPTO)", "ML-DSA-65", "withdrawn"),

    # ---------------- Protocols ----------------
    _e("sslv2", "SSLv2", "SSL", "protocol", Threat.LEGACY_BROKEN,
       "SSLv2 is prohibited; it enables the DROWN cross-protocol attack against otherwise healthy TLS servers.",
       "RFC 6176; DROWN 2016 (CVE-2016-0800)", "TLS 1.3 with a hybrid PQC group", "prohibited"),
    _e("sslv3", "SSLv3", "SSL", "protocol", Threat.LEGACY_BROKEN,
       "SSLv3 is deprecated by RFC 7568; the POODLE padding-oracle attack recovers plaintext byte by byte.",
       C_7568 + "; POODLE 2014 (CVE-2014-3566)", "TLS 1.3", "deprecated"),
    _e("tls1.0", "TLS 1.0", "TLS", "protocol", Threat.LEGACY_BROKEN,
       "TLS 1.0 is deprecated by RFC 8996; it mandates SHA-1/MD5 in the PRF and is exposed to BEAST-class CBC attacks.",
       C_8996, "TLS 1.3 with X25519MLKEM768", "deprecated"),
    _e("tls1.1", "TLS 1.1", "TLS", "protocol", Threat.LEGACY_BROKEN,
       "TLS 1.1 is deprecated by RFC 8996; it still relies on SHA-1 and MD5 in the PRF and offers no AEAD suites.",
       C_8996, "TLS 1.3 with X25519MLKEM768", "deprecated"),
    _e("tls1.2", "TLS 1.2", "TLS", "protocol", Threat.SHOR_BROKEN,
       "TLS 1.2 is not classically broken when configured with AEAD suites, but every standard key exchange it offers (ECDHE, DHE, RSA) is Shor-breakable, so recorded sessions are retro-decryptable. It also has no hybrid PQC group.",
       "RFC 5246; " + C_8547 + "; " + C_SHOR, "TLS 1.3 with the X25519MLKEM768 hybrid group"),
    _e("tls1.3", "TLS 1.3", "TLS", "protocol", Threat.SHOR_BROKEN,
       "TLS 1.3 is the current best classical protocol, but with a classical group (X25519/secp256r1) the handshake secret is Shor-recoverable from recorded traffic. Negotiating a hybrid group such as X25519MLKEM768 moves it to quantum-safe.",
       "RFC 8446; draft-ietf-tls-ecdhe-mlkem; " + C_CNSA2, "enable the X25519MLKEM768 (or SecP384r1MLKEM1024) group"),
    _e("ssh", "SSH", "SSH", "protocol", Threat.SHOR_BROKEN,
       "SSH transport key exchange defaults to classical ECDH/DH groups, so recorded sessions are retro-decryptable; OpenSSH 9.x offers mlkem768x25519-sha256 as a hybrid.",
       "RFC 4253; OpenSSH 9.0+ release notes", "mlkem768x25519-sha256 key exchange"),
    _e("ipsec", "IPsec/IKEv2", "IPsec", "protocol", Threat.SHOR_BROKEN,
       "IKEv2 key exchange uses classical DH/ECDH groups; RFC 9370 adds multiple key exchanges so a PQC KEM can be layered in.",
       "RFC 7296; RFC 9370", "IKEv2 with an additional ML-KEM key exchange (RFC 9370)"),
    _e("wireguard", "WireGuard", "WireGuard", "protocol", Threat.SHOR_BROKEN,
       "WireGuard's Noise_IK handshake is built on X25519, which is Shor-breakable; its optional pre-shared key is the documented stop-gap for post-quantum resistance.",
       "WireGuard whitepaper (Donenfeld 2017)", "enable a PSK now; migrate to a PQC-hybrid tunnel"),
    _e("kerberos", "Kerberos", "Kerberos", "protocol", Threat.GROVER_WEAKENED,
       "Kerberos v5 is symmetric-key based, so it is not Shor-breakable, but RC4-HMAC and single-DES enctypes remain widely enabled and are classically broken.",
       "RFC 4120; RFC 8429 (deprecate DES and RC4 in Kerberos)", "AES256-CTS-HMAC-SHA384-192 enctype only"),
    _e("jwt", "JWT", "JWT", "protocol", Threat.UNKNOWN,
       "A JWT's security is entirely that of its 'alg': HS256 is symmetric and quantum-adequate, RS256/ES256 are Shor-breakable, and 'none' is no security at all.",
       "RFC 7519; RFC 8725 (JWT BCP)", "depends on alg; audit each issuer"),

    # ---------------- Modes and padding ----------------
    _e("ecb", "ECB", "ECB", "mode", Threat.LEGACY_BROKEN,
       "ECB mode is deterministic: identical plaintext blocks produce identical ciphertext blocks, leaking structure regardless of key size. It provides no semantic security.",
       C_38A + " App. C", "AES-256-GCM (AEAD)"),
    _e("cbc", "CBC", "CBC", "mode", Threat.GROVER_WEAKENED,
       "CBC provides confidentiality only. Without a separate MAC over the ciphertext it is vulnerable to padding-oracle attacks (POODLE, Lucky13); it also needs an unpredictable IV.",
       C_38A + "; Vaudenay 2002 (padding oracle)", "AES-256-GCM or encrypt-then-MAC"),
    _e("ctr", "CTR", "CTR", "mode", Threat.QUANTUM_SAFE,
       "CTR mode is sound for confidentiality but is unauthenticated and catastrophically fails on nonce reuse; pair it with a MAC.",
       C_38A, "AES-256-GCM"),
    _e("gcm", "GCM", "GCM", "mode", Threat.QUANTUM_SAFE,
       "GCM is an approved AEAD mode; its main hazard is IV reuse, which destroys both confidentiality and authenticity.",
       C_38D, "keep, with a 96-bit random or counter IV"),
    _e("ccm", "CCM", "CCM", "mode", Threat.QUANTUM_SAFE,
       "CCM is an approved AEAD mode (encrypt-then-MAC with CBC-MAC).",
       "NIST SP 800-38C", "keep"),
    _e("siv", "SIV", "SIV", "mode", Threat.QUANTUM_SAFE,
       "AES-GCM-SIV / AES-SIV are nonce-misuse-resistant AEAD modes, the safest choice where nonce uniqueness cannot be guaranteed.",
       "RFC 5297; RFC 8452", "keep"),
    _e("ocb", "OCB", "OCB", "mode", Threat.QUANTUM_SAFE,
       "OCB3 is an efficient AEAD mode; it is not on the NIST approved list, so it fails a FIPS boundary.",
       "RFC 7253", "AES-256-GCM where FIPS validation is required"),
    _e("xts", "XTS", "XTS", "mode", Threat.QUANTUM_SAFE,
       "XTS is the approved mode for storage encryption; it is length-preserving and provides no authentication, which is inherent to the use case.",
       "NIST SP 800-38E", "keep for disk encryption only"),
    _e("pkcs1v15", "PKCS#1 v1.5", "RSA", "padding", Threat.LEGACY_BROKEN,
       "RSA PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher's adaptive chosen-ciphertext oracle, revived as ROBOT in 2017; the padding is broken independently of the modulus size.",
       C_BLEICHENBACHER + "; RFC 8017 sec. 7.2 warning", "RSA-OAEP as an interim fix, ML-KEM-768 as the target"),
    _e("no-padding", "NoPadding", "RSA", "padding", Threat.LEGACY_BROKEN,
       "Textbook RSA with no padding is deterministic and malleable; small-exponent and common-modulus attacks apply directly.",
       "RFC 8017; Boneh 1999 (twenty years of attacks on RSA)", "RSA-OAEP interim, ML-KEM-768 target"),
    _e("oaep", "OAEP", "RSA", "padding", Threat.SHOR_BROKEN,
       "OAEP is the sound RSA encryption padding; the residual risk is the RSA trapdoor itself, which Shor breaks.",
       "RFC 8017", "ML-KEM-768"),
]

KB: dict[str, AlgoEntry] = {e.key: e for e in _ENTRIES}

# --------------------------------------------------------------------------
# Alias table: everything a detector might emit -> KB key.
# --------------------------------------------------------------------------
ALIASES: dict[str, str] = {}


def _alias(key: str, *names: str) -> None:
    for n in names:
        ALIASES[_slug(n)] = key


def _slug(name: Any) -> str:
    """Lowercase, collapse separators. 'RSA_2048' / 'rsa-2048' / 'RSA 2048' -> 'rsa-2048'."""
    s = str(name or "").strip().lower()
    s = s.replace("\\", "/").split("/")[-1]
    s = re.sub(r"[\s_.:]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


for _k in KB:
    ALIASES[_k] = _k

_alias("rsa", "rsa", "rsaencryption", "rsa-encryption", "rsa_pkcs1", "rsapublickey", "rsaprivatekey",
       "rsa-pss", "rsassa", "rsa-oaep", "rsakey", "pkcs1", "sha256withrsa", "sha1withrsa", "md5withrsa",
       "sha256withrsaencryption", "sha1withrsaencryption", "md5withrsaencryption", "sha384withrsaencryption",
       "sha512withrsaencryption", "rsa-sha256", "rsa-sha1", "rs256", "rs384", "rs512", "ps256", "ps384", "ps512",
       "ssh-rsa", "rsa2048", "rsa4096", "rsa1024", "rsa512", "rsa3072")
_alias("rsassa-pss", "rsassa-pss", "rsapss")
_alias("rsaes-oaep", "rsaes-oaep")
_alias("dsa", "dsa", "dsakey", "dsapublickey", "dsawithsha1", "dsa-sha256", "sha1withdsa", "ssh-dss", "dss")
_alias("dh", "dh", "dhe", "diffie-hellman", "diffiehellman", "dh-key-exchange", "dhparam", "dhparams",
       "modp", "ffdhe", "dh-group", "edh", "dh1024", "dh2048")
_alias("ecdsa", "ecdsa", "ecdsa-sha2", "ecdsawithsha256", "ecdsa-with-sha256", "ecdsa-with-sha1",
       "ecdsa-with-sha384", "ecdsa-with-sha512", "es256", "es384", "es512", "es256k",
       "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sha256withecdsa")
_alias("ecdh", "ecdh", "ecdhe", "ecdh-key-exchange", "ecdhe-rsa", "ecdhe-ecdsa", "ecies-kem")
_alias("ec", "ec", "ecc", "elliptic-curve", "ellipticcurve", "id-ecpublickey", "ecpublickey", "eckey",
       "prime-field-ec")
_alias("x25519", "x25519", "curve25519", "montgomery25519", "x25519-key-exchange")
_alias("x448", "x448", "curve448")
_alias("ed25519", "ed25519", "eddsa", "edwards25519", "ssh-ed25519", "eddsa25519", "ed25519ph", "ed25519ctx")
_alias("ed448", "ed448", "edwards448", "ed448ph", "ssh-ed448")
_alias("elgamal", "elgamal", "el-gamal")
_alias("ecies", "ecies", "ecies-kem-dem")
_alias("ecmqv", "ecmqv", "mqv")
_alias("sm2", "sm2", "sm2sign", "sm2-with-sm3")
_alias("paillier", "paillier")
_alias("bls", "bls", "bls-signature", "bls12-381", "bls12381", "bls-12-381", "boneh-lynn-shacham")

_alias("md5", "md5", "md-5", "hashlib-md5", "md5sum")
_alias("md4", "md4", "md-4", "ntlm")
_alias("md2", "md2", "md-2")
_alias("sha-0", "sha-0", "sha0")
_alias("sha-1", "sha-1", "sha1", "sha", "hashlib-sha1", "sha1sum", "hmac-sha1", "sha-160")
_alias("des", "des", "des-cbc", "des-ecb", "descbc", "single-des", "des56")
_alias("3des", "3des", "des3", "desede", "triple-des", "tripledes", "des-ede3", "des-ede3-cbc",
       "des-ede", "tdea", "3des-cbc", "3des-ede-cbc")
_alias("rc4", "rc4", "arc4", "arcfour", "rc4-md5", "rc4-sha", "arcfour128", "arcfour256")
_alias("rc2", "rc2", "rc2-cbc")
_alias("rc5", "rc5")
_alias("blowfish", "blowfish", "bf", "bf-cbc", "bf-ecb")
_alias("idea", "idea")
_alias("tea", "tea", "xtea", "xxtea")
_alias("cast5", "cast5", "cast-128", "cast128", "cast")
_alias("crc32", "crc32", "crc-32", "crc", "adler32")
_alias("md5crypt", "md5crypt", "md5-crypt", "crypt-md5")
_alias("weak-prng", "weak-prng", "math-random", "mt19937", "mersenne-twister", "java-util-random",
       "rand", "srand", "random-random", "insecure-random")
_alias("null-cipher", "null", "null-cipher", "tls-null-with-null-null", "enull")
_alias("export-cipher", "export", "export-cipher", "exp", "export40", "des40", "rc4-40", "rc2-40")
_alias("anon-kex", "anon", "adh", "anull", "ecdh-anon", "dh-anon")

_alias("aes", "aes", "aes-128", "aes-192", "aes-256", "aes128", "aes192", "aes256", "rijndael",
       "aesgcm", "aes-gcm", "aes-cbc", "aes-ecb", "aes-ctr", "aes-gcm-siv", "aeskw", "aes-kw", "aes-wrap")
_alias("camellia", "camellia", "camellia-128", "camellia-192", "camellia-256")
_alias("aria", "aria")
_alias("seed", "seed")
_alias("sm4", "sm4", "sms4")
_alias("chacha20", "chacha20", "chacha", "chacha20-poly1305", "chacha20poly1305")
_alias("xchacha20", "xchacha20", "xchacha20-poly1305", "xchacha")
_alias("salsa20", "salsa20", "salsa")

_alias("sha-2", "sha-2", "sha2", "sha-224", "sha224", "sha-256", "sha256", "sha-384", "sha384",
       "sha-512", "sha512", "sha-512-224", "sha-512-256", "sha512-224", "sha512-256",
       "hashlib-sha256", "sha2-256", "sha2-384", "sha2-512")
_alias("sha-3", "sha-3", "sha3", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "keccak", "keccak-256")
_alias("shake", "shake", "shake128", "shake256", "shake-128", "shake-256", "cshake")
_alias("blake2", "blake2", "blake2b", "blake2s", "blake-2")
_alias("blake3", "blake3", "blake-3")
_alias("ripemd", "ripemd", "ripemd160", "ripemd-160", "ripemd128", "rmd160")
_alias("whirlpool", "whirlpool")

_alias("hmac", "hmac", "hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-md5", "hs256", "hs384", "hs512",
       "hmacsha256", "hmacsha1")
_alias("cmac", "cmac", "aes-cmac")
_alias("gmac", "gmac", "aes-gmac")
_alias("poly1305", "poly1305")
_alias("pbkdf2", "pbkdf2", "pbkdf2-hmac", "pbkdf2hmac", "pbkdf2-sha256", "pbkdf-2")
_alias("bcrypt", "bcrypt")
_alias("scrypt", "scrypt")
_alias("argon2", "argon2", "argon2i", "argon2d", "argon2id")
_alias("hkdf", "hkdf", "hkdf-sha256", "hkdf-expand")

_alias("ml-kem", "ml-kem", "mlkem", "kyber", "crystals-kyber", "ml-kem-512", "ml-kem-768", "ml-kem-1024",
       "kyber512", "kyber768", "kyber1024", "x25519mlkem768", "x25519-mlkem768", "secp384r1mlkem1024",
       "mlkem768x25519-sha256", "fips203")
_alias("ml-dsa", "ml-dsa", "mldsa", "dilithium", "crystals-dilithium", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
       "dilithium2", "dilithium3", "dilithium5", "fips204")
_alias("slh-dsa", "slh-dsa", "slhdsa", "sphincs", "sphincs+", "sphincsplus", "slh-dsa-sha2-128s",
       "slh-dsa-shake-256f", "fips205")
_alias("falcon", "falcon", "falcon-512", "falcon-1024", "fn-dsa", "fndsa")
_alias("hqc", "hqc", "hqc-128", "hqc-192", "hqc-256")
_alias("bike", "bike")
_alias("classic-mceliece", "classic-mceliece", "mceliece", "classicmceliece", "mceliece348864")
_alias("xmss", "xmss", "xmssmt", "xmss-mt")
_alias("lms", "lms", "hss", "lms-hss", "hss-lms")
_alias("ntru", "ntru", "ntruprime", "ntru-hps", "sntrup761")
_alias("frodokem", "frodokem", "frodo")
_alias("sike", "sike", "sidh")
_alias("rainbow", "rainbow")

_alias("sslv2", "sslv2", "ssl2", "ssl-2", "sslv2-method", "ssl2-method")
_alias("sslv3", "sslv3", "ssl3", "ssl-3", "sslv3-method", "ssl3-method")
_alias("tls1.0", "tls1-0", "tls10", "tlsv1", "tlsv1-0", "tls-1-0", "protocol-tlsv1")
_alias("tls1.1", "tls1-1", "tls11", "tlsv1-1", "tls-1-1", "protocol-tlsv1-1")
_alias("tls1.2", "tls1-2", "tls12", "tlsv1-2", "tls-1-2", "protocol-tlsv1-2")
_alias("tls1.3", "tls1-3", "tls13", "tlsv1-3", "tls-1-3", "protocol-tlsv1-3")
_alias("ssh", "ssh", "ssh2", "openssh", "sshv2")
_alias("ipsec", "ipsec", "ikev2", "ike", "isakmp")
_alias("wireguard", "wireguard", "wg", "noise-ik")
_alias("kerberos", "kerberos", "krb5", "gssapi")
_alias("jwt", "jwt", "jws", "jwe", "json-web-token")

_alias("ecb", "ecb", "mode-ecb", "aes-ecb-mode")
_alias("cbc", "cbc", "mode-cbc")
_alias("ctr", "ctr", "mode-ctr", "ofb", "cfb")
_alias("gcm", "gcm", "mode-gcm")
_alias("ccm", "ccm", "mode-ccm", "eax")
_alias("siv", "siv", "gcm-siv", "aes-siv")
_alias("ocb", "ocb", "ocb3")
_alias("xts", "xts", "xts-plain64")
_alias("pkcs1v15", "pkcs1v15", "pkcs1-v1-5", "pkcs1v1-5", "pkcs-1-v1-5", "rsa-pkcs1-padding", "pkcs1padding")
_alias("no-padding", "nopadding", "no-padding", "raw-rsa", "textbook-rsa")
_alias("oaep", "oaep", "rsa-oaep-padding", "oaepwithsha-256andmgf1padding")

# Families that carry no size suffix in their canonical display name.
_NO_SIZE_SUFFIX = {
    "ed25519", "ed448", "x25519", "x448", "3des", "des", "rc4", "rc2", "blowfish", "md5", "md4", "md2",
    "sha-0", "sha-1", "chacha20", "xchacha20", "salsa20", "poly1305", "crc32", "md5crypt", "weak-prng",
    "null-cipher", "export-cipher", "anon-kex", "sslv2", "sslv3", "tls1.0", "tls1.1", "tls1.2", "tls1.3",
    "ssh", "ipsec", "wireguard", "kerberos", "jwt", "ecb", "cbc", "ctr", "gcm", "ccm", "siv", "ocb", "xts",
    "pkcs1v15", "no-padding", "oaep", "argon2", "bcrypt", "scrypt", "sike", "rainbow", "idea", "tea",
    "cast5", "rc5", "sm4", "seed", "bike", "whirlpool", "blake3",
}

_SIZE_RE = re.compile(r"^(?P<base>.*?)-?(?P<size>\d{2,5})$")


# --------------------------------------------------------------------------
# Parameter access helpers (tolerant: Params dataclass, dict, or None)
# --------------------------------------------------------------------------
def _pget(params: Any, name: str, default: Any = None) -> Any:
    if params is None:
        return default
    if isinstance(params, dict):
        val = params.get(name, default)
    else:
        val = getattr(params, name, default)
    return default if val is None else val


def _extra(params: Any) -> dict:
    val = _pget(params, "extra", {}) or {}
    return val if isinstance(val, dict) else {}


def _int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        m = re.search(r"\d+", str(value))
        return int(m.group(0)) if m else None
    except (TypeError, ValueError):
        return None


def _key_size(params: Any) -> Optional[int]:
    size = _int_or_none(_pget(params, "key_size"))
    if size is None:
        ex = _extra(params)
        for k in ("key_size", "keysize", "bits", "modulus_bits", "size", "strength"):
            size = _int_or_none(ex.get(k))
            if size is not None:
                break
    return size


def _mode(params: Any) -> str:
    return str(_pget(params, "mode", "") or _extra(params).get("mode", "") or "")


def _padding(params: Any) -> str:
    return str(_pget(params, "padding", "") or _extra(params).get("padding", "") or "")


# --------------------------------------------------------------------------
# Family / curve normalisation
# --------------------------------------------------------------------------
def normalize_family(name: Any) -> str:
    """Map any detector spelling to a canonical KB key.

    Returns the slug itself when unknown, so callers can still report it.
    """
    slug = _slug(name)
    if not slug:
        return ""
    if slug in ALIASES:
        return ALIASES[slug]
    # strip a trailing size ("mlkem768", "aes256gcm" -> handled by mode split first)
    for suffix in ("-cbc", "-ecb", "-gcm", "-ctr", "-ccm", "-ofb", "-cfb", "-xts", "-siv", "-key", "-cipher",
                   "-hash", "-algorithm", "-signature", "-sign", "-verify", "-padding", "-mode"):
        if slug.endswith(suffix):
            trimmed = slug[: -len(suffix)]
            if trimmed in ALIASES:
                return ALIASES[trimmed]
    m = _SIZE_RE.match(slug)
    if m:
        base = m.group("base").strip("-")
        if base in ALIASES:
            return ALIASES[base]
    # last resort: longest alias that the slug starts with
    best = ""
    for alias in ALIASES:
        if len(alias) > len(best) and (slug.startswith(alias + "-") or slug == alias):
            best = alias
    return ALIASES[best] if best else slug


def _embedded_size(name: Any) -> Optional[int]:
    """Pull a size out of a name like 'RSA-2048' or 'ML-KEM-768' when params lack one."""
    slug = _slug(name)
    if slug in ALIASES and not _SIZE_RE.match(slug):
        return None
    m = _SIZE_RE.match(slug)
    if not m:
        return None
    base = m.group("base").strip("-")
    if base and (base in ALIASES or normalize_family(base) in KB):
        return int(m.group("size"))
    return None


def normalize_curve(name: Any) -> str:
    slug = _slug(name)
    if not slug:
        return ""
    if slug in CURVES:
        return slug
    if slug in _CURVE_ALIASES:
        return _CURVE_ALIASES[slug]
    lowered = {k.lower(): k for k in CURVES}
    if slug in lowered:
        return lowered[slug]
    compact = slug.replace("-", "")
    for k in CURVES:
        if k.lower().replace("-", "") == compact:
            return k
    if compact in {a.replace("-", "") for a in _CURVE_ALIASES}:
        for a, target in _CURVE_ALIASES.items():
            if a.replace("-", "") == compact:
                return target
    return slug


def curve_info(name: Any) -> Optional[dict[str, Any]]:
    key = normalize_curve(name)
    if key in CURVES:
        return CURVES[key]
    lowered = {k.lower(): v for k, v in CURVES.items()}
    return lowered.get(key)


def entry_for(family: Any, params: Any = None) -> Optional[AlgoEntry]:
    """Return the KB row for a family (params only used to disambiguate)."""
    key = normalize_family(family)
    entry = KB.get(key)
    if entry is None and params is not None:
        curve = _pget(params, "curve")
        if curve:
            info = curve_info(curve)
            if info:
                return KB.get("ec")
    return entry


def citation(family: Any, params: Any = None) -> str:
    entry = entry_for(family, params)
    return entry.citation if entry else "no KB entry; verdict withheld"


def is_pqc(family: Any) -> bool:
    entry = entry_for(family)
    return bool(entry and entry.threat is Threat.PQC)


def all_entries() -> list[dict]:
    """Full auditable dump, sorted, for the report appendix / CBOM evidence."""
    return [e.as_dict() for e in sorted(_ENTRIES, key=lambda x: (x.category, x.key))]


# --------------------------------------------------------------------------
# Per-family classifiers
# --------------------------------------------------------------------------
def _floor_note(key: str, size: Optional[int]) -> str:
    floor = KEY_SIZE_FLOORS.get(key)
    if size is None or floor is None or floor > 100000:
        return ""
    if size < floor:
        return (f" It is also below the {floor}-bit classical floor of SP 800-131A r2, "
                f"so {size} bits is inadequate today even without a quantum computer.")
    return ""


def _classify_factoring(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    size = _key_size(params)
    reason = entry.reason
    if size is None:
        reason += " The key size could not be determined from the source, so it is treated at the family level."
    else:
        reason += f" Observed modulus size: {size} bits."
        reason += _floor_note(entry.key, size)
        if size >= 3072:
            reason += (" A larger modulus buys classical margin but no quantum margin: "
                       "Shor's cost grows only polynomially in the key size.")
    pad = _slug(_padding(params))
    if pad and normalize_family(pad) in ("pkcs1v15", "no-padding"):
        pad_entry = KB[normalize_family(pad)]
        reason += " " + pad_entry.reason
    return Threat.SHOR_BROKEN, reason


def _classify_ec(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    reason = entry.reason
    curve_raw = _pget(params, "curve") or _extra(params).get("curve")
    size = _key_size(params)
    info = curve_info(curve_raw) if curve_raw else None
    if info:
        reason += (f" Curve {info['display']} ({info['bits']}-bit field, {info['strength']}-bit classical "
                   f"security; {info['note']}).")
        if info["strength"] < 112:
            reason += (" That curve is already below the 112-bit classical floor of SP 800-131A r2 and is "
                       "breakable without any quantum computer.")
        elif not info["approved"]:
            reason += " It is also outside the NIST-approved curve set of SP 800-186."
    elif curve_raw:
        reason += f" Curve '{curve_raw}' is not in the ECDAT curve table; treated at the family level."
    elif size:
        reason += f" Observed field size: {size} bits (~{size // 2}-bit classical security)."
        if size < KEY_SIZE_FLOORS.get(entry.key, 224):
            reason += " That is below the SP 800-131A r2 classical floor."
    else:
        reason += " No curve was recoverable from the source, so it is treated at the family level."
    return Threat.SHOR_BROKEN, reason


def _classify_symmetric(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    """AES / Camellia / ARIA: verdict is a function of key size, then mode."""
    size = _key_size(params)
    mode = _slug(_mode(params))
    mode_key = normalize_family(mode) if mode else ""
    reason = entry.reason

    if size is None:
        threat = Threat.GROVER_WEAKENED
        reason += (" The key size could not be determined; ECDAT assumes the 128-bit default of most APIs, "
                   "which Grover reduces to a ~64-bit search. Confirm the key size to refine this.")
    elif size <= 64:
        threat = Threat.LEGACY_BROKEN
        reason += f" A {size}-bit key is brute-forceable classically."
    elif size < 128:
        threat = Threat.LEGACY_BROKEN
        reason += f" A {size}-bit key is below the 128-bit floor and inadequate classically."
    elif size < 256:
        threat = Threat.GROVER_WEAKENED
        reason += (f" A {size}-bit key leaves ~{size // 2}-bit effective strength against Grover; "
                   f"CNSA 2.0 requires 256-bit symmetric keys for national security systems.")
    else:
        threat = Threat.QUANTUM_SAFE
        reason += (f" A {size}-bit key retains ~{size // 2}-bit effective strength against Grover, "
                   f"which meets CNSA 2.0.")

    if mode_key == "ecb":
        threat = Threat.LEGACY_BROKEN
        reason += (" Critically, the mode is ECB: " + KB["ecb"].reason +
                   " The key size is irrelevant while this mode is in use.")
    elif mode_key == "cbc":
        if threat in (Threat.QUANTUM_SAFE,):
            threat = Threat.GROVER_WEAKENED
        reason += " Mode is CBC: " + KB["cbc"].reason
    elif mode_key in ("ctr", "xts") and threat is Threat.QUANTUM_SAFE:
        reason += f" Mode {mode.upper()} is unauthenticated; pair it with a MAC or move to an AEAD mode."
    return threat, reason


def _classify_sha2(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    size = _key_size(params) or _embedded_size(label) or _int_or_none(_extra(params).get("variant"))
    reason = entry.reason
    if size is None:
        return Threat.UNKNOWN, reason + " The digest length could not be determined, so no verdict is issued."
    if size < 224:
        return Threat.LEGACY_BROKEN, reason + f" A {size}-bit digest is below every current floor."
    if size < CNSA2_HASH_FLOOR:
        return (Threat.GROVER_WEAKENED,
                reason + (f" A {size}-bit digest gives {size // 2}-bit collision resistance classically and a "
                          f"{size // 2}-bit preimage margin under Grover; CNSA 2.0 requires SHA-384 or larger "
                          f"for national security systems, so this is adequate for integrity today but is not "
                          f"the CNSA 2.0 target."))
    return (Threat.QUANTUM_SAFE,
            reason + f" A {size}-bit digest keeps a {size // 2}-bit margin under Grover and meets CNSA 2.0.")


def _classify_sha3(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    threat, reason = _classify_sha2(entry, params, label)
    if threat is Threat.UNKNOWN:
        return Threat.QUANTUM_SAFE, entry.reason + " Digest length unknown; SHA-3 defaults are 256 bits or more."
    return threat, reason


def _classify_shake(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    size = _key_size(params) or _embedded_size(label)
    if size and size <= 128:
        return (Threat.GROVER_WEAKENED,
                entry.reason + " SHAKE128 caps at a 128-bit security level, leaving ~64 bits against Grover.")
    return Threat.QUANTUM_SAFE, entry.reason + " SHAKE256 provides a 256-bit capacity, which is quantum-adequate."


def _classify_hmac(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    ex = _extra(params)
    inner = ex.get("hash") or ex.get("hash_alg") or ""
    if not inner:
        slug = _slug(label)
        m = re.match(r"^hmac-?(.*)$", slug)
        if m and m.group(1):
            inner = m.group(1)
    inner_key = normalize_family(inner) if inner else ""
    reason = entry.reason
    if inner_key in ("md5", "md4", "md2", "sha-0"):
        return (Threat.LEGACY_BROKEN,
                reason + f" The underlying hash is {KB[inner_key].display}, which is disallowed for all keyed "
                         f"use by SP 800-131A r2 even though HMAC does not depend on collision resistance.")
    if inner_key == "sha-1":
        return (Threat.GROVER_WEAKENED,
                reason + " The underlying hash is SHA-1: HMAC-SHA-1 is not practically broken, but SP 800-131A r2 "
                         "phases it out and it fails a CNSA 2.0 review.")
    if inner_key in ("sha-2", "sha-3", "blake2", "blake3"):
        inner_size = _key_size(params) or _embedded_size(inner)
        if inner_size and inner_size < 256:
            return (Threat.GROVER_WEAKENED,
                    reason + f" The underlying digest is {inner_size} bits, below the 256-bit comfort margin.")
        return Threat.QUANTUM_SAFE, reason + f" Underlying hash: {inner or 'SHA-2 family'}."
    return Threat.QUANTUM_SAFE, reason


def _classify_pqc(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    size = _key_size(params) or _embedded_size(label)
    reason = entry.reason
    pset = ""
    if size:
        pset = f"{entry.key}-{size}"
        meta = PQC_PARAM_SETS.get(pset)
        if meta:
            reason += f" Parameter set {entry.display}-{size} targets NIST security category {meta['category']}."
        else:
            reason += f" Observed parameter {size}."
    if entry.key == "ml-kem" and size == 512:
        reason += (" ML-KEM-512 is category 1; CNSA 2.0 requires ML-KEM-1024 for national security systems, "
                   "so treat 512 as a functional but under-strength choice.")
    if entry.key == "ml-dsa" and size == 44:
        reason += " ML-DSA-44 is category 2; CNSA 2.0 requires ML-DSA-87 for national security systems."
    slug = _slug(label)
    if entry.key == "ml-kem" and ("kyber" in slug) and "ml-kem" not in slug:
        reason += (" The name used is 'Kyber', which usually means a pre-standard round-3 implementation; "
                   "these are wire-incompatible with FIPS 203 ML-KEM and must be re-validated.")
    if entry.key == "ml-dsa" and "dilithium" in slug and "ml-dsa" not in slug:
        reason += (" The name used is 'Dilithium', which usually means a pre-standard implementation; "
                   "it is wire-incompatible with FIPS 204 ML-DSA.")
    return Threat.PQC, reason


def _classify_tls(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    ex = _extra(params)
    groups = " ".join(str(v) for v in (ex.get("groups"), ex.get("group"), ex.get("kex"),
                                       ex.get("key_exchange"), ex.get("ciphersuite"))
                      if v)
    slug = _slug(groups)
    if entry.key in ("tls1.3", "tls1.2") and ("mlkem" in slug.replace("-", "") or "kyber" in slug):
        return (Threat.PQC,
                entry.reason + f" A hybrid post-quantum group was observed ({groups}), which removes the "
                               f"harvest-now-decrypt-later exposure of the handshake.")
    return entry.threat, entry.reason


def _classify_jwt(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    ex = _extra(params)
    alg = str(ex.get("alg") or ex.get("algorithm") or "")
    if not alg:
        return Threat.UNKNOWN, entry.reason + " No 'alg' value was recoverable, so no verdict is issued."
    if _slug(alg) == "none":
        return (Threat.LEGACY_BROKEN,
                "The JWT uses alg='none', which disables signature verification entirely; any attacker can mint "
                "a valid token. See RFC 8725 sec. 3.1.")
    sub = normalize_family(alg)
    if sub in KB and sub != "jwt":
        threat, reason = classify(alg, params)
        return threat, f"JWT alg={alg}: " + reason
    return Threat.UNKNOWN, entry.reason + f" alg='{alg}' is not in the KB."


def _classify_static(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    return entry.threat, entry.reason


def _classify_3des(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    size = _key_size(params)
    reason = entry.reason
    if size and size <= 112:
        reason += f" The observed {size}-bit keying option (2-key TDEA) was disallowed by NIST already in 2015."
    return Threat.LEGACY_BROKEN, reason


def _classify_kdf_pbkdf2(entry: AlgoEntry, params: Any, label: str) -> tuple[Threat, str]:
    ex = _extra(params)
    iters = _int_or_none(ex.get("iterations") or ex.get("rounds") or ex.get("count"))
    reason = entry.reason
    if iters is not None:
        reason += f" Observed iteration count: {iters}."
        if iters < 600000:
            return (Threat.GROVER_WEAKENED,
                    reason + " That is below the current OWASP guidance of 600,000 iterations for "
                             "PBKDF2-HMAC-SHA-256, so offline cracking is cheap.")
    return Threat.QUANTUM_SAFE, reason


_CLASSIFIERS = {
    "rsa": _classify_factoring,
    "rsassa-pss": _classify_factoring,
    "rsaes-oaep": _classify_factoring,
    "oaep": _classify_factoring,
    "paillier": _classify_factoring,
    "dsa": _classify_factoring,
    "dh": _classify_factoring,
    "elgamal": _classify_factoring,
    "ecdsa": _classify_ec,
    "ecdh": _classify_ec,
    "ec": _classify_ec,
    "dsa-ec-generic": _classify_ec,
    "ecies": _classify_ec,
    "ecmqv": _classify_ec,
    "sm2": _classify_ec,
    "bls": _classify_ec,
    "aes": _classify_symmetric,
    "camellia": _classify_symmetric,
    "aria": _classify_symmetric,
    "3des": _classify_3des,
    "sha-2": _classify_sha2,
    "sha-3": _classify_sha3,
    "shake": _classify_shake,
    "hmac": _classify_hmac,
    "ml-kem": _classify_pqc,
    "ml-dsa": _classify_pqc,
    "slh-dsa": _classify_pqc,
    "falcon": _classify_pqc,
    "hqc": _classify_pqc,
    "bike": _classify_pqc,
    "classic-mceliece": _classify_pqc,
    "xmss": _classify_pqc,
    "lms": _classify_pqc,
    "ntru": _classify_pqc,
    "frodokem": _classify_pqc,
    "tls1.2": _classify_tls,
    "tls1.3": _classify_tls,
    "jwt": _classify_jwt,
    "pbkdf2": _classify_kdf_pbkdf2,
}


# --------------------------------------------------------------------------
# Public: classify
# --------------------------------------------------------------------------
def classify(family: Any, params: Any = None) -> tuple[Threat, str]:
    """Return ``(Threat, reason)`` for an algorithm plus its parameters.

    Never raises. An unknown family degrades to ``Threat.UNKNOWN`` with a reason
    that says so explicitly rather than guessing.

    >>> t, why = classify("RSA", Params(key_size=1024))
    >>> t is Threat.SHOR_BROKEN
    True
    """
    try:
        label = str(family or "")
        key = normalize_family(label)
        entry = KB.get(key)

        if entry is None:
            # A curve alone is enough to place it as elliptic-curve crypto.
            curve = _pget(params, "curve") or _extra(params).get("curve")
            if curve and curve_info(curve):
                return _classify_ec(KB["ec"], params, label)
            return (Threat.UNKNOWN,
                    f"'{label or 'unnamed'}' is not in the ECDAT knowledge base (v{KB_VERSION}); "
                    f"no quantum verdict is issued. Add an entry to app/engine/kb.py to classify it.")

        fn = _CLASSIFIERS.get(key, _classify_static)
        threat, reason = fn(entry, params, label)

        # Cross-cutting escalations that apply to any family.
        threat, reason = _apply_mode_padding(threat, reason, key, params)
        return threat, reason
    except Exception as exc:  # pragma: no cover - classification must never break a scan
        return (Threat.UNKNOWN,
                f"classification failed for '{family}' ({exc.__class__.__name__}: {exc}); "
                f"treated as unknown rather than guessed.")


def _apply_mode_padding(threat: Threat, reason: str, key: str, params: Any) -> tuple[Threat, str]:
    """Escalate on a broken mode or padding regardless of the base family."""
    if key in ("aes", "camellia", "aria"):
        return threat, reason  # already handled in _classify_symmetric
    mode_key = normalize_family(_mode(params)) if _mode(params) else ""
    if mode_key == "ecb" and threat in (Threat.QUANTUM_SAFE, Threat.GROVER_WEAKENED, Threat.PQC):
        return Threat.LEGACY_BROKEN, reason + " Mode is ECB: " + KB["ecb"].reason
    pad_key = normalize_family(_padding(params)) if _padding(params) else ""
    if pad_key in ("pkcs1v15", "no-padding") and key not in ("rsa", "rsassa-pss", "rsaes-oaep"):
        if threat in (Threat.QUANTUM_SAFE, Threat.PQC, Threat.GROVER_WEAKENED):
            return Threat.LEGACY_BROKEN, reason + " Padding issue: " + KB[pad_key].reason
    return threat, reason


# --------------------------------------------------------------------------
# Public: canonical_name
# --------------------------------------------------------------------------
def canonical_name(family: Any, params: Any = None) -> str:
    """Build the display name ECDAT uses everywhere.

    "RSA-1024", "ECDSA-secp256r1", "AES-256-GCM", "ML-KEM-768", "SHA-256",
    "Ed25519", "TLS 1.2", "3DES-CBC".
    """
    try:
        label = str(family or "").strip()
        key = normalize_family(label)
        entry = KB.get(key)
        size = _key_size(params)
        if size is None:
            size = _embedded_size(label)
        curve_raw = _pget(params, "curve") or _extra(params).get("curve")
        mode = _mode(params)
        mode_disp = ""
        if mode:
            mk = normalize_family(mode)
            mode_disp = KB[mk].display if mk in KB and KB[mk].category == "mode" else str(mode).upper()

        if entry is None:
            base = label or "unknown"
            parts = [base]
            if size and str(size) not in base:
                parts.append(str(size))
            if curve_raw:
                parts.append(str(curve_raw))
            if mode_disp and mode_disp.lower() not in base.lower():
                parts.append(mode_disp)
            return "-".join(p for p in parts if p)

        display = entry.display

        # Hash families: the size is the variant name.
        if key == "sha-2" and size:
            base = f"SHA-{size}" if size in (224, 256, 384, 512) else f"SHA-2-{size}"
            return base
        if key == "sha-3" and size:
            return f"SHA3-{size}"
        if key == "shake" and size:
            return f"SHAKE{size}"
        if key == "blake2" and size:
            return f"BLAKE2-{size}"

        # Elliptic curve families: curve is the discriminator.
        if key in ("ecdsa", "ecdh", "ec", "ecies", "ecmqv", "dsa-ec-generic", "sm2", "bls"):
            if curve_raw:
                info = curve_info(curve_raw)
                curve_disp = info["display"] if info else str(curve_raw)
                return f"{display}-{curve_disp}"
            if size:
                return f"{display}-{size}"
            return display

        if key in ("x25519", "x448", "ed25519", "ed448"):
            return display

        # Protocols keep their spelled-out version.
        if entry.category == "protocol":
            return display

        if key in _NO_SIZE_SUFFIX:
            name = display
        elif size:
            name = f"{display}-{size}"
        else:
            name = display

        if mode_disp and entry.category in ("symmetric",) and mode_disp.upper() not in name.upper():
            name = f"{name}-{mode_disp.upper()}"
        return name
    except Exception:  # pragma: no cover - naming must never break a scan
        return str(family or "unknown")


# --------------------------------------------------------------------------
# Small self-test so `python -m app.engine.kb` proves the table is sane.
# --------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    samples = [
        ("RSA", Params(key_size=1024)),
        ("RSA", Params(key_size=4096, padding="PKCS1v15")),
        ("ECDSA", Params(curve="prime256v1")),
        ("ECDSA", Params(curve="sect163k1")),
        ("AES", Params(key_size=128, mode="CBC")),
        ("AES", Params(key_size=256, mode="GCM")),
        ("AES", Params(key_size=256, mode="ECB")),
        ("SHA-256", Params()),
        ("sha1", Params()),
        ("3DES", Params(key_size=112)),
        ("Kyber768", Params()),
        ("ML-KEM", Params(key_size=1024)),
        ("Ed25519", Params()),
        ("TLSv1.0", Params()),
        ("TLS1.3", Params(extra={"groups": "X25519MLKEM768"})),
        ("Blowfish", Params(key_size=128)),
        ("frobnicate", Params()),
    ]
    print(f"ECDAT KB v{KB_VERSION}: {len(KB)} entries, {len(ALIASES)} aliases, {len(CURVES)} curves\n")
    for fam, p in samples:
        th, why = classify(fam, p)
        print(f"{canonical_name(fam, p):<26} {th.value:<16} {why[:100]}")
