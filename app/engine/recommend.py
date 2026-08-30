"""
ECDAT - migration recommender with mechanical autofix.

Three hard rules govern this module:

1. **The mapping is a table, never a model.**  Every recommendation is looked up
   in :data:`REC_KB`, which is keyed to the published NIST standards (FIPS 203 /
   204 / 205, SP 800-131A Rev.2, SP 800-57 Part 1 Rev.5, SP 800-52 Rev.2).
   Identical input always produces identical output, and every line of advice is
   attributable to a document an auditor can pull.

2. **Rule selection uses structured evidence, not file paths.**  Earlier versions
   decided whether an RSA key was a signing key or a key-transport key by
   searching occurrence *file paths* for substrings like "encrypt".  That made
   the advice depend on incidental directory naming, and an RSA signing key under
   ``src/encryption/`` was told to migrate to ML-KEM - a KEM, which cannot sign.
   Usage is now read from ``params.extra`` (usage / role / key_usage / alg /
   crypto_functions) and from ``kind``; occurrence *evidence text* is a weak
   secondary signal; file paths are never consulted.  When the signals conflict
   the answer is :data:`AMBIGUOUS_USAGE`, not a guess.

3. **We only patch what we can prove, and a patch may never change a format, a
   key, or a mode.**  :func:`generate_fix` emits a unified diff only for
   substitutions that are local to one line and preserve message format, key
   material and API shape: fresh-hash constructor swaps and protocol version
   strings.  Everything that needs new key material (AES-128 to AES-256, RSA
   2048 to 3072), a new ciphertext format (any mode change to an AEAD: nonce plus
   tag), a different API shape (PyCryptodome ``encrypt`` vs
   ``encrypt_and_digest``), a different parameter object (JCE ``GCMParameterSpec``
   vs ``IvParameterSpec``) or a wider output buffer (OpenSSL ``EVP_md5`` to
   ``EVP_sha256`` overflows a ``MD5_DIGEST_LENGTH`` buffer) gets
   ``fix_patch == ""`` and an explicit sentence saying a human must do it.
   Hash swaps are additionally suppressed wherever the digest value is *pinned* -
   HMAC, MGF1/OAEP/PSS parameters, TOTP/HOTP, KDFs, verification and comparison
   paths, stored password or integrity records - because changing the
   constructor there breaks interoperation rather than fixing it.

Public API
----------
``recommend(artefact, repo_root=None)``      enrich one artefact in place
``recommend_all(artefacts, repo_root=None)`` enrich a list in place
``generate_fix(artefact, repo_root=None)``   unified diff string (may be "")
``classify(artefact)``                       artefact -> REC_KB rule id
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from .models import Artefact

__all__ = [
    "recommend",
    "recommend_all",
    "generate_fix",
    "classify",
    "REC_KB",
    "FIX_RULES",
]

# --------------------------------------------------------------------------- #
# Standing facts used to build honest trade-off tables.  Sizes are in bytes and
# come from the FIPS documents themselves.
# --------------------------------------------------------------------------- #
_ML_KEM_768 = "ML-KEM-768: encapsulation key 1184 B, ciphertext 1088 B, shared secret 32 B"
_X25519 = "X25519: public key 32 B, ciphertext 32 B"
_ML_DSA_65 = "ML-DSA-65: signature 3309 B (~3.3 KB), public key 1952 B"
_ECDSA_P256 = "ECDSA P-256: signature ~64 B raw / ~72 B DER, public key 33 B compressed"
_FIPS203 = "NIST FIPS 203 (ML-KEM), final August 2024"
_FIPS204 = "NIST FIPS 204 (ML-DSA), final August 2024"
_FIPS205 = "NIST FIPS 205 (SLH-DSA), final August 2024"
_SP800_131A = "NIST SP 800-131A Rev.2"
_SP800_57 = "NIST SP 800-57 Part 1 Rev.5"
_SP800_52 = "NIST SP 800-52 Rev.2"
_SP800_208 = "NIST SP 800-208 (stateful hash-based signatures)"


# --------------------------------------------------------------------------- #
# The knowledge base.  rule_id -> recommendation record.
# --------------------------------------------------------------------------- #
REC_KB: dict[str, dict[str, Any]] = {
    "KEM_HYBRID": {
        "recommendation": "hybrid X25519 + ML-KEM-768",
        "standard": _FIPS203,
        "rationale": (
            "Key establishment based on discrete-log or factoring is fully broken by "
            "Shor's algorithm, and any transcript captured today can be decrypted "
            "retroactively once a cryptographically relevant quantum computer exists "
            "(harvest-now-decrypt-later). Deploy the hybrid group X25519MLKEM768 so "
            "security holds if either component survives."
        ),
        "trade_offs": {
            "size": f"{_ML_KEM_768} vs {_X25519}. In the hybrid group the shares are "
                    "concatenated: client share 1216 B vs 32 B, server share 1120 B "
                    "(1088 B ML-KEM ciphertext + 32 B X25519 public key) vs 32 B - "
                    "roughly +2.2 KB per handshake.",
            "performance": "ML-KEM-768 keygen/encap/decap are lattice operations measured in "
                           "tens of microseconds - typically faster than X25519 scalar "
                           "multiplication; the cost is bandwidth, not CPU.",
            "maturity": f"{_FIPS203}. The hybrid group X25519MLKEM768 (code point 0x11ec) is "
                        "already enabled by default in mainstream browsers and TLS stacks.",
            "interop": "Hybrid keeps a classical component, so a peer that fails to negotiate "
                       "the PQ group still gets X25519 security; pure ML-KEM does not.",
            "migration": "Library/TLS-config level change. No change to application data "
                         "formats; MTU and record-size assumptions must be re-checked. "
                         "New key material is generated, so this is not a source-level "
                         "substitution and ECDAT emits no patch.",
        },
        "alternatives": "ML-KEM-1024 where NIST category 5 is mandated.",
    },
    "SIG_MLDSA": {
        "recommendation": "ML-DSA-65",
        "standard": _FIPS204,
        "rationale": (
            "Signatures over RSA, DSA, ECDSA or EdDSA are forgeable once Shor's "
            "algorithm is available. Signature exposure is not retroactive - a forged "
            "signature only matters in the future - so the deadline is the lifetime of "
            "the verifying trust anchor (roots, firmware keys, code-signing chains)."
        ),
        "trade_offs": {
            "size": f"{_ML_DSA_65} vs {_ECDSA_P256} - about 50x larger signatures. A "
                    "3-certificate chain grows by roughly 15 KB (~5 KB per certificate: "
                    "+3.2 KB signature and +1.9 KB public key).",
            "performance": "ML-DSA signing and verification are fast (comparable to or faster "
                           "than ECDSA); verification is the cheap side, which suits "
                           "many-verifier deployments.",
            "maturity": f"{_FIPS204}. Deterministic and hedged variants both specified.",
            "interop": "Requires X.509 stacks that understand the ML-DSA OIDs; older "
                       "verifiers must be inventoried before switching a trust anchor.",
            "migration": "Certificate/PKI-level change; plan for dual-algorithm (composite or "
                         "parallel chain) issuance during the overlap period. New key "
                         "material, so no automatic patch.",
        },
        "alternatives": "SLH-DSA (FIPS 205) for long-lived roots and firmware, where a "
                        "conservative hash-based assumption is worth the signature size.",
    },
    "SIG_SLHDSA": {
        "recommendation": "SLH-DSA-SHA2-128s (ML-DSA-65 where signature size dominates)",
        "standard": _FIPS205,
        "rationale": (
            "This key signs artefacts with a very long verification horizon (firmware, "
            "roots of trust, archival records). SLH-DSA rests only on hash-function "
            "security, so it survives even a future break of structured lattices - the "
            "right conservatism for a trust anchor that cannot be rotated in the field."
        ),
        "trade_offs": {
            "size": "SLH-DSA-SHA2-128s: signature 7856 B (~7.9 KB), public key 32 B. "
                    f"The fast variant -128f is 17088 B. Compare {_ML_DSA_65}.",
            "performance": "The 's' (small) parameter sets sign in the hundreds of "
                           "milliseconds range - acceptable for a release-signing step, "
                           "not for per-transaction signing. Verification is fast.",
            "maturity": f"{_FIPS205}. Stateless, so it avoids the key-state hazards of "
                        f"LMS/XMSS ({_SP800_208}).",
            "interop": "Signature size may exceed fixed-size firmware signature slots - "
                       "check the bootloader image format before committing.",
            "migration": "Usually a dual-signature scheme (classical + PQ) during rollout so "
                         "fielded devices keep verifying. New key material, so no "
                         "automatic patch.",
        },
        "alternatives": f"LMS/XMSS ({_SP800_208}) if a stateful scheme can be managed safely.",
    },
    "AMBIGUOUS_USAGE": {
        "recommendation": "manual review - Shor-broken primitive, replacement depends on "
                          "usage (ML-KEM-768 for key establishment, ML-DSA-65 for signatures)",
        "standard": f"{_FIPS203} / {_FIPS204}",
        "rationale": (
            "The algorithm itself is fully broken by Shor's algorithm and must be "
            "replaced, but ECDAT could not establish from structured evidence whether "
            "this asset is used for key establishment or for signatures, and the two "
            "have different replacements. ML-KEM is a key-encapsulation mechanism and "
            "cannot produce signatures; ML-DSA is a signature scheme and cannot "
            "establish keys. Naming one of them here would be a guess with a 50% chance "
            "of being functionally impossible, so ECDAT refuses."
        ),
        "trade_offs": {
            "size": "Depends on the resolved role: see KEM_HYBRID or SIG_MLDSA.",
            "performance": "Depends on the resolved role.",
            "maturity": "Both targets are final NIST standards (August 2024).",
            "interop": "Depends on the resolved role.",
            "migration": "First step is a one-line answer from the owning engineer: does "
                         "this key encrypt/establish, or does it sign? That answer selects "
                         "the target algorithm; the urgency is already established.",
        },
        "alternatives": "Record the role in the code (a comment, a key-usage extension, an "
                        "explicit parameter) so the next scan classifies it automatically.",
    },
    "HASH_SHA256": {
        "recommendation": "SHA-256",
        "standard": _SP800_131A,
        "rationale": (
            "MD5 and SHA-1 are classically broken - collisions are practical today, with "
            "no quantum computer required. MD5 chosen-prefix collisions cost seconds; "
            "SHA-1 fell to the SHAttered collision in 2017 (~2^63.1 work) and to a "
            "chosen-prefix collision in 2020 for roughly USD 45,000."
        ),
        "trade_offs": {
            "size": "Digest grows from 16 B (MD5) / 20 B (SHA-1) to 32 B - check fixed-width "
                    "database columns, index keys and wire formats.",
            "performance": "SHA-256 is roughly 1.5-2x the cost of MD5 per byte, and modern "
                           "CPUs with SHA extensions close most of that gap.",
            "maturity": f"{_SP800_131A} disallows SHA-1 for digital signatures; SHA-256 is "
                        "universally supported.",
            "interop": "Any stored digests must be recomputed or dual-indexed during rollout. "
                       "Where the digest value is pinned - HMAC, TOTP/HOTP, MGF1/OAEP/PSS "
                       "parameters, git object ids, stored password or integrity records - "
                       "swapping the constructor breaks verification and both peers must "
                       "change together.",
            "migration": "Mechanical for a fresh, non-persisted, unkeyed fingerprint; ECDAT "
                         "patches only that case. If the hash is part of a password store, "
                         "move to Argon2id or PBKDF2 instead - a fast hash is the wrong "
                         "primitive there.",
        },
        "alternatives": "SHA-384/SHA-512 for high-assurance contexts; SHA-3 where diversity "
                        "of design is required.",
    },
    "KEYED_HASH_LEGACY": {
        "recommendation": "re-key onto HMAC-SHA-256 (or PBKDF2/HKDF-SHA-256)",
        "standard": _SP800_131A,
        "rationale": (
            "This keyed construction is built on a broken digest. SP 800-131A Rev.2 "
            "disallows MD5 for all keyed use and restricts HMAC-SHA-1 to legacy "
            "verification only. HMAC's collision resistance requirement is weaker than a "
            "bare hash, so this is not an immediate forgery, but it is a disallowed "
            "primitive that an auditor will flag and it must be scheduled out."
        ),
        "trade_offs": {
            "size": "MAC/derived-key output grows to 32 B unless explicitly truncated.",
            "performance": "Comparable; SHA-256 with hardware support is not a bottleneck.",
            "maturity": f"{_SP800_131A}; SP 800-107 Rev.1 for HMAC key and output sizing.",
            "interop": "Both ends of a MAC must change together, and any derived key changes "
                       "value - stored records derived under the old PRF must be migrated "
                       "or re-derived on next use.",
            "migration": "Not a constructor swap: every existing MAC and derived key changes "
                         "value, so ECDAT emits no patch. Roll out with dual verification "
                         "(accept old, issue new) and then retire the old PRF.",
        },
        "alternatives": "For password storage move to Argon2id; HMAC-SHA-1 may remain only "
                        "inside a protocol that mandates it (for example RFC 6238 TOTP), "
                        "which should be recorded as an explicit, dated waiver.",
    },
    "CIPHER_AES256": {
        "recommendation": "AES-256-GCM",
        "standard": _SP800_131A,
        "rationale": (
            "Legacy block and stream ciphers are broken independently of quantum "
            "computing: single DES has a 56-bit key, 3DES has a 64-bit block and is "
            "birthday-bound at ~32 GB per key (Sweet32), and RC4 has exploitable "
            "keystream biases prohibited in TLS by RFC 7465."
        ),
        "trade_offs": {
            "size": "128-bit block instead of 64-bit removes the Sweet32 birthday bound; "
                    "GCM adds a 12 B nonce and a 16 B authentication tag per record.",
            "performance": "AES-256-GCM with AES-NI/ARMv8 crypto extensions runs at several "
                           "GB/s - typically 5-10x faster than a 3DES software implementation.",
            "maturity": f"{_SP800_131A} disallowed 3DES after 2023; AES-GCM is the default "
                        "AEAD everywhere.",
            "interop": "Both endpoints and any stored ciphertext must migrate; plan a "
                       "re-encryption pass for data at rest.",
            "migration": "Key material changes (56/168-bit keys to 256-bit) and the ciphertext "
                         "gains a nonce and a tag, so this is a re-key and a format change, "
                         "not a string swap. ECDAT emits no patch.",
        },
        "alternatives": "ChaCha20-Poly1305 where AES hardware acceleration is absent.",
    },
    "AES128_UPGRADE": {
        "recommendation": "AES-256-GCM",
        "standard": _SP800_131A,
        "rationale": (
            "AES-128 is not broken, but Grover's algorithm halves the effective search "
            "space to about 2^64, which is below the margin acceptable for data with a "
            "long confidentiality lifetime. AES-256 restores a 128-bit post-quantum "
            "security level (CNSA 2.0 requires AES-256)."
        ),
        "trade_offs": {
            "size": "No ciphertext expansion if the mode is unchanged: same 128-bit block. "
                    "Key material doubles from 16 B to 32 B.",
            "performance": "14 rounds instead of 10 - roughly 30-40% more CPU per byte, "
                           "usually irrelevant next to I/O on AES-NI hardware.",
            "maturity": "AES-256 is FIPS 197 and universally available today.",
            "interop": "Both sides must agree on the cipher suite; stored data needs a "
                       "re-encryption or envelope-key rotation.",
            "migration": "Requires new 32-byte key material - a 16-byte key passed to an "
                         "AES-256 API raises immediately - so ECDAT does not patch it even "
                         "though the cipher string looks like a one-token edit. Rotate the "
                         "key, then re-encrypt or envelope-rewrap the data at rest.",
        },
        "alternatives": "AES-256-SIV or XChaCha20-Poly1305 where nonce reuse is a real risk.",
    },
    "SHA256_TO_384": {
        "recommendation": "SHA-384",
        "standard": _SP800_131A,
        "rationale": (
            "SHA-256 is quantum-resistant for practical purposes, but this asset is "
            "flagged high-assurance/long-lived. Grover reduces preimage resistance to "
            "~2^128 for SHA-256 versus ~2^192 for SHA-384, and CNSA 2.0 mandates SHA-384 "
            "for national-security systems."
        ),
        "trade_offs": {
            "size": "Digest 48 B instead of 32 B.",
            "performance": "SHA-384 is SHA-512 truncated: on 64-bit CPUs without SHA-NI it is "
                           "often faster than SHA-256; on 32-bit microcontrollers it is slower.",
            "maturity": "FIPS 180-4, universally supported.",
            "interop": "Only relevant where a peer pins the digest length.",
            "migration": "Mechanical in most call sites, but the digest value changes, so any "
                         "stored or transmitted digest must be recomputed. ECDAT does not "
                         "patch an upgrade of an already-adequate primitive.",
        },
        "alternatives": "SHA-512 where the extra 16 B is free.",
    },
    "ECB_TO_GCM": {
        "recommendation": "AES-256-GCM",
        "standard": _SP800_131A,
        "rationale": (
            "ECB encrypts identical plaintext blocks to identical ciphertext blocks, so "
            "it leaks structure regardless of key length, and it provides no integrity "
            "at all. This is a confidentiality bug today, before any quantum "
            "consideration."
        ),
        "trade_offs": {
            "size": "Adds a 12 B nonce and a 16 B tag per message.",
            "performance": "GCM with hardware GHASH is comparable to raw ECB throughput.",
            "maturity": "SP 800-38D; the standard AEAD mode.",
            "interop": "Ciphertext format changes (nonce and tag must be stored/transmitted), "
                       "so both encryptor and decryptor change together.",
            "migration": "Requires a nonce-management decision: a random 96-bit nonce per "
                         "message, or a counter. Never reuse a nonce under one key - two "
                         "messages under one nonce leak the GHASH subkey and destroy both "
                         "confidentiality and authenticity for every message under that key. "
                         "ECDAT will not generate this patch.",
        },
        "alternatives": "AES-256-CTR + HMAC-SHA-256 (encrypt-then-MAC) where GCM is "
                        "unavailable; AES-SIV where nonce discipline cannot be guaranteed.",
    },
    "UNAUTH_MODE_TO_AEAD": {
        "recommendation": "AES-256-GCM (authenticated encryption)",
        "standard": "NIST SP 800-38D",
        "rationale": (
            "CBC, CTR, CFB and OFB provide confidentiality only. Without a MAC the "
            "ciphertext is malleable, and CBC decryption in particular has a long "
            "history of padding-oracle attacks (Vaudenay 2002, Lucky13, POODLE). This "
            "is a classical weakness, independent of quantum risk."
        ),
        "trade_offs": {
            "size": "Adds a 12 B nonce and a 16 B tag per message.",
            "performance": "GCM is typically faster than CBC plus a separate HMAC pass.",
            "maturity": "SP 800-38D; the standard AEAD mode.",
            "interop": "The ciphertext format changes, so encryptor and decryptor must be "
                       "deployed together, and stored ciphertext needs re-encryption.",
            "migration": "An IV derivation that was safe for CBC (static, counter-based, or "
                         "reused per key) becomes catastrophic nonce reuse under GCM. The "
                         "change therefore requires a nonce-uniqueness decision plus, in "
                         "JCE, a GCMParameterSpec in place of IvParameterSpec. ECDAT emits "
                         "no patch for it.",
        },
        "alternatives": "Encrypt-then-MAC (AES-256-CTR + HMAC-SHA-256) where an AEAD mode is "
                        "unavailable; AES-SIV where nonce uniqueness cannot be guaranteed.",
    },
    "PKCS1V15_TO_OAEP": {
        "recommendation": "RSA-OAEP-SHA-256 as an interim step, hybrid X25519 + ML-KEM-768 as "
                          "the target",
        "standard": f"{_FIPS203}; RFC 8017 for OAEP",
        "rationale": (
            "PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher-style "
            "adaptive chosen-ciphertext oracles (1998, and again as ROBOT in 2017). "
            "OAEP removes the padding oracle, but RSA itself remains Shor-broken, so "
            "OAEP is a stop-gap and ML-KEM is the destination."
        ),
        "trade_offs": {
            "size": "OAEP with SHA-256 costs 66 B of overhead, cutting the maximum plaintext "
                    "for RSA-2048 from 245 B to 190 B.",
            "performance": "Negligible change; the RSA operation dominates.",
            "maturity": "RFC 8017 is universally implemented.",
            "interop": "Both peers must switch padding at the same time - a mixed deployment "
                       "fails to decrypt.",
            "migration": "Not a safe one-line edit: the decrypt side, the maximum message "
                         "size and any hybrid-envelope format all change together.",
        },
        "alternatives": "Skip OAEP entirely and go straight to a KEM-DEM construction with "
                        "ML-KEM-768 if the transport can be redesigned once.",
    },
    "TLS_13": {
        "recommendation": "TLS 1.3",
        "standard": _SP800_52,
        "rationale": (
            "TLS 1.0 and 1.1 are deprecated by RFC 8996 (March 2021), and SSL 2.0/3.0 "
            "are prohibited outright (RFC 6176, RFC 7568). They rely on SHA-1/MD5 "
            "constructions and CBC padding modes with a long history of practical "
            "attacks (BEAST, POODLE, Lucky13). TLS 1.3 also removes RSA key transport, "
            "which is a prerequisite for the hybrid PQ key exchange."
        ),
        "trade_offs": {
            "size": "Handshake shrinks to 1-RTT; adding X25519MLKEM768 later adds ~2.2 KB.",
            "performance": "1-RTT (0-RTT optional) is faster than the TLS 1.2 two round trips.",
            "maturity": "RFC 8446 (August 2018); mandatory-to-support in modern stacks.",
            "interop": "Clients older than roughly 2017 cannot negotiate TLS 1.3 - inventory "
                       "them before disabling 1.2.",
            "migration": "Configuration change plus removal of static-RSA and CBC cipher "
                         "suites; re-test middleboxes that inspect the handshake. A version "
                         "string is a genuine one-token edit, so ECDAT does patch it - but "
                         "confirm the peer inventory before merging.",
        },
        "alternatives": "TLS 1.2 restricted to AEAD suites with forward secrecy, only where a "
                        "hard client constraint is documented and dated.",
    },
    "TLS12_HYBRID": {
        "recommendation": "TLS 1.3 with the hybrid group X25519MLKEM768",
        "standard": f"{_SP800_52}; {_FIPS203}",
        "rationale": (
            "TLS 1.2 is not deprecated, but every key exchange it can offer - ECDHE, "
            "DHE and static RSA key transport - is broken by Shor's algorithm, and the "
            "protocol has no mechanism for negotiating a post-quantum group. Every "
            "session recorded today is decryptable retroactively. TLS 1.2 therefore "
            "needs action, not retention: it is the version that blocks the PQ "
            "migration."
        ),
        "trade_offs": {
            "size": "The hybrid group adds roughly 2.2 KB to the handshake.",
            "performance": "TLS 1.3 completes in 1-RTT against TLS 1.2's 2-RTT, which "
                           "typically offsets the extra bytes on real links.",
            "maturity": "RFC 8446; X25519MLKEM768 (0x11ec) ships enabled by default in "
                        "mainstream browsers and TLS libraries.",
            "interop": "Pre-2017 clients cannot negotiate TLS 1.3. Inventory them, and keep "
                       "TLS 1.2 only as a documented, dated exception.",
            "migration": "Configuration change on both the version floor and the group list. "
                         "ECDAT does not patch it automatically because disabling TLS 1.2 "
                         "can cut off fielded clients - that call needs the inventory.",
        },
        "alternatives": "Where TLS 1.2 must remain, restrict it to ECDHE AEAD suites and "
                        "record a dated waiver; it still offers no PQ protection.",
    },
    "TLS13_HYBRID_GROUP": {
        "recommendation": "TLS 1.3 - enable the hybrid group X25519MLKEM768",
        "standard": f"{_FIPS203}; RFC 8446",
        "rationale": (
            "The protocol version is current, but no post-quantum key-exchange group "
            "was observed. TLS 1.3 with a purely classical group (X25519 or a NIST "
            "curve) is still fully exposed to harvest-now-decrypt-later: the handshake "
            "secret is recoverable by Shor once a CRQC exists. The remaining work is "
            "the group list, not the version."
        ),
        "trade_offs": {
            "size": "Client share 1216 B and server share 1120 B instead of 32 B each - "
                    "about +2.2 KB per handshake.",
            "performance": "Negligible CPU cost; ML-KEM operations are faster than X25519.",
            "maturity": f"{_FIPS203}; the hybrid code point 0x11ec is widely deployed.",
            "interop": "Hybrid degrades gracefully - a peer that does not offer the group "
                       "still negotiates X25519.",
            "migration": "One line in the TLS configuration (group/curve preference list) "
                         "plus a check that no middlebox rejects the larger ClientHello. "
                         "ECDAT does not patch configuration files it cannot attribute.",
        },
        "alternatives": "X25519MLKEM1024 or SecP384r1MLKEM1024 where NIST category 5 is "
                        "mandated.",
    },
    "PQC_OK": {
        "recommendation": "no change - already quantum-safe",
        "standard": f"{_FIPS203} / {_FIPS204} / {_FIPS205}",
        "rationale": (
            "This asset already uses a NIST-standardised post-quantum algorithm at a "
            "parameter set of NIST category 3 or above. Record it in the CBOM as "
            "compliant and keep the parameter set under review."
        ),
        "trade_offs": {
            "size": f"{_ML_KEM_768}; {_ML_DSA_65}.",
            "performance": "Lattice operations are fast; bandwidth is the cost centre.",
            "maturity": "Standardised August 2024.",
            "interop": "Confirm the implementation tracks the final FIPS versions rather than "
                       "a pre-standard Kyber/Dilithium draft - the drafts are not "
                       "interoperable with the final standards.",
            "migration": "None required.",
        },
        "alternatives": "Consider hybrid mode during the transition period for defence in "
                        "depth.",
    },
    "PQC_PRESTANDARD": {
        "recommendation": "migrate to the final FIPS parameter set (Kyber -> FIPS 203 ML-KEM, "
                          "Dilithium -> FIPS 204 ML-DSA, SPHINCS+ -> FIPS 205 SLH-DSA)",
        "standard": f"{_FIPS203} / {_FIPS204} / {_FIPS205}",
        "rationale": (
            "This is a pre-standard, NIST round-3 era implementation. Kyber and "
            "Dilithium as submitted are wire-incompatible with the final FIPS 203/204 "
            "standards - the key-derivation and domain-separation steps changed - so a "
            "peer running the standard will not interoperate. Pre-standard code is also "
            "frequently research-grade: not constant-time, not reviewed for fault "
            "injection, and not covered by the FIPS validation programme."
        ),
        "trade_offs": {
            "size": "Broadly unchanged at the equivalent parameter set; the encodings differ.",
            "performance": "Comparable; final implementations are usually better optimised.",
            "maturity": "The final standards were published August 2024 and supersede the "
                        "round-3 submissions.",
            "interop": "This is the decisive point: pre-standard and final are NOT "
                       "interoperable. Both ends must move together, or run both during a "
                       "transition window.",
            "migration": "Library upgrade plus a re-key. Confirm the library reports the FIPS "
                         "algorithm names rather than the round-3 names before declaring "
                         "compliance.",
        },
        "alternatives": "Hybrid (classical + final PQ) during the changeover so a peer stuck "
                        "on the old build still has classical protection.",
    },
    "PQC_UNDERSTRENGTH": {
        "recommendation": "raise the parameter set to ML-KEM-768/1024 or ML-DSA-65/87",
        "standard": f"{_FIPS203} / {_FIPS204}",
        "rationale": (
            "The algorithm is standardised, but the parameter set is NIST category 1, "
            "the lowest defined level. ECDAT's floor is category 3, and CNSA 2.0 "
            "requires ML-KEM-1024 and ML-DSA-87 for national-security systems. The "
            "margin at category 1 is thin against future improvements in lattice "
            "cryptanalysis for an asset expected to last decades."
        ),
        "trade_offs": {
            "size": "ML-KEM-512 to -768: encapsulation key 800 B to 1184 B, ciphertext 768 B "
                    "to 1088 B. ML-DSA-44 to -65: signature 2420 B to 3309 B.",
            "performance": "A modest constant-factor cost; both remain fast.",
            "maturity": "All parameter sets are in the final standards - this is a strength "
                        "choice, not a compatibility problem.",
            "interop": "Parameter sets are negotiated separately, so both ends must agree.",
            "migration": "Configuration plus a re-key. No protocol redesign.",
        },
        "alternatives": "Category 5 (ML-KEM-1024 / ML-DSA-87) where CNSA 2.0 applies.",
    },
    "PQC_STATEFUL": {
        "recommendation": "retain only with audited key-state management (SP 800-208); "
                          "otherwise migrate to SLH-DSA",
        "standard": _SP800_208,
        "rationale": (
            "XMSS and LMS are stateful hash-based signature schemes. Their post-quantum "
            "security is excellent, but each one-time key index may be used exactly "
            "once: reusing an index yields practical, immediate signature forgery. That "
            "state must survive crashes, backups, restores, VM snapshots and "
            "load-balanced replicas, which is why SP 800-208 imposes explicit key-state "
            "requirements and forbids cloning private key state."
        ),
        "trade_offs": {
            "size": "Signature size depends on the tree height (typically 2-3 KB); public "
                    "keys are small (32-64 B).",
            "performance": "Fast signing and verification once the tree is built; key "
                           "generation for a tall tree is expensive.",
            "maturity": f"{_SP800_208}. Approved, but with hard operational conditions.",
            "interop": "Widely used for firmware signing; verify the recipient supports the "
                       "same tree parameters.",
            "migration": "The decision is operational, not cryptographic: can this deployment "
                         "guarantee that state is never rolled back or duplicated? If not, "
                         "SLH-DSA (FIPS 205) gives the same hash-based assumption with no "
                         "state at the cost of a larger signature.",
        },
        "alternatives": "SLH-DSA-SHA2-128s where statelessness is worth ~7.9 KB signatures.",
    },
    "PQC_DRAFT": {
        "recommendation": "treat as provisional - prefer ML-DSA-65 until FIPS 206 is final",
        "standard": "NIST FIPS 206 (FN-DSA / Falcon), draft",
        "rationale": (
            "Falcon is selected for standardisation as FN-DSA, but FIPS 206 is still a "
            "draft, so the final parameter encoding may change and no validated "
            "implementation exists yet. Falcon's signing path also uses floating-point "
            "Gaussian sampling, which is notoriously sensitive to side-channel leakage "
            "and to floating-point behaviour differing across platforms."
        ),
        "trade_offs": {
            "size": "Falcon-512 signatures are ~666 B - much smaller than ML-DSA-65's "
                    "3309 B, which is the reason to want it.",
            "performance": "Verification is fast; signing is complex and implementation-"
                           "sensitive.",
            "maturity": "Draft standard. Not yet FIPS-validatable.",
            "interop": "Encoding may change before the standard is final.",
            "migration": "If the small signature is essential, isolate the implementation so "
                         "it can be replaced when FIPS 206 lands; otherwise use ML-DSA now.",
        },
        "alternatives": "ML-DSA-65 (FIPS 204) today; revisit Falcon when FIPS 206 is final.",
    },
    "REMOVE_BROKEN_PQC": {
        "recommendation": "remove immediately - replace with ML-KEM-768 (key establishment) "
                          "or ML-DSA-65 (signatures)",
        "standard": f"{_FIPS203} / {_FIPS204}",
        "rationale": (
            "This is a post-quantum candidate that was broken classically, on ordinary "
            "hardware, during the NIST process. SIKE/SIDH fell to the Castryck-Decru "
            "key-recovery attack in 2022, which recovers the private key in about an "
            "hour on a single core. Rainbow fell to Beullens in 2022, breaking the "
            "level-1 parameter set in a weekend on a laptop. Neither offers any "
            "security at all - this is more urgent than the classical algorithms it was "
            "presumably deployed to replace."
        ),
        "trade_offs": {
            "size": f"{_ML_KEM_768}; {_ML_DSA_65}.",
            "performance": "The replacements are faster than the broken schemes.",
            "maturity": "The replacements are final NIST standards; these candidates were "
                        "withdrawn.",
            "interop": "Any peer still offering these must be upgraded in the same window.",
            "migration": "Treat as an active incident, not a migration: any data protected "
                         "by it should be considered exposed and re-protected under a new "
                         "key.",
        },
        "alternatives": "None - there is no safe parameter set for either scheme.",
    },
    "QSAFE_OK": {
        "recommendation": "no change - retain (symmetric/hash primitive at an adequate level)",
        "standard": _SP800_131A,
        "rationale": (
            "Grover's algorithm gives only a quadratic speed-up, so a 256-bit symmetric "
            "key or a 384-bit digest keeps a 128-bit or better post-quantum margin. The "
            "quantum exposure in this system is in the asymmetric layer, not here."
        ),
        "trade_offs": {
            "size": "Unchanged.",
            "performance": "Unchanged.",
            "maturity": "Current standard.",
            "interop": "Unchanged.",
            "migration": "None; keep the key-establishment layer under review instead.",
        },
        "alternatives": "None needed.",
    },
    "UNKNOWN": {
        "recommendation": "manual review required",
        "standard": "NIST IR 8547 (initial public draft, transition to PQC)",
        "rationale": (
            "ECDAT identified a cryptographic asset but could not resolve its algorithm, "
            "parameters or usage with enough confidence to name a replacement. An "
            "engineer must classify it before it can be scheduled for migration."
        ),
        "trade_offs": {
            "size": "Unknown until the asset is classified.",
            "performance": "Unknown until the asset is classified.",
            "maturity": "Unknown.",
            "interop": "Unknown.",
            "migration": "Start by recording the usage (key establishment, signature, data at "
                         "rest) - that alone selects the target algorithm.",
        },
        "alternatives": "n/a",
    },
}


# --------------------------------------------------------------------------- #
# family classification
# --------------------------------------------------------------------------- #
# Pre-standard names are deliberately kept distinct from their final standard
# names: "Kyber768" is NOT ML-KEM-768 on the wire, and calling it quantum-safe
# with no further comment is the error this table exists to prevent.
_FAMILY_TOKENS: tuple[tuple[str, str], ...] = (
    ("MLKEM", "ML-KEM"), ("MLDSA", "ML-DSA"), ("SLHDSA", "SLH-DSA"),
    ("KYBER", "KYBER"), ("DILITHIUM", "DILITHIUM"), ("SPHINCS", "SPHINCS"),
    ("FALCON", "FN-DSA"), ("FNDSA", "FN-DSA"),
    ("SIKE", "SIKE"), ("SIDH", "SIKE"), ("RAINBOW", "RAINBOW"),
    ("XMSS", "XMSS"), ("LMS", "LMS"), ("HSS", "LMS"),
    ("TRIPLEDES", "3DES"), ("3DES", "3DES"), ("DESEDE", "3DES"), ("TDEA", "3DES"),
    ("X25519", "X25519"), ("X448", "X448"),
    ("ED25519", "ED25519"), ("ED448", "ED448"),
    ("ECDSA", "ECDSA"), ("ECDH", "ECDH"), ("ECIES", "ECDH"),
    ("RSA", "RSA"), ("DSA", "DSA"), ("DH", "DH"),
    ("CHACHA", "CHACHA20"), ("POLY1305", "CHACHA20"),
    ("AES", "AES"), ("DES", "DES"), ("RC4", "RC4"), ("ARCFOUR", "RC4"),
    ("BLOWFISH", "BLOWFISH"), ("IDEA", "IDEA"), ("CAST5", "CAST5"), ("RC2", "RC2"),
    ("MD5", "MD5"), ("MD4", "MD4"), ("MD2", "MD2"),
    ("SHA3", "SHA-3"), ("SHAKE", "SHA-3"),
    ("SHA512", "SHA-512"), ("SHA384", "SHA-384"), ("SHA256", "SHA-256"),
    ("SHA224", "SHA-224"), ("SHA1", "SHA-1"),
    ("RIPEMD", "RIPEMD"),
    ("HMAC", "HMAC"),
    ("PBKDF2", "KDF"), ("ARGON", "KDF"), ("BCRYPT", "KDF"), ("SCRYPT", "KDF"),
    ("HKDF", "KDF"),
    ("SSL", "TLS"), ("TLS", "TLS"), ("DTLS", "TLS"),
)

_LEGACY_HASHES = frozenset({"MD5", "MD4", "MD2", "SHA-1", "RIPEMD"})
_LEGACY_CIPHERS = frozenset({"DES", "3DES", "RC4", "BLOWFISH", "IDEA", "CAST5", "RC2"})
_PRESTANDARD_PQC = frozenset({"KYBER", "DILITHIUM", "SPHINCS"})
_BROKEN_PQC = frozenset({"SIKE", "RAINBOW"})
_FINAL_PQC = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})

# Inner-digest tokens, longest/most specific first.
_INNER_HASH_TOKENS: tuple[tuple[str, str], ...] = (
    ("SHA3", "SHA-3"), ("SHAKE", "SHA-3"),
    ("SHA512", "SHA-512"), ("SHA384", "SHA-384"), ("SHA256", "SHA-256"),
    ("SHA224", "SHA-224"), ("SHA1", "SHA-1"),
    ("MD5", "MD5"), ("MD4", "MD4"), ("MD2", "MD2"), ("RIPEMD", "RIPEMD"),
)


def _squash(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(text or "").upper())


def _canonical_family(artefact: Any) -> str:
    """Resolve a canonical family token from family/name, defensively.

    Both the declared family and the display name are probed, because several
    detectors emit a generic family (``SHA-2``, ``TLS``) and put the variant in
    the name.
    """
    candidates = [
        str(getattr(artefact, "family", "") or ""),
        str(getattr(artefact, "name", "") or ""),
    ]
    for candidate in candidates:
        squashed = _squash(candidate)
        for token, canonical in _FAMILY_TOKENS:
            if squashed.startswith(token):
                return canonical
    for candidate in candidates:
        squashed = _squash(candidate)
        for token, canonical in _FAMILY_TOKENS:
            if token in squashed:
                return canonical
    return "UNKNOWN"


def _param(artefact: Any, name: str) -> Any:
    return getattr(getattr(artefact, "params", None), name, None)


def _extra(artefact: Any) -> dict:
    extra = getattr(getattr(artefact, "params", None), "extra", None)
    return extra if isinstance(extra, dict) else {}


def _mode(artefact: Any) -> str:
    return _squash(_param(artefact, "mode"))


def _padding(artefact: Any) -> str:
    return _squash(_param(artefact, "padding"))


def _key_size(artefact: Any) -> Optional[int]:
    value = _param(artefact, "key_size")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _inner_hash(artefact: Any) -> Optional[str]:
    """The digest inside a keyed construction (HMAC-SHA-1, PBKDF2-HMAC-SHA-256)."""
    candidates: list[str] = []
    extra = _extra(artefact)
    for key in ("hash", "digest", "inner_hash", "hash_algorithm", "prf", "mac_hash"):
        value = extra.get(key)
        if value:
            candidates.append(str(value))
    candidates.append(str(getattr(artefact, "name", "") or ""))
    for candidate in candidates:
        squashed = _squash(candidate)
        for token, canonical in _INNER_HASH_TOKENS:
            if token in squashed:
                return canonical
    return None


# --------------------------------------------------------------------------- #
# usage resolution - structured evidence only, never file paths
# --------------------------------------------------------------------------- #
_USAGE_KEYS = (
    "usage", "usages", "role", "roles", "operation", "operations", "purpose",
    "key_usage", "keyusage", "crypto_function", "crypto_functions", "primitive",
    "alg", "algorithm_use", "ext_key_usage",
)

# Declared usage values come from a controlled vocabulary (X.509 key-usage bits,
# JWA algorithm names, detector role strings), so a squashed substring test is
# both safe and precise: "digitalSignature" -> "digitalsignature" contains
# "sign".
_DECLARED_SIGN = (
    "sign", "verify", "signature", "certsign", "crlsign", "codesign", "jws",
    "jwt", "attest", "nonrepudiation", "rs256", "rs384", "rs512", "ps256",
    "ps384", "ps512", "es256", "es384", "pss",
)
_DECLARED_KEX = (
    "encrypt", "decrypt", "keyagreement", "keyencipherment", "dataencipherment",
    "keytransport", "keyestablishment", "kem", "kex", "keyexchange", "wrap",
    "unwrap", "envelope", "seal", "unseal", "oaep", "rsaes",
)

# Free source text is matched on word boundaries instead, so "design" is not
# read as "sign" and "unsealed" is not read as "seal".
_SIGN_RE = re.compile(
    r"(?<![a-z])(sign|signs|signed|signer|signing|signature|signatures|verify|"
    r"verifies|verifier|verification|jws|jwt|attest|attestation|codesign|"
    r"certsign|crlsign|nonrepudiation|rs256|rs384|rs512|ps256|ps384|ps512|"
    r"es256|es384|pss)(?![a-z])"
)
_KEX_RE = re.compile(
    r"(?<![a-z])(encrypt|encrypts|encrypted|encryption|decrypt|decrypts|"
    r"decrypted|decryption|keyagreement|keyencipherment|dataencipherment|"
    r"keytransport|keyestablishment|kem|kex|keyexchange|wrap|wraps|unwrap|"
    r"envelope|seal|seals|unseal|oaep|rsaes)(?![a-z])"
)

_LONG_TERM_TOKENS = (
    "firmware", "bootloader", "secure boot", "secureboot", "root of trust",
    "rootoftrust", "trust anchor", "trustanchor", "root ca", "rootca",
    "archival", "archive", "long-term", "longterm",
)
_HIGH_ASSURANCE_TOKENS = (
    "high-assurance", "high_assurance", "highassurance", "cnsa", "nss",
    "classified", "top secret", "topsecret", "secret", "root ca", "rootca",
    "trust anchor", "trustanchor", "firmware",
)


def _squash_lower(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


def _plain_text(artefact: Any, include_evidence: bool = True) -> str:
    """Lower-cased free text for hint matching - deliberately NOT file paths.

    Rule selection must not depend on which directory a file happens to sit in;
    two identical primitives have to receive identical advice. Occurrence
    ``file`` values are therefore never part of this corpus.
    """
    chunks = [
        str(getattr(artefact, "name", "") or ""),
        str(getattr(artefact, "kind", "") or ""),
        str(getattr(artefact, "data_class", "") or ""),
        str(getattr(artefact, "criticality", "") or ""),
    ]
    for key, value in _extra(artefact).items():
        chunks.append(f"{key} {value}")
    if include_evidence:
        for occ in (getattr(artefact, "occurrences", []) or [])[:50]:
            chunks.append(str(getattr(occ, "evidence", "") or ""))
            chunks.append(str(getattr(occ, "detector", "") or ""))
    return " ".join(chunks).lower()


def _usage(artefact: Any) -> tuple[bool, bool]:
    """Return ``(is_signature, is_key_establishment)`` from structured evidence.

    Declared usage wins outright. A certificate is a signature artefact by
    definition. Only when nothing is declared do we fall back to the matched
    source text, on word boundaries.
    """
    extra = _extra(artefact)
    declared = _squash_lower(" ".join(str(extra.get(key, "")) for key in _USAGE_KEYS))
    sign = any(token in declared for token in _DECLARED_SIGN)
    kex = any(token in declared for token in _DECLARED_KEX)
    if sign or kex:
        return sign, kex

    if str(getattr(artefact, "kind", "")).strip().lower() == "certificate":
        return True, False

    text = _plain_text(artefact)
    return bool(_SIGN_RE.search(text)), bool(_KEX_RE.search(text))


def _is_long_term(artefact: Any) -> bool:
    """Long verification horizon -> prefer the conservative hash-based signature."""
    text = _plain_text(artefact)
    if any(token in text for token in _LONG_TERM_TOKENS):
        return True
    try:
        x_years = getattr(artefact, "x_years", None)
        if x_years is not None and float(x_years) >= 10.0:
            return True
    except (TypeError, ValueError):
        pass
    return False


def _is_high_assurance(artefact: Any) -> bool:
    if str(getattr(artefact, "criticality", "")).strip().lower() in ("critical", "high"):
        return True
    return any(token in _plain_text(artefact, include_evidence=False)
               for token in _HIGH_ASSURANCE_TOKENS)


# --------------------------------------------------------------------------- #
# protocol and PQC parameter helpers
# --------------------------------------------------------------------------- #
_TLS_VERSION_RE = re.compile(r"D?TLS[_\s]*V?[_\s]*(\d)(?:[._](\d))?", re.IGNORECASE)
_SSL_VERSION_RE = re.compile(r"SSL[_\s]*V?[_\s]*([23])", re.IGNORECASE)
_HYBRID_TOKENS = ("MLKEM", "KYBER", "HYBRID", "X25519MLKEM768", "0X11EC", "4588",
                  "SECP256R1MLKEM768", "SECP384R1MLKEM1024")


def _tls_version(artefact: Any) -> Optional[str]:
    """Normalise the observed protocol version to '1.0'..'1.3' or 'ssl'."""
    sources = [str(getattr(artefact, "name", "") or ""),
               str(getattr(artefact, "family", "") or "")]
    extra = _extra(artefact)
    for key in ("version", "protocol", "min_version", "tls_version"):
        if extra.get(key):
            sources.insert(0, str(extra[key]))
    for source in sources:
        match = _TLS_VERSION_RE.search(source)
        if match:
            major, minor = match.group(1), match.group(2)
            return f"{major}.{minor}" if minor else f"{major}.0"
        if _SSL_VERSION_RE.search(source):
            return "ssl"
    return None


def _hybrid_group_observed(artefact: Any) -> bool:
    """True when a post-quantum key-exchange group was actually recorded."""
    haystack = _squash(" ".join(
        f"{k}={v}" for k, v in _extra(artefact).items()
        if k in ("group", "groups", "named_group", "named_groups", "curve",
                 "curves", "kex", "key_exchange", "hybrid", "supported_groups")
    ))
    return any(token in haystack for token in _HYBRID_TOKENS)


def _pqc_level(family: str, artefact: Any) -> Optional[int]:
    """Parameter-set number from the name (768 for ML-KEM-768, 65 for ML-DSA-65)."""
    name = _squash(getattr(artefact, "name", "") or "")
    wanted = {"ML-KEM": (1024, 768, 512), "ML-DSA": (87, 65, 44),
              "SLH-DSA": (256, 192, 128)}.get(family, ())
    for value in wanted:
        if str(value) in name:
            return value
    size = _key_size(artefact)
    return size if size in wanted else None


def _is_pre_standard(artefact: Any) -> bool:
    extra = _extra(artefact)
    for key in ("pre_standard", "prestandard", "draft", "round3", "is_draft"):
        value = extra.get(key)
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str) and value.strip().lower() in ("1", "true", "yes"):
            return True
    if extra.get("standardised_as") or extra.get("standardized_as"):
        return True
    return any(token in _squash(getattr(artefact, "name", "") or "")
               for token in ("KYBER", "DILITHIUM", "SPHINCS"))


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #
def classify(artefact: Any) -> str:
    """Map an artefact onto a :data:`REC_KB` rule id. Pure and deterministic."""
    family = _canonical_family(artefact)
    key_size = _key_size(artefact)
    mode = _mode(artefact)
    padding = _padding(artefact)

    # --- post-quantum families -------------------------------------------- #
    if family in _BROKEN_PQC:
        return "REMOVE_BROKEN_PQC"
    if family in _PRESTANDARD_PQC:
        return "PQC_PRESTANDARD"
    if family in ("XMSS", "LMS"):
        return "PQC_STATEFUL"
    if family == "FN-DSA":
        return "PQC_DRAFT"
    if family in _FINAL_PQC:
        if _is_pre_standard(artefact):
            return "PQC_PRESTANDARD"
        level = _pqc_level(family, artefact)
        if (family == "ML-KEM" and level == 512) or (family == "ML-DSA" and level == 44):
            return "PQC_UNDERSTRENGTH"
        return "PQC_OK"

    # --- protocols ---------------------------------------------------------- #
    if family == "TLS":
        version = _tls_version(artefact)
        if version in ("ssl", "1.0", "1.1", "2.0", "3.0"):
            return "TLS_13"
        if version == "1.2":
            return "TLS12_HYBRID"
        if version == "1.3":
            return "QSAFE_OK" if _hybrid_group_observed(artefact) else "TLS13_HYBRID_GROUP"
        return "TLS_13"

    # --- keyed constructions: judge the inner digest, not the wrapper -------- #
    if family in ("HMAC", "KDF"):
        inner = _inner_hash(artefact)
        if inner in _LEGACY_HASHES:
            return "KEYED_HASH_LEGACY"
        return "QSAFE_OK"

    # --- hashes ------------------------------------------------------------- #
    if family in _LEGACY_HASHES:
        return "HASH_SHA256"
    if family == "SHA-224":
        return "HASH_SHA256"
    if family == "SHA-256":
        return "SHA256_TO_384" if _is_high_assurance(artefact) else "QSAFE_OK"
    if family in ("SHA-384", "SHA-512", "SHA-3"):
        return "QSAFE_OK"

    # --- symmetric ---------------------------------------------------------- #
    if family in _LEGACY_CIPHERS:
        return "CIPHER_AES256"
    if family == "AES":
        if mode == "ECB":
            return "ECB_TO_GCM"
        if key_size is not None and key_size < 256:
            return "AES128_UPGRADE"
        if mode in ("CBC", "CTR", "CFB", "CFB8", "OFB"):
            return "UNAUTH_MODE_TO_AEAD"
        return "QSAFE_OK"
    if family == "CHACHA20":
        return "QSAFE_OK"

    # --- asymmetric --------------------------------------------------------- #
    if family == "RSA":
        sign, kex = _usage(artefact)
        if sign and kex:
            return "AMBIGUOUS_USAGE"
        if sign:
            return "SIG_SLHDSA" if _is_long_term(artefact) else "SIG_MLDSA"
        if kex:
            if padding.startswith("PKCS1V15") or padding in ("PKCS1", "PKCS115"):
                return "PKCS1V15_TO_OAEP"
            return "KEM_HYBRID"
        # No usage evidence at all: PKCS#1 v1.5 *encryption* padding is the only
        # unambiguous structural hint, and even it is used for signatures too.
        return "AMBIGUOUS_USAGE"

    if family in ("ECDSA", "ED25519", "ED448", "DSA"):
        return "SIG_SLHDSA" if _is_long_term(artefact) else "SIG_MLDSA"
    if family in ("ECDH", "DH", "X25519", "X448"):
        return "KEM_HYBRID"

    return "UNKNOWN"


# --------------------------------------------------------------------------- #
# autofix
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FixRule:
    """One mechanical, format-preserving source substitution.

    A rule may only be added here if applying it leaves key material, message
    format, output length in the target language and the surrounding API shape
    unchanged.  Everything else is a human change.
    """
    rule_id: str
    families: frozenset
    pattern: "re.Pattern[str]"
    repl: Any                      # str or Callable[[re.Match, Any], str]
    guard: Optional[Callable[[Any], bool]] = None
    note: str = ""


# Contexts where a digest value is pinned and swapping the constructor breaks
# interoperation instead of fixing a weakness: keyed constructions, padding and
# mask-generation parameters, one-time-password algorithms mandated by their own
# RFCs, verification/comparison paths, and stored digest records.
_PINNED_DIGEST_CONTEXT = re.compile(
    r"(hmac|mgf1|\bmgf\b|oaep|\bpss\b|pkcs1|totp|hotp|\botp\b|pbkdf2|hkdf|"
    r"\bkdf\b|derive_key|derivekey|verify|verif|compare_digest|constant_time|"
    r"password|passwd|pwd_hash|stored|checksum_db|git|object_id|objectid|"
    r"signature|\bsign\b|fingerprint_pin|pinned)",
    re.IGNORECASE,
)

# Rules whose safety depends on the digest not being pinned.
_HASH_SWAP_RULES = frozenset({
    "md5.hashlib", "md5.hashlib.new", "md5.node", "md5.java", "md5.hashes",
    "sha1.hashlib", "sha1.hashlib.new", "sha1.node", "sha1.java", "sha1.hashes",
})

FIX_RULES: tuple[FixRule, ...] = (
    # ---- broken hashes, fresh-digest call sites only ----------------------- #
    # Deliberately absent: the OpenSSL EVP_md5()/EVP_sha1() swaps.  In C the
    # digest is written into a caller-supplied buffer sized by
    # MD5_DIGEST_LENGTH (16) or SHA_DIGEST_LENGTH (20); switching to SHA-256
    # writes 32 bytes and overflows it.  A memory-safety bug is not an
    # acceptable price for removing a weak hash.
    FixRule("md5.hashlib", frozenset({"MD5"}),
            re.compile(r"\bhashlib\.md5\s*\("), "hashlib.sha256(",
            note="Python hashlib constructor swap."),
    FixRule("md5.hashlib.new", frozenset({"MD5"}),
            re.compile(r"(hashlib\.new\(\s*['\"])md5(['\"])", re.IGNORECASE), r"\1sha256\2",
            note="Python hashlib.new name swap."),
    FixRule("md5.node", frozenset({"MD5"}),
            re.compile(r"(createHash\(\s*['\"])md5(['\"]\s*\))", re.IGNORECASE), r"\1sha256\2",
            note="Node crypto.createHash algorithm swap."),
    FixRule("md5.java", frozenset({"MD5"}),
            re.compile(r"(MessageDigest\.getInstance\(\s*\")MD5(\")", re.IGNORECASE),
            r"\1SHA-256\2", note="Java MessageDigest algorithm swap."),
    FixRule("md5.hashes", frozenset({"MD5"}),
            re.compile(r"\bhashes\.MD5\s*\(\s*\)"), "hashes.SHA256()",
            note="python-cryptography hash object swap."),
    FixRule("sha1.hashlib", frozenset({"SHA-1"}),
            re.compile(r"\bhashlib\.sha1\s*\("), "hashlib.sha256(",
            note="Python hashlib constructor swap."),
    FixRule("sha1.hashlib.new", frozenset({"SHA-1"}),
            re.compile(r"(hashlib\.new\(\s*['\"])sha-?1(['\"])", re.IGNORECASE), r"\1sha256\2",
            note="Python hashlib.new name swap."),
    FixRule("sha1.node", frozenset({"SHA-1"}),
            re.compile(r"(createHash\(\s*['\"])sha-?1(['\"]\s*\))", re.IGNORECASE),
            r"\1sha256\2", note="Node crypto.createHash algorithm swap."),
    FixRule("sha1.java", frozenset({"SHA-1"}),
            re.compile(r"(MessageDigest\.getInstance\(\s*\")SHA-?1(\")", re.IGNORECASE),
            r"\1SHA-256\2", note="Java MessageDigest algorithm swap."),
    FixRule("sha1.hashes", frozenset({"SHA-1"}),
            re.compile(r"\bhashes\.SHA1\s*\(\s*\)"), "hashes.SHA256()",
            note="python-cryptography hash object swap."),

    # ---- protocol versions ------------------------------------------------- #
    # A version identifier is a pure configuration token: no key material, no
    # message format owned by this process, no API shape change.
    FixRule("tls.string", frozenset({"TLS"}),
            re.compile(r"(['\"])(?:SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1|TLS1\.0|TLS1\.1)\1"),
            r"\1TLSv1.3\1",
            note="Protocol name string (Java SSLContext / config value)."),
    FixRule("tls.python.version", frozenset({"TLS"}),
            re.compile(r"(ssl\.TLSVersion\.)(?:SSLv3|TLSv1|TLSv1_1)\b"), r"\1TLSv1_3",
            note="Python ssl.TLSVersion minimum/maximum constant."),

    # ---- deliberately NOT here --------------------------------------------- #
    # aes.weak.string   'aes-128-cbc' -> 'aes-256-gcm': doubles the key length
    #                   (16 B key into an AES-256 API raises) and changes the
    #                   ciphertext format.
    # aes.ecb.string    'aes-256-ecb' -> 'aes-256-gcm': the ciphertext gains a
    #                   nonce and a tag that the surrounding format cannot carry.
    # aes.java.ecb/cbc  AES/CBC/PKCS5Padding -> AES/GCM/NoPadding: JCE requires a
    #                   GCMParameterSpec, and an IV derivation that was safe for
    #                   CBC becomes catastrophic GCM nonce reuse.
    # aes.pycryptodome  AES.MODE_ECB -> AES.MODE_GCM: PyCryptodome generates a
    #                   fresh random nonce that the existing code neither stores
    #                   nor transmits, and encrypt() no longer returns a tag, so
    #                   the ciphertext silently becomes undecryptable.
    # rsa.*             key_size 1024/2048 -> 3072: new key material, and it
    #                   entrenches RSA in an artefact whose own recommendation is
    #                   ML-KEM or ML-DSA. (For the record: SP 800-131A Rev.2 sets
    #                   the RSA floor at 2048; 3072 is the SP 800-57 Part 1 Rev.5
    #                   size for 128-bit classical strength.)
)


def _rules_for(artefact: Any) -> list[FixRule]:
    family = _canonical_family(artefact)
    rules: list[FixRule] = []
    for rule in FIX_RULES:
        if rule.families and family not in rule.families:
            continue
        if rule.guard is not None:
            try:
                if not rule.guard(artefact):
                    continue
            except Exception:
                continue
        rules.append(rule)
    return rules


def _apply_rules(line: str, rules: Iterable[FixRule], artefact: Any) -> tuple[str, list[str]]:
    """Apply every applicable rule to one source line. Returns (line, rule_ids)."""
    applied: list[str] = []
    for rule in rules:
        repl = rule.repl
        try:
            if callable(repl):
                new_line, count = rule.pattern.subn(lambda m: repl(m, artefact), line)
            else:
                new_line, count = rule.pattern.subn(repl, line)
        except Exception:
            continue
        if count and new_line != line:
            line = new_line
            applied.append(rule.rule_id)
    return line, applied


def _pinned_digest_nearby(lines: list[str], index: int, window: int = 3) -> bool:
    """Is this digest call site inside a context where the value is pinned?"""
    start = max(0, index - window)
    end = min(len(lines), index + window + 1)
    return bool(_PINNED_DIGEST_CONTEXT.search("\n".join(lines[start:end])))


def _read_lines(path: str) -> Optional[list[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except (OSError, ValueError):
        return None
    return content.splitlines()


def _resolve_path(path: str, repo_root: Optional[str]) -> str:
    """Occurrence paths are root-relative POSIX paths; make them readable.

    Source detectors record ``os.path.relpath(full, root)``, so opening the
    recorded string only works when the process CWD happens to equal the scan
    root.  Everywhere else the read failed and the autofix silently produced
    nothing, which then rendered as the (wrong) "no safe automatic patch" text.
    """
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(repo_root or ".", path))


def _diff_path(path: str, repo_root: Optional[str]) -> str:
    """Label used in the diff header - always repo-relative, always POSIX."""
    raw = str(path or "")
    if os.path.isabs(raw) and repo_root:
        try:
            relative = os.path.relpath(raw, repo_root)
            if not relative.startswith(".."):
                return relative.replace(os.sep, "/")
        except (ValueError, OSError):
            pass
    posix = raw.replace(os.sep, "/")
    while posix.startswith("./"):
        posix = posix[2:]
    return posix.lstrip("/")


def generate_fix(artefact: Any, repo_root: Optional[str] = None,
                 max_files: int = 25, errors: Optional[list] = None) -> str:
    """Build a unified diff for the mechanically-safe fixes on this artefact.

    Reads the real source lines from disk (resolving root-relative occurrence
    paths against ``repo_root``), applies only the substitutions in
    :data:`FIX_RULES`, and renders a ``git apply -p1``-compatible patch with
    three lines of context.

    Returns ``""`` when no safe fix exists, when the digest is pinned by its
    surrounding context, when the recorded line no longer matches, or when the
    file cannot be read - never a guess.  When ``errors`` is supplied, an entry
    is appended for every file that could not be read and every site suppressed
    as pinned, so "no patch because unsafe" is distinguishable from "no patch
    because the file was missing".
    """
    rules = _rules_for(artefact)
    if not rules:
        return ""

    by_file: dict[str, list[Any]] = {}
    for occ in getattr(artefact, "occurrences", []) or []:
        path = str(getattr(occ, "file", "") or "")
        if not path or "://" in path:      # network artefacts have no source file
            continue
        by_file.setdefault(path, []).append(occ)

    diffs: list[str] = []
    for path in sorted(by_file)[:max_files]:
        full = _resolve_path(path, repo_root)
        original = _read_lines(full)
        if original is None:
            if errors is not None:
                errors.append(
                    f"recommend: cannot read {full} for {getattr(artefact, 'name', '?')}; "
                    "no patch generated for this file"
                )
            continue
        patched = list(original)
        touched = False

        for occ in by_file[path]:
            index = _locate(occ, patched, rules, artefact)
            if index is None:
                continue
            if any(rule.rule_id in _HASH_SWAP_RULES for rule in rules) and \
                    _pinned_digest_nearby(patched, index):
                if errors is not None:
                    errors.append(
                        f"recommend: hash swap suppressed at {path}:{index + 1} - the digest "
                        "value is pinned by its context (keyed/padding/verification/stored "
                        "digest); changing the constructor there breaks interoperation"
                    )
                continue
            new_line, applied = _apply_rules(patched[index], rules, artefact)
            if applied and new_line != patched[index]:
                patched[index] = new_line
                touched = True

        if not touched:
            continue

        label = _diff_path(path, repo_root)
        diff_lines = difflib.unified_diff(
            original, patched,
            fromfile=f"a/{label}", tofile=f"b/{label}",
            n=3, lineterm="",
        )
        rendered = "\n".join(diff_lines)
        if rendered:
            diffs.append(rendered + "\n")

    return "".join(diffs)


def _locate(occ: Any, lines: list[str], rules: list[FixRule],
            artefact: Any) -> Optional[int]:
    """Find the 0-based index of the line this occurrence refers to.

    Trusts the recorded line number first. If that line no longer matches any
    rule (the file moved on since the scan), falls back to a unique match on the
    recorded evidence text. Ambiguous fallbacks are refused.
    """
    line_no = getattr(occ, "line", None)
    if isinstance(line_no, int) and 1 <= line_no <= len(lines):
        candidate = lines[line_no - 1]
        _, applied = _apply_rules(candidate, rules, artefact)
        if applied:
            return line_no - 1

    evidence = str(getattr(occ, "evidence", "") or "").strip()
    if len(evidence) < 4:
        return None
    matches = [i for i, line in enumerate(lines) if evidence in line]
    if len(matches) != 1:
        return None
    _, applied = _apply_rules(lines[matches[0]], rules, artefact)
    return matches[0] if applied else None


# --------------------------------------------------------------------------- #
# recommendation entry points
# --------------------------------------------------------------------------- #
def _rationale(artefact: Any, entry: dict[str, Any], fix_patch: str,
               had_rules: bool, fix_errors: list) -> str:
    """Compose the per-artefact rationale: KB text + this artefact's evidence."""
    parts: list[str] = [entry["rationale"]]

    threat_reason = str(getattr(artefact, "threat_reason", "") or "").strip()
    if threat_reason:
        parts.append(f"Risk engine finding: {threat_reason}")

    occurrences = getattr(artefact, "occurrences", []) or []
    if occurrences:
        files = sorted({str(getattr(o, "file", "") or "") for o in occurrences})
        first = occurrences[0]
        location = f"{getattr(first, 'file', '?')}:{getattr(first, 'line', '?')}"
        parts.append(
            f"Evidence: {len(occurrences)} occurrence(s) across {len(files)} file(s), "
            f"first at {location}."
        )

    if fix_patch:
        parts.append(
            "A mechanical patch is attached (fix_patch). It changes only the algorithm "
            "identifier on the flagged lines - it does not change key material, message "
            "format or API shape - but review it, run the test suite, and confirm no peer "
            "or stored record pins the old value before merging."
        )
    elif had_rules and fix_errors:
        parts.append(
            "No patch was produced because the recorded source could not be read or the "
            "call site is one where the digest value is pinned. See trade_offs['fix_notes'] "
            "- this is not the same as the change being unsafe in principle."
        )
    else:
        parts.append(
            "No safe automatic patch: this change alters key material, message format or "
            "protocol negotiation, so ECDAT will not generate a diff. "
            f"{entry['trade_offs'].get('migration', '')}".strip()
        )

    parts.append(f"Standard: {entry['standard']}. Alternatives: {entry['alternatives']}")
    return " ".join(p for p in parts if p)


def recommend(artefact: Any, repo_root: Optional[str] = None) -> Any:
    """Attach recommendation, rationale, trade-offs and (where safe) a patch."""
    try:
        rule_id = classify(artefact)
    except Exception:
        rule_id = "UNKNOWN"
    entry = REC_KB.get(rule_id, REC_KB["UNKNOWN"])

    fix_errors: list[str] = []
    had_rules = False
    try:
        had_rules = bool(_rules_for(artefact))
        fix_patch = generate_fix(artefact, repo_root=repo_root, errors=fix_errors)
    except Exception as error:  # a broken artefact must not stop the batch
        fix_patch = ""
        fix_errors.append(f"recommend: fix generation failed: {error!r}")

    trade_offs = dict(entry["trade_offs"])
    trade_offs["rule_id"] = rule_id
    trade_offs["standard"] = entry["standard"]
    if fix_errors:
        trade_offs["fix_notes"] = fix_errors

    artefact.recommendation = entry["recommendation"]
    artefact.rec_rationale = _rationale(artefact, entry, fix_patch, had_rules, fix_errors)
    artefact.trade_offs = trade_offs
    artefact.fix_patch = fix_patch

    # Keep the machine-readable trail on a declared, serialised field too.
    extra = _extra(artefact)
    if extra is not None and isinstance(extra, dict):
        extra["rec_rule_id"] = rule_id
        if fix_errors:
            extra["fix_notes"] = list(fix_errors)
    return artefact


def recommend_all(artefacts: list[Artefact], repo_root: Optional[str] = None) -> list[Artefact]:
    """Enrich every artefact in place; one bad artefact never stops the batch."""
    for artefact in artefacts or []:
        if artefact is None:
            continue
        try:
            recommend(artefact, repo_root=repo_root)
        except Exception:
            try:
                entry = REC_KB["UNKNOWN"]
                artefact.recommendation = entry["recommendation"]
                artefact.rec_rationale = entry["rationale"]
                artefact.trade_offs = dict(entry["trade_offs"])
                artefact.fix_patch = ""
            except Exception:
                pass
    return artefacts
