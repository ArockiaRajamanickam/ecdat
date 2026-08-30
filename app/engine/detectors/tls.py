"""Live TLS endpoint detector for ECDAT.

Source code and manifests describe what a system *intends* to negotiate.  This
module records what it *actually* negotiates on the wire: protocol version,
cipher suite, key-exchange group, and the served certificate chain.  That gap is
where most real migration surprises live - a repository can be fully modernised
while the load balancer in front of it still terminates TLS 1.0 with a static
RSA key exchange.

Safety contract
---------------
* **Importing this module opens no sockets.**
* **``detect()`` connects only to endpoints the policy explicitly lists.**  With
  no ``tls.endpoints`` configured it returns ``([], 0, [])`` without touching
  the network, so a registry that walks every detector over a source tree stays
  entirely offline unless the operator opted in.  ``root_path`` is accepted for
  protocol conformance and is never used to derive a target.
* **One connection per endpoint.**  No retries, no redirects, no follow-on
  requests.  ``probe_pqc`` may add a single extra connection, and only on
  interpreters whose ``ssl`` module can pin key-exchange groups (see below).
* **Hard timeout.**  ``timeout`` is applied to connect *and* to the handshake.
* **Never raises.**  Every failure is returned as a string in ``errors``.
* Nothing is sent after the handshake: no HTTP request, no data.

PQC / hybrid detection
----------------------
The negotiated key-exchange group is the only reliable place to see a hybrid
KEM such as ``X25519MLKEM768``.  CPython exposes it via ``SSLSocket.group()``
only on newer builds; ``SSLContext.set_ecdh_curve()`` cannot pin a hybrid group
because it resolves names through the EC curve NID table.  So this module:

1. reads the negotiated group when the runtime offers it (authoritative);
2. otherwise looks for PQC tokens in the cipher-suite string;
3. otherwise reports ``pqc_group`` as unmeasured and says plainly that the
   runtime could not tell us - it never claims an endpoint is classical-only on
   the strength of a measurement it could not take.

API
---
    detect(root_path, policy)                  -> (artefacts, endpoints, errors)
    scan_endpoint(host, port=443, timeout=6.0) -> (list[Artefact], list[str])
    scan_endpoints(targets, ...)               -> (list[Artefact], list[str])
    parse_target("example.gov.in:8443")        -> ("example.gov.in", 8443)
    parse_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384") -> dict

Path convention
---------------
Network artefacts keep an explicit ``tls://host:port`` occurrence path, which is
unambiguous against the root-relative filesystem paths every other detector
emits.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from typing import Any, Iterable, Optional

try:  # package-relative first (normal case)
    from ..models import Artefact, Occurrence, Params
    from .certs import artefacts_from_certificate
except ImportError:  # pragma: no cover - standalone / script execution
    from app.engine.models import Artefact, Occurrence, Params  # type: ignore
    from app.engine.detectors.certs import artefacts_from_certificate  # type: ignore

try:
    from cryptography import x509 as _x509

    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _x509 = None  # type: ignore
    _CRYPTO_OK = False


NAME = "tls"
DETECTOR = "tls"

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 6.0

#: hybrid / pure PQC groups worth pinning when the runtime allows it
PQC_GROUPS: tuple[str, ...] = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "MLKEM768",
    "MLKEM1024",
    "X25519Kyber768Draft00",
)

#: tokens that mark a group or suite as post-quantum
_PQC_TOKEN_RE = re.compile(
    r"(mlkem|ml-kem|kyber|frodo|bike|hqc|sntrup|ntru|mceliece|sike|saber|"
    r"mldsa|ml-dsa|dilithium|falcon|sphincs)",
    re.IGNORECASE,
)

_PROTOCOL_FAMILY = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLSv1": "TLSv1.0",
    "TLSv1.0": "TLSv1.0",
    "TLSv1.1": "TLSv1.1",
    "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3",
}

#: protocol versions that are deprecated outright (RFC 8996 and earlier)
_LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

_KEX_TOKENS = {
    "ECDHE", "EECDH", "DHE", "EDH", "ECDH", "DH", "RSA", "PSK", "SRP",
    "ADH", "AECDH", "DHE_PSK", "ECDHE_PSK", "RSA_PSK", "GOST",
}
_AUTH_TOKENS = {"RSA", "ECDSA", "DSS", "PSK", "SRP", "anon", "ECDSA_SHA1"}

_BULK_SPECS: tuple[tuple[str, str, str, Optional[int]], ...] = (
    # (token, display family, canonical family, key bits)
    ("CHACHA20", "ChaCha20-Poly1305", "ChaCha20-Poly1305", 256),
    ("AES256", "AES", "AES", 256),
    ("AES128", "AES", "AES", 128),
    ("AES", "AES", "AES", None),
    ("CAMELLIA256", "Camellia", "Camellia", 256),
    ("CAMELLIA128", "Camellia", "Camellia", 128),
    ("ARIA256", "ARIA", "ARIA", 256),
    ("ARIA128", "ARIA", "ARIA", 128),
    ("3DES", "3DES", "3DES", 168),
    ("DES3", "3DES", "3DES", 168),
    ("CBC3", "3DES", "3DES", 168),
    ("IDEA", "IDEA", "IDEA", 128),
    ("SEED", "SEED", "SEED", 128),
    ("RC4", "RC4", "RC4", 128),
    ("RC2", "RC2", "RC2", 128),
    ("DES", "DES", "DES", 56),
    ("NULL", "NULL", "NULL", 0),
)

#: bulk ciphers that are broken outright, with the reason shown as evidence
_BROKEN_BULK = {
    "RC4": "RC4 is prohibited by RFC 7465 (biased keystream).",
    "DES": "Single DES has a 56-bit key and is brute-forceable today.",
    "3DES": "3DES is limited to a 64-bit block (Sweet32) and is disallowed by NIST after 2023.",
    "RC2": "RC2 is obsolete and cryptographically broken.",
    "IDEA": "IDEA is obsolete and removed from modern TLS stacks.",
    "NULL": "NULL cipher: the session carries plaintext.",
}

#: fixed digest lengths, so a hash artefact carries its variant in params and
#: not only in its display name (the risk engine classifies from parameters)
_DIGEST_BITS: dict[str, int] = {
    "MD5": 128, "SHA-1": 160,
    "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
    "SHA3-224": 224, "SHA3-256": 256, "SHA3-384": 384, "SHA3-512": 512,
}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _clip(text: str, limit: int = 320) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_target(target: str, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """Accept ``host``, ``host:port``, ``https://host:port/path`` or ``[::1]:443``."""
    raw = (target or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    if raw.startswith("["):  # bracketed IPv6
        host, _, tail = raw.partition("]")
        host = host[1:]
        port = int(tail.lstrip(":")) if tail.lstrip(":").isdigit() else default_port
        return host, port
    if raw.count(":") == 1:
        host, _, tail = raw.partition(":")
        return host, int(tail) if tail.isdigit() else default_port
    return raw, default_port  # bare host or unbracketed IPv6


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_pqc(name: Optional[str]) -> bool:
    return bool(name and _PQC_TOKEN_RE.search(name))


def parse_cipher_suite(name: str) -> dict[str, Any]:
    """Decompose an OpenSSL or IANA cipher-suite name into its primitives.

    ``ECDHE-RSA-AES256-GCM-SHA384`` and ``TLS_AES_256_GCM_SHA384`` both resolve
    to a key exchange, an authentication algorithm, a bulk cipher with mode and
    key size, and a MAC/PRF hash.
    """
    out: dict[str, Any] = {
        "suite": name,
        "tls13": False,
        "kex": None,
        "auth": None,
        "bulk": None,
        "bulk_family": None,
        "bulk_bits": None,
        "mode": None,
        "mac": None,
        "aead": False,
        "forward_secrecy": None,
        "anonymous": False,
    }
    if not name:
        return out

    upper = name.upper()
    if upper.startswith("TLS_") and "_WITH_" not in upper:
        # TLS 1.3 suite: key exchange and auth are negotiated separately
        out["tls13"] = True
        tokens = upper[4:].split("_")
        out["kex"] = "ECDHE"  # TLS 1.3 is always ephemeral
        out["forward_secrecy"] = True
    elif "_WITH_" in upper:  # IANA form, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        left, _, right = upper.partition("_WITH_")
        left_tokens = [t for t in left.split("_") if t and t != "TLS"]
        tokens = right.split("_")
        if left_tokens:
            out["kex"] = left_tokens[0]
            if len(left_tokens) > 1:
                out["auth"] = left_tokens[1]
    else:
        tokens = upper.split("-")
        if tokens and tokens[0] in _KEX_TOKENS:
            out["kex"] = tokens[0]
            tokens = tokens[1:]
            if tokens and tokens[0] in _AUTH_TOKENS:
                out["auth"] = tokens[0]
                tokens = tokens[1:]
        else:
            # No key-exchange prefix means static RSA key transport.
            out["kex"] = "RSA"
            out["auth"] = "RSA"

    kex = out["kex"] or ""
    if out["forward_secrecy"] is None:
        out["forward_secrecy"] = kex in {"ECDHE", "EECDH", "DHE", "EDH", "AECDH", "ADH"}
    out["anonymous"] = kex in {"ADH", "AECDH"} or out["auth"] == "anon"
    if out["auth"] is None and kex in {"RSA", "ECDH", "DH"}:
        out["auth"] = "RSA"

    joined = "-".join(tokens)
    for token, display, family, bits in _BULK_SPECS:
        if token in tokens or token in joined:
            out["bulk_family"] = family
            out["bulk_bits"] = bits
            break

    # explicit key size token (AES_256_GCM style)
    if out["bulk_family"] and out["bulk_bits"] is None:
        for tok in tokens:
            if tok.isdigit() and int(tok) in (128, 192, 256):
                out["bulk_bits"] = int(tok)
                break

    if "POLY1305" in joined:
        out["mode"] = "Poly1305"
    elif "GCM" in tokens:
        out["mode"] = "GCM"
    elif "CCM8" in tokens or "CCM_8" in joined:
        out["mode"] = "CCM8"
    elif "CCM" in tokens:
        out["mode"] = "CCM"
    elif out["bulk_family"] in ("RC4", "NULL", None):
        out["mode"] = None
    else:
        out["mode"] = "CBC"

    out["aead"] = out["mode"] in ("GCM", "CCM", "CCM8", "Poly1305")

    for tok in reversed(tokens):
        if tok.startswith("SHA") or tok == "MD5":
            out["mac"] = "SHA-1" if tok == "SHA" else (
                "MD5" if tok == "MD5" else f"SHA-{tok[3:]}" if tok[3:].isdigit() else tok
            )
            break

    if out["bulk_family"]:
        bits = out["bulk_bits"]
        mode = out["mode"]
        label = out["bulk_family"]
        if label == "ChaCha20-Poly1305":
            out["bulk"] = "ChaCha20-Poly1305"
        else:
            out["bulk"] = label + (f"-{bits}" if bits else "") + (f"-{mode}" if mode else "")
    return out


def _hash_family(display: str) -> str:
    if display.startswith("SHA3-"):
        return "SHA-3"
    if display in ("SHA-1", "SHA"):
        return "SHA-1"
    if display == "MD5":
        return "MD5"
    if display.startswith("SHA-"):
        return "SHA-2"
    return display or "UNKNOWN"


def _digest_bits(display: str) -> Optional[int]:
    """Digest length in bits for a normalised hash display name."""
    if display in _DIGEST_BITS:
        return _DIGEST_BITS[display]
    m = re.fullmatch(r"(?:SHA-|SHA3-)(\d{3})", display or "")
    if m:
        size = int(m.group(1))
        return size if size in (224, 256, 384, 512) else None
    return None


def _hostname_matches(cert: Any, host: str) -> Optional[bool]:
    """RFC 6125 style check against SAN dNSName (falling back to CN)."""
    if cert is None or not host:
        return None
    names: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        names.extend(ext.value.get_values_for_type(_x509.DNSName))
        if _is_ip(host):
            names.extend(str(v) for v in ext.value.get_values_for_type(_x509.IPAddress))
    except Exception:
        pass
    if not names:
        try:
            attrs = cert.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)
            names.extend(str(a.value) for a in attrs)
        except Exception:
            return None
    if not names:
        return None
    target = host.lower().rstrip(".")
    for candidate in names:
        pattern = str(candidate).lower().rstrip(".")
        if pattern == target:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.in"
            if target.endswith(suffix) and target.count(".") == pattern.count("."):
                return True
    return False


def _negotiated_group(ssock: Any) -> Optional[str]:
    """Read the negotiated key-exchange group, where the runtime exposes it."""
    for attr in ("group", "negotiated_group"):
        fn = getattr(ssock, attr, None)
        if callable(fn):
            try:
                value = fn()
                if value:
                    return str(value)
            except Exception:
                continue
    return None


def _try_set_groups(ctx: ssl.SSLContext, groups: Iterable[str]) -> bool:
    """Pin key-exchange groups when the interpreter supports it.

    ``SSLContext.set_groups()`` exists only on newer CPython builds.
    ``set_ecdh_curve()`` is *not* a substitute: it resolves names through the EC
    curve NID table and therefore rejects hybrid names like X25519MLKEM768.
    """
    setter = getattr(ctx, "set_groups", None)
    if not callable(setter):
        return False
    names = list(groups)
    try:
        setter(names)
        return True
    except Exception:
        try:
            setter(":".join(names))
            return True
        except Exception:
            return False


def _build_context(permissive: bool = True) -> ssl.SSLContext:
    """A client context tuned for *observation*, not for protecting traffic.

    Verification is off and the security level is lowered on purpose: a
    discovery tool has to be able to see the weak endpoints it is looking for.
    Nothing is ever sent over these sockets.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if permissive:
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        except Exception:
            pass
        for spec in ("ALL:@SECLEVEL=0", "ALL:COMPLEMENTOFDEFAULT:@SECLEVEL=0", "ALL"):
            try:
                ctx.set_ciphers(spec)
                break
            except Exception:
                continue
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    return ctx


def _handshake(
    host: str, port: int, timeout: float, ctx: ssl.SSLContext, sni: Optional[str]
) -> dict[str, Any]:
    """One connection, one handshake, no data sent. Raises on failure."""
    observation: dict[str, Any] = {}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
            observation["version"] = ssock.version()
            observation["cipher"] = ssock.cipher()
            observation["group"] = _negotiated_group(ssock)
            observation["compression"] = ssock.compression()
            try:
                observation["alpn"] = ssock.selected_alpn_protocol()
            except Exception:
                observation["alpn"] = None
            try:
                observation["der"] = ssock.getpeercert(binary_form=True)
            except Exception:
                observation["der"] = None
    return observation


def _occ(host: str, port: int, evidence: str, confidence: str = "high") -> Occurrence:
    return Occurrence(
        file=f"tls://{host}:{port}",
        line=None,
        evidence=_clip(evidence),
        detector=DETECTOR,
        confidence=confidence,
    )


def _mk(
    name: str,
    family: str,
    kind: str,
    host: str,
    port: int,
    evidence: str,
    *,
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
    mode: Optional[str] = None,
    padding: Optional[str] = None,
    not_after: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
    confidence: str = "high",
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
        occurrences=[_occ(host, port, evidence, confidence)],
    )


# --------------------------------------------------------------------------- #
# policy plumbing
# --------------------------------------------------------------------------- #
def _policy_section(policy: Any, key: str) -> Any:
    """Read one top-level key from a Policy object, a mapping or a namespace."""
    if policy is None:
        return None
    data = getattr(policy, "data", None)
    if isinstance(data, dict) and key in data:
        return data[key]
    if isinstance(policy, dict) and key in policy:
        return policy[key]
    value = getattr(policy, key, None)
    if callable(value):
        try:
            return value()
        except Exception:
            return None
    return value


def _endpoints_from_policy(policy: Any) -> tuple[list[str], dict[str, Any], list[str]]:
    """Extract the configured endpoint list and probe options.

    Returns ``(targets, options, errors)``.  An absent or empty configuration
    yields an empty target list, which keeps ``detect()`` completely offline.
    """
    errors: list[str] = []
    options: dict[str, Any] = {
        "timeout": DEFAULT_TIMEOUT,
        "probe_pqc": True,
        "enabled": True,
    }
    if policy is None:
        return [], options, errors

    section = _policy_section(policy, "tls")
    raw_endpoints: Any = None
    if isinstance(section, dict):
        raw_endpoints = section.get("endpoints", section.get("targets"))
        for key in ("timeout", "probe_pqc", "enabled"):
            if key in section:
                options[key] = section[key]
    elif isinstance(section, (list, tuple)):
        raw_endpoints = section
    if raw_endpoints is None:
        raw_endpoints = _policy_section(policy, "tls_endpoints")
    if raw_endpoints is None:
        return [], options, errors

    if isinstance(raw_endpoints, str):
        raw_endpoints = [raw_endpoints]
    if not isinstance(raw_endpoints, (list, tuple, set)):
        return [], options, [
            f"tls: policy 'tls.endpoints' must be a list, got "
            f"{type(raw_endpoints).__name__}; no endpoints probed"
        ]

    targets: list[str] = []
    for item in raw_endpoints:
        if isinstance(item, str):
            if item.strip():
                targets.append(item.strip())
        elif isinstance(item, dict):
            host = item.get("host") or item.get("hostname") or item.get("target")
            if not host:
                errors.append(f"tls: endpoint entry {item!r} has no 'host'; skipped")
                continue
            port = item.get("port")
            targets.append(f"{host}:{port}" if port else str(host))
        else:
            errors.append(f"tls: unusable endpoint entry {item!r}; skipped")

    try:
        options["timeout"] = float(options.get("timeout", DEFAULT_TIMEOUT))
    except Exception:
        options["timeout"] = DEFAULT_TIMEOUT
    options["probe_pqc"] = bool(options.get("probe_pqc", True))
    options["enabled"] = bool(options.get("enabled", True))
    return targets, options, errors


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def scan_endpoint(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    sni: Optional[str] = None,
    probe_pqc: bool = True,
) -> tuple[list[Artefact], list[str]]:
    """Connect once to ``host:port`` and record the negotiated cryptography.

    Args:
        host: hostname or IP.  ``host:port`` and ``https://host/...`` forms are
            accepted and parsed, in which case ``port`` acts as the default.
        port: TCP port, default 443.
        timeout: hard timeout in seconds for connect and handshake alike.
        sni: override the SNI name (defaults to ``host`` unless it is an IP).
        probe_pqc: allow one extra connection pinned to hybrid PQC groups, on
            interpreters that can pin groups.  On interpreters that cannot
            (most today) this costs nothing and is silently skipped.

    Returns:
        ``(artefacts, errors)``.  Never raises.
    """
    artefacts: list[Artefact] = []
    errors: list[str] = []

    try:
        host, port = parse_target(str(host), default_port=port)
    except Exception as exc:
        return [], [f"tls: cannot parse target {host!r}: {exc}"]

    if not host:
        return [], ["tls: empty host"]
    try:
        port = int(port)
        if not (0 < port < 65536):
            raise ValueError(port)
    except Exception:
        return [], [f"tls://{host}: invalid port {port!r}"]
    try:
        timeout = float(timeout)
        if timeout <= 0:
            timeout = DEFAULT_TIMEOUT
    except Exception:
        timeout = DEFAULT_TIMEOUT

    server_name = sni if sni is not None else (None if _is_ip(host) else host)
    target = f"tls://{host}:{port}"

    try:
        ctx = _build_context()
        obs = _handshake(host, port, timeout, ctx, server_name)
    except ssl.SSLError as exc:
        return [], [f"{target}: TLS handshake failed: {exc}"]
    except socket.timeout:
        return [], [f"{target}: timed out after {timeout}s"]
    except OSError as exc:
        return [], [f"{target}: connection failed: {exc}"]
    except Exception as exc:  # last resort - this module must never raise
        return [], [f"{target}: unexpected failure: {type(exc).__name__}: {exc}"]

    version = obs.get("version") or "unknown"
    cipher_tuple = obs.get("cipher") or (None, None, None)
    suite_name = cipher_tuple[0] or ""
    secret_bits = cipher_tuple[2]
    group = obs.get("group")
    alpn = obs.get("alpn")
    der = obs.get("der")
    suite = parse_cipher_suite(suite_name)

    # ---- PQC / hybrid posture ------------------------------------------- #
    pqc_group = False
    pqc_measured = True
    group_source = "runtime"
    group_confidence = "high"
    if group and _is_pqc(group):
        pqc_group = True
    elif _is_pqc(suite_name):
        pqc_group = True
        group_source = "cipher-suite name"
    elif group is None:
        group_source = "unavailable"
        pqc_measured = False

    probe_attempted = False
    if probe_pqc and not pqc_group and group is None:
        # Only meaningful where the runtime can pin groups; skipped otherwise,
        # so the default costs no extra connection on current CPython builds.
        try:
            probe_ctx = _build_context(permissive=False)
            if _try_set_groups(probe_ctx, PQC_GROUPS):
                probe_attempted = True
                probe_obs = _handshake(host, port, timeout, probe_ctx, server_name)
                probe_group = probe_obs.get("group") or ""
                if probe_group and not _is_pqc(probe_group):
                    # The server completed the handshake on a classical group;
                    # that is not evidence of PQC support.
                    group = probe_group
                    group_source = "pinned-group probe"
                    pqc_measured = True
                else:
                    pqc_group = True
                    pqc_measured = True
                    group_source = "pinned-group probe"
                    if probe_group:
                        group = probe_group
                    else:
                        group = "hybrid PQC group (negotiated; name not exposed)"
                        group_confidence = "medium"
        except Exception:
            # A refused hybrid handshake simply means "no PQC support".
            pass

    base_extra: dict[str, Any] = {
        "host": host,
        "port": port,
        "sni": server_name,
        "endpoint": f"{host}:{port}",
        "cipher_suite": suite_name,
        "secret_bits": secret_bits,
        "alpn": alpn,
        "group": group,
        "group_source": group_source,
        "pqc_group": pqc_group,
        "pqc_measured": pqc_measured,
        "pqc_probe_attempted": probe_attempted,
    }

    # ---- 1. protocol version --------------------------------------------- #
    proto_family = _PROTOCOL_FAMILY.get(version, version)
    proto_flags: list[str] = []
    if version in _LEGACY_PROTOCOLS:
        proto_flags.append(
            "DEPRECATED PROTOCOL: TLS 1.0/1.1 and SSL are prohibited by RFC 8996."
        )
    if obs.get("compression"):
        proto_flags.append(f"TLS compression active ({obs['compression']}): CRIME risk.")
    if not pqc_measured:
        proto_flags.append(
            "Negotiated key-exchange group not exposed by this Python/OpenSSL "
            "build, so hybrid-PQC support could not be measured."
        )
    evidence = f"negotiated {version} with {suite_name or 'unknown suite'}"
    if secret_bits:
        evidence += f" ({secret_bits}-bit)"
    if group:
        evidence += f", group {group}"
    if alpn:
        evidence += f", ALPN {alpn}"
    if proto_flags:
        evidence += " -- " + " ".join(proto_flags)

    artefacts.append(
        _mk(
            proto_family,
            proto_family,
            "protocol",
            host,
            port,
            evidence,
            extra={
                **base_extra,
                "role": "protocol_version",
                "deprecated": version in _LEGACY_PROTOCOLS,
                "compression": obs.get("compression"),
                "threat_hint": "legacy_broken" if version in _LEGACY_PROTOCOLS else "unknown",
            },
        )
    )

    # ---- 2. key exchange -------------------------------------------------- #
    kex = suite.get("kex")
    if kex:
        if pqc_group:
            kex_family = "ML-KEM"
            kex_name = group or "hybrid-PQC-KEX"
            kex_ev = (
                f"hybrid post-quantum key exchange {kex_name} negotiated on "
                f"{version}: this endpoint already resists harvest-now-decrypt-later"
            )
            kex_extra = {"pqc": True, "threat_hint": "pqc", "hybrid": True}
        elif kex in ("ECDHE", "EECDH", "ECDH", "AECDH"):
            kex_family = "ECDH"
            kex_name = f"ECDHE-{group}" if group else ("ECDH-static" if kex == "ECDH" else "ECDHE")
            kex_ev = f"{kex} key agreement on {version} (suite {suite_name})"
            kex_extra = {"threat_hint": "shor_broken", "static": kex == "ECDH"}
        elif kex in ("DHE", "EDH", "DH", "ADH"):
            kex_family = "DH"
            kex_name = "DHE" if kex in ("DHE", "EDH") else "DH-static"
            kex_ev = f"finite-field Diffie-Hellman key agreement on {version} (suite {suite_name})"
            kex_extra = {"threat_hint": "shor_broken", "static": kex in ("DH", "ADH")}
        elif kex == "RSA":
            kex_family = "RSA"
            kex_name = "RSA-key-transport"
            kex_ev = (
                f"static RSA key transport on {version} (suite {suite_name}) -- "
                "NO FORWARD SECRECY: every recorded session decrypts the moment "
                "the server's RSA key is recovered, so today's traffic is already "
                "exposed to harvest-now-decrypt-later"
            )
            kex_extra = {"threat_hint": "shor_broken", "forward_secrecy": False}
        else:
            kex_family = kex
            kex_name = kex
            kex_ev = f"{kex} key exchange on {version} (suite {suite_name})"
            kex_extra = {"threat_hint": "unknown"}

        if suite.get("anonymous"):
            kex_ev += " -- ANONYMOUS key exchange: the server is not authenticated."
        if suite.get("forward_secrecy") is False and kex != "RSA":
            kex_ev += " -- no forward secrecy."

        artefacts.append(
            _mk(
                kex_name,
                kex_family,
                "protocol",
                host,
                port,
                kex_ev,
                curve=group,
                extra={
                    **base_extra,
                    "role": "key_exchange",
                    "kex": kex,
                    "auth": suite.get("auth"),
                    "forward_secrecy": suite.get("forward_secrecy"),
                    "anonymous": suite.get("anonymous"),
                    **kex_extra,
                },
                confidence=group_confidence if pqc_group else "high",
            )
        )

    # ---- 3. bulk cipher --------------------------------------------------- #
    if suite.get("bulk_family"):
        family = suite["bulk_family"]
        bulk_flags: list[str] = []
        if family in _BROKEN_BULK:
            bulk_flags.append(_BROKEN_BULK[family])
        if not suite.get("aead") and family not in ("NULL", "RC4"):
            bulk_flags.append(
                "Non-AEAD construction (MAC-then-encrypt CBC): Lucky13/BEAST class exposure."
            )
        if family == "AES" and suite.get("bulk_bits") == 128:
            bulk_flags.append(
                "AES-128 retains ~64-bit strength against Grover; AES-256 is the "
                "NIST-recommended target for long-lived data."
            )
        bulk_ev = (
            f"bulk cipher {suite['bulk']} negotiated on {version} (suite {suite_name})"
        )
        if bulk_flags:
            bulk_ev += " -- " + " ".join(bulk_flags)
        artefacts.append(
            _mk(
                suite["bulk"] or family,
                family,
                "algorithm",
                host,
                port,
                bulk_ev,
                key_size=suite.get("bulk_bits"),
                mode=suite.get("mode"),
                extra={
                    **base_extra,
                    "role": "bulk_cipher",
                    "aead": suite.get("aead"),
                    "threat_hint": "legacy_broken" if family in _BROKEN_BULK else "grover_weakened",
                },
            )
        )

    # ---- 4. MAC / PRF hash ------------------------------------------------ #
    mac = suite.get("mac")
    if mac:
        mac_family = _hash_family(mac)
        role = "prf" if suite.get("tls13") or suite.get("aead") else "mac"
        mac_ev = (
            f"{mac} used as the {'PRF/HKDF hash' if role == 'prf' else 'record MAC'} "
            f"in suite {suite_name} on {version}"
        )
        if mac_family in ("SHA-1", "MD5") and role == "mac":
            mac_ev += " -- legacy MAC primitive; migrate to an AEAD suite."
        artefacts.append(
            _mk(
                mac,
                mac_family,
                "algorithm",
                host,
                port,
                mac_ev,
                key_size=_digest_bits(mac),
                extra={
                    **base_extra,
                    "role": role,
                    "variant": mac,
                    "digest_bits": _digest_bits(mac),
                    "threat_hint": "legacy_broken"
                    if (mac_family in ("SHA-1", "MD5") and role == "mac")
                    else "grover_weakened",
                },
            )
        )

    # ---- 5. served certificate -------------------------------------------- #
    if der:
        cert_arts, cert_errs = artefacts_from_certificate(
            der,
            file=f"tls://{host}:{port}",
            line=None,
            detector=DETECTOR,
            source_note=f"X.509 certificate served by {host}:{port}",
        )
        errors += cert_errs
        hostname_ok: Optional[bool] = None
        if _CRYPTO_OK:
            try:
                hostname_ok = _hostname_matches(_x509.load_der_x509_certificate(der), host)
            except Exception:
                hostname_ok = None
        for art in cert_arts:
            art.params.extra.update(
                {
                    "host": host,
                    "port": port,
                    "endpoint": f"{host}:{port}",
                    "served_over": version,
                    "hostname_match": hostname_ok,
                    "chain_verified": None,  # single unauthenticated probe by design
                }
            )
            if hostname_ok is False and art.occurrences:
                art.occurrences[0].evidence = _clip(
                    art.occurrences[0].evidence
                    + f" [HOSTNAME MISMATCH: no SAN/CN covers {host}]"
                )
        artefacts += cert_arts
    else:
        errors.append(f"{target}: handshake succeeded but no peer certificate was returned")

    return artefacts, errors


def scan_endpoints(
    targets: Iterable[str],
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    probe_pqc: bool = True,
) -> tuple[list[Artefact], list[str]]:
    """Scan several ``host``/``host:port`` targets sequentially."""
    artefacts: list[Artefact] = []
    errors: list[str] = []
    for target in targets:
        a, e = scan_endpoint(target, port, timeout, probe_pqc=probe_pqc)
        artefacts += a
        errors += e
    return artefacts, errors


def detect(
    root_path: str, policy: Any = None
) -> tuple[list[Artefact], int, list[str]]:
    """Mandated detector entry point (network probe, opt-in only).

    Unlike the filesystem detectors this one derives nothing from
    ``root_path``: a TLS endpoint is not discoverable from source, so targets
    come exclusively from the policy::

        tls:
          enabled: true          # optional, default true when endpoints exist
          timeout: 6.0           # optional
          probe_pqc: true        # optional
          endpoints:
            - scanme.example.gov.in
            - {host: api.example.in, port: 8443}

    With no ``tls.endpoints`` configured this returns ``([], 0, [])`` and makes
    no network connection at all, so a registry may call it unconditionally
    alongside the offline detectors.

    Returns ``(artefacts, endpoints_probed, errors)``; ``endpoints_probed``
    takes the place of ``files_scanned``.
    """
    artefacts: list[Artefact] = []
    try:
        targets, options, errors = _endpoints_from_policy(policy)
    except Exception as exc:
        return [], 0, [f"tls: policy endpoint configuration unreadable: {exc}"]

    if not targets:
        return [], 0, errors
    if not options.get("enabled", True):
        return [], 0, errors + [
            "tls: endpoints are configured but 'tls.enabled' is false; no probe run"
        ]

    probed = 0
    for target in targets:
        probed += 1
        try:
            found, errs = scan_endpoint(
                target,
                DEFAULT_PORT,
                options["timeout"],
                probe_pqc=options["probe_pqc"],
            )
        except Exception as exc:  # scan_endpoint is total; never trust that here
            errors.append(f"tls://{target}: probe raised: {type(exc).__name__}: {exc}")
            continue
        artefacts += found
        errors += errs

    return artefacts, probed, errors


__all__ = [
    "NAME",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "PQC_GROUPS",
    "detect",
    "scan_endpoint",
    "scan_endpoints",
    "parse_target",
    "parse_cipher_suite",
]
