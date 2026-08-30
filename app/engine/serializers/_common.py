"""Shared, dependency-free helpers for the ECDAT serializers.

Every serializer in this package must survive being handed either a real
:class:`app.engine.models.ScanResult` / :class:`Artefact` object *or* the plain
``dict`` produced by ``to_dict()`` (that is what the scan store round-trips).
The accessors below normalise both shapes, plus ``Enum`` values, so that no
serializer ever raises on a partially-populated artefact.

Severity ranking is **not** redefined here.  ``SEVERITY_RANK`` is imported
unconditionally from :mod:`app.engine.models`, which is the single source of
truth for the whole engine.  The documented direction is **critical == highest
weight**; ``SEVERITY_ORDER`` is derived from the table rather than hard-coded,
so adding a severity to the model propagates everywhere without edits here.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from enum import Enum
from typing import Any, Iterable

from ..models import SEVERITY_RANK

__all__ = [
    "TOOL_NAME",
    "TOOL_VENDOR",
    "TOOL_VERSION",
    "TOOL_URI",
    "SEVERITY_ORDER",
    "ENGINE_EXTRA_KEYS",
    "enum_value",
    "field",
    "name_of",
    "family_of",
    "artefacts_of",
    "params_of",
    "extra_of",
    "engine_extra",
    "occurrences_of",
    "severity_of",
    "threat_of",
    "score_of",
    "severity_weight",
    "rank_artefacts",
    "severity_counts",
    "iso8601",
    "slug",
    "stable_id",
    "posix_path",
    "relative_path",
    "trade_offs_of",
    "artefact_key",
    "display_params",
]

TOOL_NAME = "ECDAT"
TOOL_VENDOR = "ECDAT Project"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/ecdat/ecdat"


def enum_value(value: Any) -> Any:
    """Return ``value.value`` for Enums, ``value`` otherwise."""
    if isinstance(value, Enum):
        return value.value
    return value


def _severity_table() -> dict[str, int]:
    """Normalise ``models.SEVERITY_RANK`` keys (Enum or str) to lower-case names."""
    table: dict[str, int] = {}
    for raw_key, raw_weight in SEVERITY_RANK.items():
        name = enum_value(raw_key)
        if not isinstance(name, str):
            continue
        try:
            table[name.strip().lower()] = int(raw_weight)
        except (TypeError, ValueError):
            continue
    return table


#: Canonical severity -> weight map.  Critical is the highest weight.
_SEVERITY_WEIGHT: dict[str, int] = _severity_table()

#: Worst-first ordering used for every ranked view we emit, derived from the
#: shared table so there is exactly one place that defines severity order.
SEVERITY_ORDER: tuple[str, ...] = tuple(
    sorted(_SEVERITY_WEIGHT, key=lambda name: (-_SEVERITY_WEIGHT[name], name))
)

#: Name of the lowest-ranked severity; used when a value cannot be resolved.
_LOWEST_SEVERITY: str = SEVERITY_ORDER[-1] if SEVERITY_ORDER else "none"

#: Keys the engine stamps into ``params.extra`` for its own bookkeeping.  They
#: are real data (and are surfaced deliberately by the CBOM and the report), but
#: they are not cryptographic *parameters*, so ``display_params`` hides them.
ENGINE_EXTRA_KEYS = frozenset(
    {
        "z_year",
        "mosca_deadline_year",
        "mosca_statement",
        "policy_rule",
        "policy_name",
        "kb_citation",
        "threat_hint",
        "classical_findings",
        "crypto_functions",
        "execution_environment",
        "implementation_platform",
        "certification_level",
        "signature_algorithm_ref",
        "subject_public_key_ref",
        "notes",
        "advisory",
    }
)


def field(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` off a dataclass instance or a mapping, tolerating either."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        value = obj.get(name, default)
    else:
        value = getattr(obj, name, default)
    if value is None:
        return default
    return value


def name_of(artefact: Any, default: str = "unknown") -> str:
    """Display name, never blank - detectors occasionally hand us an empty name."""
    text = str(field(artefact, "name", "") or "").strip()
    return text or default


def family_of(artefact: Any, default: str = "unknown") -> str:
    text = str(field(artefact, "family", "") or "").strip()
    return text or default


def artefacts_of(scan_result: Any) -> list[Any]:
    value = field(scan_result, "artefacts", []) or []
    return list(value)


def params_of(artefact: Any) -> Any:
    return field(artefact, "params", {}) or {}


def extra_of(artefact: Any) -> dict[str, Any]:
    """``params.extra`` as a plain dict, never ``None``."""
    raw = field(params_of(artefact), "extra", {}) or {}
    return raw if isinstance(raw, dict) else {}


def engine_extra(artefact: Any, name: str, default: Any = None) -> Any:
    """Read a value the risk engine stamped into ``params.extra``.

    Falls back to a same-named attribute on the artefact so that a build which
    carries these as real model fields keeps working unchanged.
    """
    value = extra_of(artefact).get(name)
    if value not in (None, ""):
        return value
    value = field(artefact, name, None)
    if value not in (None, ""):
        return value
    return default


def occurrences_of(artefact: Any) -> list[Any]:
    value = field(artefact, "occurrences", []) or []
    return list(value)


def severity_of(artefact: Any) -> str:
    raw = enum_value(field(artefact, "severity", _LOWEST_SEVERITY))
    text = str(raw or _LOWEST_SEVERITY).strip().lower()
    return text if text in _SEVERITY_WEIGHT else _LOWEST_SEVERITY


def threat_of(artefact: Any) -> str:
    raw = enum_value(field(artefact, "threat", "unknown"))
    return str(raw or "unknown").strip().lower()


def score_of(artefact: Any) -> float:
    try:
        return float(field(artefact, "score", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def severity_weight(severity: Any) -> int:
    text = str(enum_value(severity) or _LOWEST_SEVERITY).strip().lower()
    return _SEVERITY_WEIGHT.get(text, 0)


def rank_artefacts(artefacts: Iterable[Any]) -> list[Any]:
    """Worst first: severity, then score, then occurrence count, then name."""
    return sorted(
        artefacts,
        key=lambda a: (
            -severity_weight(severity_of(a)),
            -score_of(a),
            -len(occurrences_of(a)),
            name_of(a).lower(),
        ),
    )


def severity_counts(artefacts: Iterable[Any]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for artefact in artefacts:
        name = severity_of(artefact)
        counts[name] = counts.get(name, 0) + 1
    return counts


def iso8601(value: Any = None) -> str:
    """Best-effort RFC3339/ISO-8601 UTC timestamp string."""
    if value is None:
        value = _dt.datetime.now(_dt.timezone.utc)
    if isinstance(value, _dt.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
        return moment.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, (int, float)):
        moment = _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value).strip()
    if not text:
        return iso8601(_dt.datetime.now(_dt.timezone.utc))
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return iso8601(parsed)


_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


def slug(text: Any, default: str = "asset") -> str:
    cleaned = _SLUG_RE.sub("-", str(text or "")).strip("-").lower()
    return cleaned or default


def stable_id(*parts: Any) -> str:
    """Deterministic short digest, used for bom-refs and SARIF fingerprints."""
    joined = "␟".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:16]


def posix_path(path: Any) -> str:
    return str(path or "").replace("\\", "/")


def relative_path(path: Any, root: Any) -> str:
    """Strip ``root`` off ``path`` when it is a prefix; never raises.

    Detectors are required to emit root-relative POSIX paths already; network
    artefacts keep their explicit scheme (``tls://host:port``) and are returned
    untouched.
    """
    text = posix_path(path)
    if "://" in text:
        return text
    base = posix_path(root).rstrip("/")
    if base and text.startswith(base + "/"):
        return text[len(base) + 1 :]
    if base and text == base:
        return text.rsplit("/", 1)[-1] or text
    return text


def trade_offs_of(artefact: Any) -> dict[str, str]:
    raw = field(artefact, "trade_offs", {}) or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, (list, tuple)):
        return {f"note {i + 1}": str(v) for i, v in enumerate(raw)}
    return {"note": str(raw)}


def artefact_key(artefact: Any) -> str:
    """``Artefact.key()`` when available, otherwise rebuild the same shape."""
    getter = getattr(artefact, "key", None)
    if callable(getter):
        try:
            value = getter()
            if value:
                return str(value)
        except Exception:
            pass
    if isinstance(artefact, dict) and artefact.get("key"):
        return str(artefact["key"])
    params = params_of(artefact)
    parts = [str(field(artefact, "family", "") or "")]
    for name in ("key_size", "curve", "mode"):
        parts.append(str(field(params, name, None)))
    return "|".join(parts)


def display_params(artefact: Any) -> str:
    """Human summary of the extracted parameters, e.g. ``key_size=2048, mode=CBC``.

    Engine bookkeeping stamped into ``params.extra`` (Mosca statement, policy
    rule, KB citation ...) is deliberately excluded - it is reported in its own
    sections rather than masquerading as a cryptographic parameter.
    """
    params = params_of(artefact)
    bits: list[str] = []
    for name in ("key_size", "curve", "mode", "padding", "not_after"):
        value = field(params, name, None)
        if value not in (None, "", []):
            bits.append(f"{name}={value}")
    for name, value in sorted(extra_of(artefact).items()):
        if name in ENGINE_EXTRA_KEYS:
            continue
        if value not in (None, "", [], {}):
            bits.append(f"{name}={value}")
    return ", ".join(bits)
