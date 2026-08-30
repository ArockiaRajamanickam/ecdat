"""
ECDAT policy engine.

Loads the risk / migration policy that drives Mosca's inequality (X + Y > Z),
data-class assignment, business-criticality weighting, path filtering and the
CI gate.

This module is the **single source of truth for path matching and for gate
decisions**.  Other modules must not reimplement either:

    * glob matching        -> :func:`glob_match` / :func:`compile_glob`
    * ignore filtering     -> :meth:`Policy.is_ignored`
    * severity ordering    -> :data:`SEVERITY_RANK` (imported from
                              ``app.engine.models``) and :func:`severity_rank`
    * the CI gate verdict  -> :meth:`Policy.gate_should_fail`

Severity ordering is defined once, in ``app/engine/models.py``.  The contract is
**critical == highest**: a larger rank means a worse finding.  There is no local
mirror of the table and no direction guard anywhere in this package; if the
model's ordering ever changes, it changes in exactly one place.

The policy may be written as JSON *or* as the small YAML subset used by
``default_policy.yaml``.  PyYAML is optional: if it is installed it is used,
otherwise a self-contained parser in this module handles the subset

    * nested maps by 2-space indentation      ``mosca:\n  Z_quantum_threat_year: 2035``
    * inline / flow maps                      ``pii: { X_protection_lifetime: 25 }``
    * inline / flow sequences                 ``langs: [python, java]``
    * block sequences                         ``ignore_paths:\n  - "**/dist/**"``
    * single- or double-quoted keys           ``"**/payments/**": 1.0``
    * ``#`` comments, blank lines, ``---`` document markers

Glob semantics (path aware, unlike bare :func:`fnmatch.fnmatch`)::

    *              any run of characters except "/"
    ?              one character except "/"
    [abc] [!abc]   character class / negated class
    **/            zero or more leading directories   ("**/x/**" matches "x/b.py")
    /**            this path or anything under it     ("src/**"  matches "src")
    no "/" at all  matches that name at any depth      ("*.pem")

Rule ordering is preserved from the file and matching is **last match wins**,
so a policy reads top-to-bottom: broad defaults first, sharp overrides last.

Public API
----------
``Policy.load(path | None) -> Policy``   (``None`` = built-in defaults)
``.data_class_for(path) -> str``
``.x_for(path, data_class=None) -> int``
``.y_default() -> int``   ``.y_for_family(family) -> int``
``.z_year() -> int``
``.criticality_for(path) -> float``
``.is_ignored(path) -> bool``
``.mosca(path, ...) -> dict``
``.fail_on() -> str``   ``.min_report_severity() -> str``
``.fail_on_mosca_act_now() -> bool``   ``.fail_on_scan_errors() -> bool``
``.gate_should_fail(severity, mosca_act_now=False) -> bool``
``.tls_endpoints() -> list[dict]``   ``.probe_timeout() -> float``
``.rule_counts() -> dict``   ``.to_dict() -> dict``

Run ``python -m app.engine.policy`` to execute the built-in self-test.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

# --- shared model: severity ordering lives in models.py and nowhere else -----
if __package__ in (None, ""):  # pragma: no cover - `python app/engine/policy.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from app.engine.models import SEVERITY_RANK
else:
    from .models import SEVERITY_RANK

__all__ = [
    "Policy",
    "PolicyError",
    "GlobRule",
    "compile_glob",
    "glob_match",
    "normalise_path",
    "parse_yaml",
    "severity_rank",
    "SEVERITY_RANK",
    "BUILTIN_DEFAULTS",
    "DEFAULT_POLICY_FILENAME",
]

DEFAULT_POLICY_FILENAME = "default_policy.yaml"


class PolicyError(ValueError):
    """Raised when a policy file cannot be parsed or is structurally invalid."""


# ---------------------------------------------------------------------------
# Severity ranking — one table, imported from the shared model.
# ---------------------------------------------------------------------------

#: ``{"critical": 4, "high": 3, ...}`` — the shared table keyed by lowercase
#: name so both ``Severity.HIGH`` and the string ``"high"`` resolve identically.
_RANK_BY_NAME: dict[str, int] = {
    str(getattr(_k, "value", _k)).lower(): int(_v) for _k, _v in SEVERITY_RANK.items()
}
_MAX_RANK: int = max(_RANK_BY_NAME.values()) if _RANK_BY_NAME else 4
_MIN_RANK: int = min(_RANK_BY_NAME.values()) if _RANK_BY_NAME else 0


def severity_rank(severity: Any) -> int:
    """Rank of ``severity`` (``Severity`` member or name). Higher == worse."""
    name = str(getattr(severity, "value", severity) or "none").strip().lower()
    return _RANK_BY_NAME.get(name, _MIN_RANK)


def _is_known_severity(name: str) -> bool:
    return name in _RANK_BY_NAME


# ---------------------------------------------------------------------------
# Path + glob machinery
# ---------------------------------------------------------------------------


def normalise_path(path: str | os.PathLike[str]) -> str:
    """Normalise a path for glob matching: forward slashes, no './', no drive."""
    p = str(path).replace("\\", "/").strip()
    if len(p) >= 2 and p[1] == ":" and p[0].isalpha():  # windows drive letter
        p = p[2:]
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.rstrip("/") if len(p) > 1 else p


def _class_to_regex(pat: str, i: int) -> tuple[str, int]:
    """Translate a ``[...]`` character class starting at ``pat[i] == '['``."""
    n = len(pat)
    j = i + 1
    negate = False
    if j < n and pat[j] in "!^":
        negate = True
        j += 1
    body_start = j
    if j < n and pat[j] == "]":  # literal ']' as first member
        j += 1
    while j < n and pat[j] != "]":
        j += 1
    if j >= n:  # unterminated class -> treat '[' literally
        return re.escape("["), i + 1
    body = pat[body_start:j].replace("\\", "\\\\")
    return ("[" + ("^" if negate else "") + body + "]"), j + 1


def _glob_to_regex(pattern: str) -> str:
    """Translate a path glob into an anchored regular expression."""
    pat = normalise_path(pattern)
    if pat == "":
        return r"\A\Z"
    match_any_depth = "/" not in pat
    out: list[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            j = i
            while j < n and pat[j] == "*":
                j += 1
            double = (j - i) >= 2
            if double and j < n and pat[j] == "/":
                out.append(r"(?:[^/]+/)*")  # "**/"  -> zero or more directories
                i = j + 1
            elif double and j >= n:
                if out and out[-1] == "/":  # ".../**" -> self or anything below
                    out.pop()
                    out.append(r"(?:/.*)?")
                else:
                    out.append(r".*")
                i = j
            elif double:
                out.append(r".*")
                i = j
            else:
                out.append(r"[^/]*")
                i = j
        elif c == "?":
            out.append(r"[^/]")
            i += 1
        elif c == "[":
            frag, i = _class_to_regex(pat, i)
            out.append(frag)
        elif c == "/":
            out.append("/")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    if match_any_depth:
        body = r"(?:[^/]+/)*" + body
    return r"\A" + body + r"\Z"


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}
_GLOB_CACHE_MAX = 4096


def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile (and memoise) a path glob into a regex."""
    rx = _GLOB_CACHE.get(pattern)
    if rx is None:
        rx = re.compile(_glob_to_regex(pattern))
        if len(_GLOB_CACHE) >= _GLOB_CACHE_MAX:  # pragma: no cover - huge policies
            _GLOB_CACHE.clear()
        _GLOB_CACHE[pattern] = rx
    return rx


def glob_match(pattern: str, path: str | os.PathLike[str]) -> bool:
    """True when ``path`` matches the path glob ``pattern``.

    This is the one glob implementation in ECDAT.  Detectors, the risk engine,
    the gate and the serializers must all route through it (or through
    :meth:`Policy.is_ignored`) rather than using :mod:`fnmatch`, whose patterns
    are not path aware.
    """
    return compile_glob(pattern).match(normalise_path(path)) is not None


@dataclass(frozen=True)
class GlobRule:
    """One ``glob -> value`` policy rule, keeping its position in the file."""

    pattern: str
    value: Any
    order: int = 0
    source: str = ""

    def matches(self, normalised_path: str) -> bool:
        return compile_glob(self.pattern).match(normalised_path) is not None


class _RuleSet:
    """Ordered glob rules resolved last-match-wins."""

    __slots__ = ("rules", "default", "_cache")

    def __init__(self, rules: Sequence[GlobRule], default: Any) -> None:
        self.rules: list[GlobRule] = list(rules)
        self.default = default
        self._cache: dict[str, tuple[Any, str | None]] = {}

    def resolve(self, path: str) -> tuple[Any, str | None]:
        p = normalise_path(path)
        hit = self._cache.get(p)
        if hit is not None:
            return hit
        value, pattern = self.default, None
        for rule in self.rules:  # last match wins
            if rule.matches(p):
                value, pattern = rule.value, rule.pattern
        result = (value, pattern)
        if len(self._cache) < 20000:
            self._cache[p] = result
        return result

    def any_match(self, path: str) -> bool:
        p = normalise_path(path)
        return any(r.matches(p) for r in self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[GlobRule]:
        return iter(self.rules)


# ---------------------------------------------------------------------------
# Minimal, dependency-free YAML subset parser
# ---------------------------------------------------------------------------

_TRUE = {"true", "yes", "on"}
_FALSE = {"false", "no", "off"}
_NULL = {"", "null", "~", "none"}


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment that is not inside quotes."""
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                out.append(ch)
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
        else:
            if ch in "\"'":
                quote = ch
                out.append(ch)
            elif ch == "#":
                if not out or out[-1] in " \t":
                    break
                out.append(ch)
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _unquote(text: str) -> str:
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        body = t[1:-1]
        if t[0] == '"':
            body = (
                body.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )
        else:
            body = body.replace("''", "'")
        return body
    return t


def _is_quoted(text: str) -> bool:
    t = text.strip()
    return len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'"


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on ``sep`` ignoring separators inside quotes/brackets/braces."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def _split_key_value(text: str) -> tuple[str, str] | None:
    """Split ``key: value`` at the first structural colon; None if there is none."""
    quote: str | None = None
    depth = 0
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            if i + 1 >= n or text[i + 1] in " \t":
                return text[:i].strip(), text[i + 1 :].strip()
        i += 1
    return None


def _parse_scalar(text: str) -> Any:
    t = text.strip()
    if t.startswith("{") and t.endswith("}"):
        return _parse_flow_map(t)
    if t.startswith("[") and t.endswith("]"):
        return _parse_flow_seq(t)
    if _is_quoted(t):
        return _unquote(t)
    low = t.lower()
    if low in _NULL:
        return None
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    try:
        if re.fullmatch(r"[+-]?\d+", t):
            return int(t)
        if re.fullmatch(r"[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?", t):
            return float(t)
    except ValueError:  # pragma: no cover - regex already guards this
        pass
    return t


def _parse_flow_map(text: str) -> dict[str, Any]:
    inner = text.strip()[1:-1].strip()
    result: dict[str, Any] = {}
    if not inner:
        return result
    for item in _split_top_level(inner):
        if not item:
            continue
        kv = _split_key_value(item)
        if kv is None:
            if ":" in item:
                k, _, v = item.partition(":")
                result[_unquote(k)] = _parse_scalar(v)
            else:
                result[_unquote(item)] = None
            continue
        key, value = kv
        result[_unquote(key)] = _parse_scalar(value)
    return result


def _parse_flow_seq(text: str) -> list[Any]:
    inner = text.strip()[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(item) for item in _split_top_level(inner) if item != ""]


@dataclass
class _Frame:
    indent: int
    container: Any = None          # dict | list | None (undecided)
    parent: Any = None             # dict | list holding this container
    key: str | None = None


def _close_frame(frame: _Frame) -> None:
    """A key/item that never received children resolves to null."""
    if frame.container is None:
        if isinstance(frame.parent, dict) and frame.key is not None:
            frame.parent.setdefault(frame.key, None)
        elif isinstance(frame.parent, list):
            frame.parent.append(None)


def _parse_yaml_subset(text: str) -> dict[str, Any]:
    """Parse the supported YAML subset into plain Python containers."""
    root: dict[str, Any] = {}
    stack: list[_Frame] = [_Frame(indent=-1, container=root)]

    raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for lineno, raw in enumerate(raw_lines, start=1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raw = raw.replace("\t", "  ")
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        content = stripped.strip()
        if content in ("---", "..."):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        is_item = content == "-" or content.startswith("- ")

        while len(stack) > 1 and indent <= stack[-1].indent:
            top = stack[-1]
            if (
                is_item
                and indent == top.indent
                and (top.container is None or isinstance(top.container, list))
            ):
                break
            _close_frame(stack.pop())

        frame = stack[-1]
        if frame.container is None:
            frame.container = [] if is_item else {}
            if isinstance(frame.parent, dict):
                frame.parent[frame.key] = frame.container
            elif isinstance(frame.parent, list):
                frame.parent.append(frame.container)
        container = frame.container

        if is_item:
            if not isinstance(container, list):
                raise PolicyError(
                    f"line {lineno}: sequence item inside a mapping: {content!r}"
                )
            body = content[1:].strip()
            if body == "":
                stack.append(_Frame(indent=indent, container=None, parent=container, key=None))
                continue
            kv = _split_key_value(body)
            if kv is not None and not _is_quoted(body):
                item_map: dict[str, Any] = {}
                container.append(item_map)
                key, value = kv
                if value == "":
                    stack.append(_Frame(indent=indent, container=item_map))
                    stack.append(
                        _Frame(indent=indent + 1, container=None, parent=item_map, key=_unquote(key))
                    )
                else:
                    item_map[_unquote(key)] = _parse_scalar(value)
                    stack.append(_Frame(indent=indent, container=item_map))
            else:
                container.append(_parse_scalar(body))
            continue

        if not isinstance(container, dict):
            raise PolicyError(f"line {lineno}: mapping key inside a sequence: {content!r}")

        kv = _split_key_value(content)
        if kv is None:
            raise PolicyError(f"line {lineno}: expected 'key: value', got {content!r}")
        key, value = kv
        key = _unquote(key)
        if value == "":
            stack.append(_Frame(indent=indent, container=None, parent=container, key=key))
        else:
            container[key] = _parse_scalar(value)

    while len(stack) > 1:
        _close_frame(stack.pop())
    return root


def parse_yaml(text: str) -> dict[str, Any]:
    """Parse YAML text, preferring PyYAML when it is installed."""
    try:  # optional dependency, never required
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise PolicyError("policy document must be a mapping at the top level")
        return loaded
    except PolicyError:
        raise
    except ImportError:
        pass
    except Exception:
        # PyYAML present but unhappy with the document; fall back to our parser.
        pass
    return _parse_yaml_subset(text)


def _loads_any(text: str, *, hint: str = "") -> dict[str, Any]:
    """Load a policy document that may be JSON or the YAML subset."""
    probe = "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ).lstrip()
    looks_json = hint.lower().endswith(".json") or probe.startswith("{")
    if looks_json:
        try:
            loaded = json.loads(text)
            if not isinstance(loaded, dict):
                raise PolicyError("policy JSON must be an object at the top level")
            return loaded
        except json.JSONDecodeError:
            if hint.lower().endswith(".json"):
                raise PolicyError(f"invalid JSON policy: {hint or '<string>'}") from None
    return parse_yaml(text)


# ---------------------------------------------------------------------------
# Built-in defaults (mirror of default_policy.yaml; used if the file is absent)
# ---------------------------------------------------------------------------

BUILTIN_DEFAULTS: dict[str, Any] = {
    "version": 1,
    "name": "ECDAT baseline policy (built-in)",
    "description": "Conservative harvest-now-decrypt-later posture.",
    "inherit_defaults": True,
    "mosca": {"Z_quantum_threat_year": 2035, "default_X_protection_years": 10},
    "migration": {
        "default_Y_years": 3,
        "Y_by_family": {
            "RSA": 3,
            "ECDSA": 3,
            "ECDH": 3,
            "DH": 3,
            "AES": 1,
            "SHA-2": 1,
            "TLS": 2,
        },
    },
    "data_classes": {
        "classified": {"X_protection_lifetime": 40},
        "health": {"X_protection_lifetime": 30},
        "pii": {"X_protection_lifetime": 25},
        "financial": {"X_protection_lifetime": 15},
        "credential": {"X_protection_lifetime": 12},
        "default": {"X_protection_lifetime": 10},
        "internal": {"X_protection_lifetime": 5},
        "session_key": {"X_protection_lifetime": 1},
        "public": {"X_protection_lifetime": 0},
    },
    "data_class_paths": {
        "**": "default",
        "**/session/**": "session_key",
        "**/sessions/**": "session_key",
        "**/cache/**": "session_key",
        "**/ephemeral/**": "session_key",
        "**/tmp/**": "session_key",
        "**/public/**": "public",
        "**/static/**": "public",
        "**/assets/**": "public",
        "**/docs/**": "public",
        "**/examples/**": "public",
        "**/internal/**": "internal",
        "**/telemetry/**": "internal",
        "**/metrics/**": "internal",
        "**/payment/**": "financial",
        "**/payments/**": "financial",
        "**/billing/**": "financial",
        "**/ledger/**": "financial",
        "**/txn/**": "financial",
        "**/transactions/**": "financial",
        "**/upi/**": "financial",
        "**/settlement/**": "financial",
        "**/user/**": "pii",
        "**/users/**": "pii",
        "**/customer/**": "pii",
        "**/customers/**": "pii",
        "**/profile/**": "pii",
        "**/kyc/**": "pii",
        "**/aadhaar/**": "pii",
        "**/pan/**": "pii",
        "**/biometric/**": "pii",
        "**/subscriber/**": "pii",
        "**/health/**": "health",
        "**/medical/**": "health",
        "**/patient/**": "health",
        "**/ehr/**": "health",
        "**/auth/**": "credential",
        "**/identity/**": "credential",
        "**/secrets/**": "credential",
        "**/vault/**": "credential",
        "**/keystore/**": "credential",
        "**/keys/**": "credential",
        "*.pem": "credential",
        "*.key": "credential",
        "*.p12": "credential",
        "*.pfx": "credential",
        "*.jks": "credential",
        "**/classified/**": "classified",
        "**/restricted/**": "classified",
        "**/defence/**": "classified",
        "**/sigint/**": "classified",
    },
    "business_criticality": {
        "**": 0.3,
        "**/payment/**": 1.0,
        "**/payments/**": 1.0,
        "**/settlement/**": 1.0,
        "**/upi/**": 1.0,
        "**/billing/**": 0.95,
        "**/ledger/**": 0.95,
        "**/auth/**": 0.9,
        "**/login/**": 0.9,
        "**/identity/**": 0.9,
        "**/sso/**": 0.9,
        "**/session/**": 0.85,
        "**/crypto/**": 0.85,
        "**/security/**": 0.85,
        "**/kms/**": 0.85,
        "**/pki/**": 0.85,
        "**/tls/**": 0.8,
        "**/api/**": 0.7,
        "**/core/**": 0.7,
        "**/server/**": 0.7,
        "**/gateway/**": 0.7,
        "**/db/**": 0.6,
        "**/database/**": 0.6,
        "**/scripts/**": 0.2,
        "**/tools/**": 0.2,
        "**/test/**": 0.1,
        "**/tests/**": 0.1,
        "**/testdata/**": 0.1,
        "**/fixtures/**": 0.1,
        "**/mock/**": 0.1,
        "**/mocks/**": 0.1,
        "**/examples/**": 0.1,
        "**/sample/**": 0.1,
        "**/samples/**": 0.1,
        "**/docs/**": 0.05,
    },
    "gate": {
        "fail_on": "critical",
        "fail_on_mosca_act_now": False,
        "fail_on_scan_errors": False,
        "min_report_severity": "low",
    },
    "tls": {
        "timeout_seconds": 5.0,
        "endpoints": [],
    },
    "ignore_paths": [
        "**/.git/**",
        "**/.hg/**",
        "**/.svn/**",
        "**/node_modules/**",
        "**/bower_components/**",
        "**/vendor/**",
        "**/third_party/**",
        "**/site-packages/**",
        "**/dist-packages/**",
        "**/.venv/**",
        "**/venv/**",
        "**/env/**",
        "**/virtualenv/**",
        "**/__pycache__/**",
        "**/.mypy_cache/**",
        "**/.pytest_cache/**",
        "**/.ruff_cache/**",
        "**/.tox/**",
        "**/dist/**",
        "**/build/**",
        "**/out/**",
        "**/target/**",
        "**/coverage/**",
        "**/.next/**",
        "**/.nuxt/**",
        "**/.gradle/**",
        "**/.idea/**",
        "**/.DS_Store",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.lock",
        "*-lock.json",
    ],
}


def _deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Merge ``overlay`` onto ``base``; overlay map keys are appended in order."""
    out: dict[str, Any] = {}
    for k, v in base.items():
        out[k] = copy.deepcopy(v) if isinstance(v, (dict, list)) else v
    for k, v in overlay.items():
        cur = out.get(k)
        if isinstance(cur, dict) and isinstance(v, Mapping):
            out[k] = _deep_merge(cur, v)
        elif isinstance(cur, list) and isinstance(v, list):
            merged = list(cur)
            for item in v:
                if item not in merged:
                    merged.append(item)
            out[k] = merged
        else:
            out[k] = copy.deepcopy(v) if isinstance(v, (dict, list)) else v
    return out


def _as_int(value: Any, fallback: int) -> int:
    try:
        if isinstance(value, bool):
            return fallback
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _as_float(value: Any, fallback: float) -> float:
    try:
        if isinstance(value, bool):
            return fallback
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _as_bool(value: Any, fallback: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return fallback


def _rules_from_mapping(
    raw: Any, coerce, source: str, errors: list[str]
) -> list[GlobRule]:
    """Build ordered GlobRules from a ``glob -> value`` mapping (or list of maps)."""
    rules: list[GlobRule] = []
    items: list[tuple[str, Any]] = []
    if isinstance(raw, Mapping):
        items = [(str(k), v) for k, v in raw.items()]
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, Mapping):
                if "pattern" in entry or "glob" in entry:
                    pat = str(entry.get("pattern") or entry.get("glob"))
                    val = entry.get("value", entry.get("class", entry.get("criticality")))
                    items.append((pat, val))
                else:
                    items.extend((str(k), v) for k, v in entry.items())
    elif raw is not None:
        errors.append(f"{source}: expected a mapping of glob -> value, got {type(raw).__name__}")
    for order, (pattern, value) in enumerate(items):
        if not pattern:
            continue
        try:
            compile_glob(pattern)
        except re.error as exc:  # pragma: no cover - defensive
            errors.append(f"{source}: bad glob {pattern!r} ({exc})")
            continue
        rules.append(GlobRule(pattern=pattern, value=coerce(value), order=order, source=source))
    return rules


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    """An effective ECDAT policy: Mosca parameters, path rules and the CI gate."""

    data: dict[str, Any] = field(default_factory=dict)
    source: str = "<built-in defaults>"
    root: str | None = None
    errors: list[str] = field(default_factory=list)

    # resolved / compiled state (built in __post_init__)
    _z_year: int = field(default=2035, repr=False)
    _default_x: int = field(default=10, repr=False)
    _default_y: int = field(default=3, repr=False)
    _class_x: dict[str, int] = field(default_factory=dict, repr=False)
    _y_by_family: dict[str, int] = field(default_factory=dict, repr=False)
    _class_rules: _RuleSet = field(default=None, repr=False)  # type: ignore[assignment]
    _crit_rules: _RuleSet = field(default=None, repr=False)  # type: ignore[assignment]
    _ignore_rules: list[tuple[re.Pattern[str], re.Pattern[str]]] = field(
        default_factory=list, repr=False
    )
    _ignore_patterns: list[str] = field(default_factory=list, repr=False)

    # -- construction -------------------------------------------------------

    def __post_init__(self) -> None:
        self._rebuild()

    def _rebuild(self) -> None:
        d = self.data if isinstance(self.data, dict) else {}
        errors = self.errors

        raw_mosca = d.get("mosca")
        mosca = raw_mosca if isinstance(raw_mosca, Mapping) else {}
        if raw_mosca is not None and not isinstance(raw_mosca, Mapping):
            errors.append(
                "mosca: expected a mapping with Z_quantum_threat_year / "
                "default_X_protection_years; using built-in values"
            )
        self._z_year = _as_int(mosca.get("Z_quantum_threat_year"), 2035)
        self._default_x = _as_int(mosca.get("default_X_protection_years"), 10)

        raw_migration = d.get("migration")
        migration = raw_migration if isinstance(raw_migration, Mapping) else {}
        if raw_migration is not None and not isinstance(raw_migration, Mapping):
            errors.append(
                "migration: expected a mapping with default_Y_years / Y_by_family; "
                "using built-in values"
            )
        self._default_y = _as_int(migration.get("default_Y_years"), 3)
        y_fam = migration.get("Y_by_family")
        self._y_by_family = {}
        if isinstance(y_fam, Mapping):
            for fam, years in y_fam.items():
                self._y_by_family[str(fam).upper()] = _as_int(years, self._default_y)
        elif y_fam is not None:
            errors.append("migration.Y_by_family: expected a mapping of family -> years")

        # data classes -> X lifetime
        self._class_x = {}
        raw_classes = d.get("data_classes")
        if isinstance(raw_classes, Mapping):
            for name, spec in raw_classes.items():
                key = str(name)
                if isinstance(spec, Mapping):
                    val = spec.get("X_protection_lifetime", spec.get("x", spec.get("X")))
                    self._class_x[key] = _as_int(val, self._default_x)
                elif spec is None:
                    self._class_x[key] = self._default_x
                else:
                    self._class_x[key] = _as_int(spec, self._default_x)
        elif raw_classes is not None:
            errors.append("data_classes: expected a mapping of name -> {X_protection_lifetime}")
        self._class_x.setdefault("default", self._default_x)

        # glob rule sets
        self._class_rules = _RuleSet(
            _rules_from_mapping(
                d.get("data_class_paths"), lambda v: str(v) if v is not None else "default",
                "data_class_paths", errors,
            ),
            default="default",
        )
        self._crit_rules = _RuleSet(
            _rules_from_mapping(
                d.get("business_criticality"),
                lambda v: min(1.0, max(0.0, _as_float(v, 0.3))),
                "business_criticality",
                errors,
            ),
            default=self._fallback_criticality(d),
        )

        # a data_class_paths rule naming a class that does not exist would
        # otherwise silently fall back to "default" and quietly break Mosca.
        unknown = sorted(
            {str(r.value) for r in self._class_rules if str(r.value) not in self._class_x}
        )
        if unknown:
            errors.append(
                "data_class_paths: unknown data class(es) "
                + ", ".join(unknown)
                + "; those rules fall back to 'default' (declare them under data_classes)"
            )

        # ignore globs (also match "<pattern>/**" so "node_modules" ignores its tree)
        self._ignore_rules = []
        self._ignore_patterns = []
        raw_ignore = d.get("ignore_paths")
        patterns: list[str] = []
        if isinstance(raw_ignore, list):
            patterns = [str(p) for p in raw_ignore if p is not None and str(p).strip()]
        elif isinstance(raw_ignore, str):
            patterns = [p for p in (s.strip() for s in raw_ignore.split(",")) if p]
        elif isinstance(raw_ignore, Mapping):
            patterns = [str(k) for k in raw_ignore.keys()]
        elif raw_ignore is not None:
            errors.append("ignore_paths: expected a list of globs")
        for pat in patterns:
            try:
                direct = compile_glob(pat)
                subtree = compile_glob(pat.rstrip("/") + "/**")
            except re.error as exc:  # pragma: no cover - defensive
                errors.append(f"ignore_paths: bad glob {pat!r} ({exc})")
                continue
            self._ignore_rules.append((direct, subtree))
            self._ignore_patterns.append(pat)

        # gate keys are validated once, here, so a typo is not silently ignored
        raw_gate = d.get("gate")
        if raw_gate is not None and not isinstance(raw_gate, (Mapping, str)):
            errors.append("gate: expected a mapping of gate settings")
        elif isinstance(raw_gate, Mapping):
            for key in ("fail_on", "min_report_severity"):
                if key in raw_gate:
                    name = str(raw_gate[key] or "none").lower()
                    if not _is_known_severity(name):
                        errors.append(
                            f"gate.{key}: unknown severity {raw_gate[key]!r}; "
                            f"expected one of {', '.join(sorted(_RANK_BY_NAME))}"
                        )

    @staticmethod
    def _fallback_criticality(d: Mapping[str, Any]) -> float:
        raw = d.get("business_criticality")
        if isinstance(raw, Mapping):
            for key in ("default", "**", "*"):
                if key in raw:
                    return min(1.0, max(0.0, _as_float(raw[key], 0.3)))
        return 0.3

    # -- loading ------------------------------------------------------------

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str] | None = None,
        *,
        root: str | os.PathLike[str] | None = None,
        inherit_defaults: bool | None = None,
    ) -> "Policy":
        """Load a policy from ``path`` (YAML or JSON); ``None`` = built-in defaults.

        A user policy is deep-merged onto the defaults unless the document sets
        ``inherit_defaults: false`` (or the caller passes ``inherit_defaults=False``).
        Never raises for a missing default file — it falls back to
        :data:`BUILTIN_DEFAULTS`.
        """
        errors: list[str] = []
        defaults, default_src = cls._load_defaults(errors)

        if path is None:
            return cls(
                data=defaults,
                source=default_src,
                root=str(root) if root is not None else None,
                errors=errors,
            )

        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {p}: {exc}") from exc
        try:
            user = _loads_any(text, hint=str(p))
        except PolicyError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise PolicyError(f"cannot parse policy file {p}: {exc}") from exc
        if not isinstance(user, dict):
            raise PolicyError(f"policy file {p} must contain a mapping at the top level")

        inherit = user.get("inherit_defaults", True) if inherit_defaults is None else inherit_defaults
        data = _deep_merge(defaults, user) if inherit else dict(user)
        return cls(
            data=data,
            source=str(p),
            root=str(root) if root is not None else None,
            errors=errors,
        )

    @classmethod
    def loads(
        cls,
        text: str,
        *,
        fmt: str | None = None,
        source: str = "<string>",
        root: str | os.PathLike[str] | None = None,
        inherit_defaults: bool | None = None,
    ) -> "Policy":
        """Load a policy from an in-memory YAML/JSON document."""
        errors: list[str] = []
        defaults, _ = cls._load_defaults(errors)
        hint = f"x.{fmt}" if fmt else source
        user = _loads_any(text, hint=hint)
        inherit = user.get("inherit_defaults", True) if inherit_defaults is None else inherit_defaults
        data = _deep_merge(defaults, user) if inherit else dict(user)
        return cls(
            data=data,
            source=source,
            root=str(root) if root is not None else None,
            errors=errors,
        )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        source: str = "<dict>",
        root: str | os.PathLike[str] | None = None,
        inherit_defaults: bool = False,
    ) -> "Policy":
        """Build a policy directly from a mapping (round-trips :meth:`to_dict`)."""
        errors: list[str] = []
        payload = {k: v for k, v in data.items() if k not in ("_meta", "resolved")}
        if inherit_defaults:
            defaults, _ = cls._load_defaults(errors)
            merged = _deep_merge(defaults, payload)
        else:
            merged = _deep_merge({}, payload)
        return cls(
            data=merged,
            source=source,
            root=str(root) if root is not None else None,
            errors=errors,
        )

    @classmethod
    def default_policy_path(cls) -> Path:
        """Location of the bundled ``default_policy.yaml``."""
        return Path(__file__).resolve().with_name(DEFAULT_POLICY_FILENAME)

    @classmethod
    def _load_defaults(cls, errors: list[str]) -> tuple[dict[str, Any], str]:
        path = cls.default_policy_path()
        try:
            if path.is_file():
                loaded = _loads_any(
                    path.read_text(encoding="utf-8", errors="replace"), hint=str(path)
                )
                if isinstance(loaded, dict) and loaded:
                    return _deep_merge(BUILTIN_DEFAULTS, loaded), str(path)
                errors.append(f"{path}: empty or invalid default policy; using built-ins")
        except Exception as exc:
            errors.append(f"{path}: {exc}; using built-in defaults")
        return _deep_merge({}, BUILTIN_DEFAULTS), "<built-in defaults>"

    # -- path normalisation -------------------------------------------------

    def relative(self, path: str | os.PathLike[str]) -> str:
        """Normalise ``path`` and, when a scan root is set, make it root-relative.

        Every detector is required to record ``Occurrence.file`` as a POSIX path
        relative to the scan root, so this is normally a no-op; it exists so an
        absolute path handed in by a caller still resolves against the same rules.
        """
        p = normalise_path(path)
        if self.root:
            r = normalise_path(self.root)
            if r and (p == r or p.startswith(r + "/")):
                p = p[len(r) :].lstrip("/")
        return p

    # -- required API -------------------------------------------------------

    def z_year(self) -> int:
        """Z: the assumed arrival year of a cryptographically relevant quantum computer."""
        return self._z_year

    def y_default(self) -> int:
        """Y: default migration duration in years."""
        return self._default_y

    def y_for_family(self, family: str | None) -> int:
        """Y for a specific algorithm family, falling back to :meth:`y_default`."""
        if family:
            hit = self._y_by_family.get(str(family).upper())
            if hit is not None:
                return hit
        return self._default_y

    def data_class_for(self, path: str | os.PathLike[str]) -> str:
        """Data class of ``path`` (last matching glob wins; ``"default"`` if none)."""
        value, _ = self._class_rules.resolve(self.relative(path))
        name = str(value) if value else "default"
        return name if name in self._class_x else "default"

    def x_for_class(self, data_class: str | None) -> int:
        """X (confidentiality lifetime, years) for a named data class."""
        if data_class and data_class in self._class_x:
            return self._class_x[data_class]
        return self._class_x.get("default", self._default_x)

    def x_for(self, path: str | os.PathLike[str], data_class: str | None = None) -> int:
        """X for ``path``; an explicit ``data_class`` overrides the path rules."""
        cls_name = data_class if data_class else self.data_class_for(path)
        return self.x_for_class(cls_name)

    def criticality_for(self, path: str | os.PathLike[str]) -> float:
        """Business criticality of ``path`` in ``0.0 .. 1.0`` (last match wins)."""
        value, _ = self._crit_rules.resolve(self.relative(path))
        return min(1.0, max(0.0, _as_float(value, 0.3)))

    def is_ignored(self, path: str | os.PathLike[str]) -> bool:
        """True when ``path`` (or a directory above it) is excluded from scanning.

        Detectors must call this per candidate file *and* per directory while
        walking, instead of carrying their own exclusion lists.
        """
        p = self.relative(path)
        if not p:
            return False
        for direct, subtree in self._ignore_rules:
            if direct.match(p) or subtree.match(p):
                return True
        return False

    def ignore_patterns(self) -> list[str]:
        """The raw ignore globs, for callers that need to report them."""
        return list(self._ignore_patterns)

    def rule_counts(self) -> dict[str, int]:
        """How many rules actually compiled — lets callers detect an inert policy.

        A caller that resolves ``{"data_class_paths": 0, "business_criticality": 0}``
        is holding a policy that cannot influence scoring and should say so loudly
        rather than falling back to hardcoded defaults in silence.
        """
        return {
            "data_class_paths": len(self._class_rules),
            "business_criticality": len(self._crit_rules),
            "data_classes": len(self._class_x),
            "ignore_paths": len(self._ignore_rules),
            "Y_by_family": len(self._y_by_family),
        }

    def to_dict(self) -> dict[str, Any]:
        """The effective policy as plain data, plus a ``resolved`` summary block."""
        out = copy.deepcopy(self.data) if isinstance(self.data, dict) else {}
        out["_meta"] = {
            "source": self.source,
            "root": self.root,
            "errors": list(self.errors),
        }
        out["resolved"] = {
            "Z_quantum_threat_year": self._z_year,
            "default_X_protection_years": self._default_x,
            "default_Y_years": self._default_y,
            "Y_by_family": dict(self._y_by_family),
            "data_class_X": dict(self._class_x),
            "data_class_rules": len(self._class_rules),
            "business_criticality_rules": len(self._crit_rules),
            "ignore_patterns": list(self._ignore_patterns),
            "gate_fail_on": self.fail_on(),
            "gate_min_report_severity": self.min_report_severity(),
            "gate_fail_on_mosca_act_now": self.fail_on_mosca_act_now(),
            "gate_fail_on_scan_errors": self.fail_on_scan_errors(),
        }
        return out

    # -- convenience for the risk engine / CI gate --------------------------

    def matched_rules_for(self, path: str | os.PathLike[str]) -> dict[str, Any]:
        """Which globs decided this path — provenance for the report."""
        p = self.relative(path)
        cls_value, cls_pat = self._class_rules.resolve(p)
        crit_value, crit_pat = self._crit_rules.resolve(p)
        return {
            "path": p,
            "data_class": str(cls_value) if cls_value else "default",
            "data_class_rule": cls_pat,
            "criticality": min(1.0, max(0.0, _as_float(crit_value, 0.3))),
            "criticality_rule": crit_pat,
            "ignored": self.is_ignored(p),
        }

    def mosca(
        self,
        path: str | os.PathLike[str],
        *,
        data_class: str | None = None,
        family: str | None = None,
        x_years: int | None = None,
        y_years: int | None = None,
    ) -> dict[str, Any]:
        """Evaluate Mosca's inequality ``X + Y > Z`` for one path.

        Returns X, Y, Z, the shortfall in years (``X + Y - (Z - now)``) and the
        ``act_now`` verdict.
        """
        cls_name = data_class or self.data_class_for(path)
        x = self.x_for_class(cls_name) if x_years is None else int(x_years)
        y = self.y_for_family(family) if y_years is None else int(y_years)
        z = self._z_year
        now = _current_year()
        years_left = z - now
        shortfall = (x + y) - years_left
        return {
            "data_class": cls_name,
            "x_years": x,
            "y_years": y,
            "z_year": z,
            "current_year": now,
            "years_until_z": years_left,
            "act_now": shortfall > 0,
            "shortfall_years": shortfall,
            "criticality": self.criticality_for(path),
            "statement": (
                f"X={x}y + Y={y}y = {x + y}y vs {years_left}y until Z={z}"
                f" -> {'act now' if shortfall > 0 else 'within margin'}"
            ),
        }

    # -- gate ---------------------------------------------------------------
    # Every gate knob lives here. gate.py must not reimplement the threshold
    # comparison; it calls gate_should_fail() so the two cannot drift.

    def _gate(self) -> Mapping[str, Any]:
        gate = self.data.get("gate")
        return gate if isinstance(gate, Mapping) else {}

    def fail_on(self) -> str:
        """Severity at which the CI gate fails the build (``"none"`` disables it)."""
        gate = self.data.get("gate")
        value = "critical"
        if isinstance(gate, Mapping):
            value = str(gate.get("fail_on", "critical") or "none").lower()
        elif isinstance(gate, str):
            value = gate.lower()
        return value if _is_known_severity(value) else "critical"

    def min_report_severity(self) -> str:
        """Severity floor: findings below this are dropped from the gate decision."""
        value = str(self._gate().get("min_report_severity", "low") or "none").lower()
        return value if _is_known_severity(value) else "low"

    def fail_on_mosca_act_now(self) -> bool:
        """Whether an ``act_now`` Mosca verdict alone fails the gate."""
        return _as_bool(self._gate().get("fail_on_mosca_act_now"), False)

    def fail_on_scan_errors(self) -> bool:
        """Whether scan errors (unreadable files, probe failures) fail the gate."""
        return _as_bool(self._gate().get("fail_on_scan_errors"), False)

    def counts_for_gate(self, severity: Any) -> bool:
        """True when a finding of ``severity`` is at or above ``min_report_severity``."""
        return severity_rank(severity) >= severity_rank(self.min_report_severity())

    def gate_should_fail(self, severity: Any, *, mosca_act_now: bool = False) -> bool:
        """True when a finding of ``severity`` must fail the build.

        The single implementation of the gate verdict:

        1. findings below ``gate.min_report_severity`` are dropped entirely
           (they cannot fail the build even via ``fail_on_mosca_act_now``);
        2. a finding at or above ``gate.fail_on`` fails;
        3. otherwise ``gate.fail_on_mosca_act_now`` may still fail it.
        """
        if not self.counts_for_gate(severity):
            return False
        rank = severity_rank(severity)
        threshold = self.fail_on()
        if threshold != "none" and rank > _MIN_RANK and rank >= severity_rank(threshold):
            return True
        return bool(mosca_act_now and self.fail_on_mosca_act_now())

    # -- probes -------------------------------------------------------------

    def probe_timeout(self) -> float:
        """Socket timeout (seconds) for the TLS probe."""
        raw = self.data.get("tls")
        if isinstance(raw, Mapping):
            return max(0.1, _as_float(raw.get("timeout_seconds"), 5.0))
        return 5.0

    def tls_endpoints(self) -> list[dict[str, Any]]:
        """Endpoints for the TLS probe as ``[{'host', 'port', 'timeout'}, ...]``.

        Accepts ``"host:port"`` strings, bare hostnames (port 443) and mappings.
        Returns ``[]`` when nothing is configured, which is what the detector
        needs in order to report ``([], 0, [])`` instead of reaching the network.
        """
        raw = self.data.get("tls")
        if not isinstance(raw, Mapping):
            return []
        entries = raw.get("endpoints")
        if entries is None:
            return []
        if isinstance(entries, (str, Mapping)):
            entries = [entries]
        if not isinstance(entries, list):
            self.errors.append("tls.endpoints: expected a list of host:port entries")
            return []
        timeout = self.probe_timeout()
        out: list[dict[str, Any]] = []
        for entry in entries:
            host: str | None = None
            port = 443
            entry_timeout = timeout
            if isinstance(entry, Mapping):
                host = str(entry.get("host") or entry.get("hostname") or "").strip() or None
                port = _as_int(entry.get("port"), 443)
                entry_timeout = max(0.1, _as_float(entry.get("timeout"), timeout))
            elif entry is not None:
                text = str(entry).strip()
                if text.startswith("tls://"):
                    text = text[len("tls://") :]
                if not text:
                    continue
                if text.count(":") == 1:
                    head, _, tail = text.partition(":")
                    host = head.strip() or None
                    port = _as_int(tail, 443)
                else:
                    host = text
            if not host:
                self.errors.append(f"tls.endpoints: skipping entry without a host: {entry!r}")
                continue
            if not (0 < port < 65536):
                self.errors.append(f"tls.endpoints: skipping {host!r} with invalid port {port}")
                continue
            out.append({"host": host, "port": port, "timeout": entry_timeout})
        return out

    # -- misc ---------------------------------------------------------------

    def filter_paths(self, paths: Iterable[str | os.PathLike[str]]) -> list[str]:
        """Drop ignored paths from an iterable, preserving order."""
        return [self.relative(p) for p in paths if not self.is_ignored(p)]

    @property
    def name(self) -> str:
        return str(self.data.get("name") or "ECDAT policy")

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"<Policy {self.name!r} Z={self._z_year} X_default={self._default_x} "
            f"Y={self._default_y} classes={len(self._class_x)} "
            f"class_rules={len(self._class_rules)} crit_rules={len(self._crit_rules)} "
            f"ignores={len(self._ignore_rules)} src={self.source}>"
        )


def _current_year() -> int:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).year


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _self_test() -> int:
    import tempfile

    # ---- 0. severity ordering comes from the shared model ------------------
    assert severity_rank("critical") > severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low") > severity_rank("none")
    assert severity_rank("critical") == _MAX_RANK, "critical must be the highest rank"
    assert severity_rank("garbage") == severity_rank("none")
    try:
        from .models import Severity as _Sev  # type: ignore
    except ImportError:  # pragma: no cover - script execution
        from app.engine.models import Severity as _Sev  # type: ignore
    assert severity_rank(_Sev.CRITICAL) == severity_rank("critical"), "enum and name agree"

    # ---- 1. glob translation ------------------------------------------------
    assert glob_match("**/x/**", "a/x/b.py"), "**/x/** must match a/x/b.py"
    assert glob_match("**/x/**", "x/b.py"), "**/x/** must match x/b.py"
    assert glob_match("**/x/**", "a/b/x/c/d.py")
    assert glob_match("**/x/**", "x")
    assert not glob_match("**/x/**", "ax/b.py")
    assert not glob_match("**/x/**", "a/xy/b.py")
    assert not glob_match("**/x/**", "a/b.py")

    assert glob_match("src/**", "src")
    assert glob_match("src/**", "src/deep/mod.py")
    assert not glob_match("src/**", "lib/src/mod.py")

    assert glob_match("*.pem", "server.pem")
    assert glob_match("*.pem", "certs/prod/server.pem"), "bare name globs match at any depth"
    assert not glob_match("*.pem", "server.pem.bak")

    assert glob_match("**/*.java", "a/b/C.java")
    assert glob_match("**", "anything/at/all.py")
    assert glob_match("a/?/c.py", "a/b/c.py")
    assert not glob_match("a/?/c.py", "a/bb/c.py")
    assert glob_match("a/[bc]/d.py", "a/c/d.py")
    assert not glob_match("a/[!bc]/d.py", "a/c/d.py")
    assert glob_match("**/node_modules/**", "web/node_modules/left-pad/index.js")

    # the fnmatch approximations this replaces produced these false results:
    assert not glob_match("**/keys/**", "src/monkeys/a.py"), "no substring false positive"
    assert glob_match("**/node_modules/**", "node_modules/x.js"), "top-level tree matches too"

    # path normalisation
    assert glob_match("**/x/**", "./a/x/b.py")
    assert glob_match("**/x/**", "a\\x\\b.py")

    # ---- 2. YAML subset parser ---------------------------------------------
    sample = """
# comment line
version: 1
name: "test policy"   # trailing comment
mosca:
  Z_quantum_threat_year: 2030
  default_X_protection_years: 7
migration:
  default_Y_years: 4
  Y_by_family:
    RSA: 5
data_classes:
  pii: { X_protection_lifetime: 25 }
  session_key: { X_protection_lifetime: 1 }
data_class_paths:
  "**": default
  "**/kyc/**": pii
business_criticality:
  "**": 0.3
  "**/payments/**": 1.0
gate:
  fail_on: high
flags: [a, b, "c d"]
ignore_paths:
  - "**/dist/**"
  - "*.min.js"
"""
    parsed = _parse_yaml_subset(sample)
    assert parsed["version"] == 1
    assert parsed["name"] == "test policy"
    assert parsed["mosca"]["Z_quantum_threat_year"] == 2030
    assert parsed["migration"]["Y_by_family"]["RSA"] == 5
    assert parsed["data_classes"]["pii"]["X_protection_lifetime"] == 25
    assert list(parsed["data_class_paths"]) == ["**", "**/kyc/**"], "key order preserved"
    assert parsed["business_criticality"]["**/payments/**"] == 1.0
    assert parsed["flags"] == ["a", "b", "c d"]
    assert parsed["ignore_paths"] == ["**/dist/**", "*.min.js"]
    assert parsed["gate"]["fail_on"] == "high"

    # unindented block sequence, booleans and nulls
    parsed2 = _parse_yaml_subset(
        "ignore_paths:\n- a\n- b\nflag: true\nother: false\nnothing:\nnum: -2.5\n"
    )
    assert parsed2["ignore_paths"] == ["a", "b"]
    assert parsed2["flag"] is True and parsed2["other"] is False
    assert parsed2["nothing"] is None
    assert abs(parsed2["num"] + 2.5) < 1e-9

    # ---- 3. default policy loads -------------------------------------------
    pol = Policy.load(None)
    assert pol.z_year() == 2035, pol.z_year()
    assert pol.y_default() == 3
    assert pol.x_for_class("pii") == 25
    assert pol.x_for_class("financial") == 15
    assert pol.x_for_class("session_key") == 1
    assert pol.x_for_class("public") == 0
    assert pol.x_for_class("default") == 10
    assert pol.x_for_class("nonexistent-class") == 10
    assert pol.fail_on() == "critical"
    assert pol.min_report_severity() == "low"
    assert pol.fail_on_mosca_act_now() is False
    assert pol.fail_on_scan_errors() is False
    assert not pol.errors, pol.errors
    counts = pol.rule_counts()
    assert counts["data_class_paths"] > 30 and counts["business_criticality"] > 20, counts

    # ---- 4. glob resolution through the policy -----------------------------
    assert pol.data_class_for("src/payments/gateway.py") == "financial"
    assert pol.x_for("src/payments/gateway.py") == 15
    assert pol.data_class_for("api/kyc/verify.py") == "pii"
    assert pol.x_for("api/kyc/verify.py") == 25, "the headline Mosca input must be 25, not 5"
    assert pol.data_class_for("session/token.py") == "session_key"
    assert pol.x_for("session/token.py") == 1
    assert pol.data_class_for("public/index.html") == "public"
    assert pol.x_for("public/index.html") == 0
    assert pol.data_class_for("certs/prod/server.pem") == "credential"
    assert pol.data_class_for("misc/util.py") == "default"
    assert pol.x_for("misc/util.py") == 10

    assert abs(pol.criticality_for("src/payments/charge.py") - 1.0) < 1e-9
    assert abs(pol.criticality_for("src/auth/login.py") - 0.9) < 1e-9
    assert abs(pol.criticality_for("misc/util.py") - 0.3) < 1e-9
    assert abs(pol.criticality_for("tests/test_crypto.py") - 0.1) < 1e-9, (
        "later rule (tests) must beat the earlier crypto rule"
    )
    assert abs(pol.criticality_for("docs/design.md") - 0.05) < 1e-9

    assert pol.is_ignored("web/node_modules/left-pad/index.js")
    assert pol.is_ignored("node_modules/x/y.js")
    assert pol.is_ignored("node_modules"), "the directory itself is ignored, so walks can prune"
    assert pol.is_ignored("app/static/bundle.min.js")
    assert pol.is_ignored("build/out.o")
    assert not pol.is_ignored("src/crypto/rsa.py")

    # explicit data_class overrides the path rules
    assert pol.x_for("misc/util.py", data_class="classified") == 40

    # per-family Y
    assert pol.y_for_family("RSA") == 3
    assert pol.y_for_family("AES") == 1
    assert pol.y_for_family("UNKNOWN-FAMILY") == pol.y_default()

    # ---- 5. last-match-wins ordering ---------------------------------------
    ordered = Policy.loads(
        'inherit_defaults: false\n'
        'data_class_paths:\n'
        '  "**": default\n'
        '  "**/a/**": pii\n'
        '  "**/a/b/**": public\n'
        'data_classes:\n'
        '  default: { X_protection_lifetime: 10 }\n'
        '  pii: { X_protection_lifetime: 25 }\n'
        '  public: { X_protection_lifetime: 0 }\n',
        inherit_defaults=False,
    )
    assert ordered.data_class_for("a/x.py") == "pii"
    assert ordered.data_class_for("a/b/x.py") == "public", "last matching rule wins"
    assert ordered.x_for("a/b/x.py") == 0

    # ---- 6. user policy merges onto the defaults ---------------------------
    with tempfile.TemporaryDirectory() as tmp:
        yml = Path(tmp) / "site.yaml"
        yml.write_text(
            "mosca:\n"
            "  Z_quantum_threat_year: 2030\n"
            "data_classes:\n"
            "  pii: { X_protection_lifetime: 40 }\n"
            "data_class_paths:\n"
            '  "**/payments/**": pii\n'
            "business_criticality:\n"
            '  "**/tests/**": 0.9\n'
            "gate:\n"
            "  fail_on: high\n"
            "  fail_on_scan_errors: true\n"
            "tls:\n"
            "  endpoints:\n"
            '    - "npci.example.in:443"\n'
            "    - { host: uidai.example.in, port: 8443 }\n"
            "ignore_paths:\n"
            '  - "**/legacy/**"\n',
            encoding="utf-8",
        )
        merged = Policy.load(yml)
        assert merged.z_year() == 2030
        assert merged.x_for_class("pii") == 40
        assert merged.x_for_class("financial") == 15, "untouched defaults survive"
        assert merged.data_class_for("src/payments/x.py") == "pii", "user rule appended last"
        assert abs(merged.criticality_for("tests/t.py") - 0.9) < 1e-9
        assert merged.fail_on() == "high"
        assert merged.fail_on_scan_errors() is True
        assert merged.is_ignored("app/legacy/old.java")
        assert merged.is_ignored("node_modules/a.js"), "default ignores kept"
        eps = merged.tls_endpoints()
        assert eps == [
            {"host": "npci.example.in", "port": 443, "timeout": 5.0},
            {"host": "uidai.example.in", "port": 8443, "timeout": 5.0},
        ], eps

        jsn = Path(tmp) / "site.json"
        jsn.write_text(
            json.dumps(
                {
                    "mosca": {"Z_quantum_threat_year": 2029},
                    "business_criticality": {"**/edge/**": 0.77},
                    "gate": {"fail_on": "medium"},
                }
            ),
            encoding="utf-8",
        )
        jpol = Policy.load(jsn)
        assert jpol.z_year() == 2029
        assert abs(jpol.criticality_for("svc/edge/handler.go") - 0.77) < 1e-9
        assert jpol.fail_on() == "medium"

        # a root makes absolute paths root-relative before matching
        rooted = Policy.load(None, root=tmp)
        assert rooted.data_class_for(str(Path(tmp) / "payments" / "a.py")) == "financial"

        # malformed policy is a clean PolicyError, never a crash
        bad = Path(tmp) / "bad.json"
        bad.write_text("{not json at all", encoding="utf-8")
        try:
            Policy.load(bad)
        except PolicyError:
            pass
        else:  # pragma: no cover
            raise AssertionError("malformed JSON policy must raise PolicyError")

    # ---- 7. Mosca + gate ----------------------------------------------------
    verdict = pol.mosca("api/kyc/verify.py", family="RSA")
    assert verdict["x_years"] == 25 and verdict["y_years"] == 3
    assert verdict["z_year"] == 2035
    assert verdict["act_now"] is True, verdict
    assert "Z=2035" in verdict["statement"]
    calm = pol.mosca("public/index.html", family="AES")
    assert calm["x_years"] == 0 and calm["act_now"] is False, calm

    assert pol.gate_should_fail("critical") is True
    assert pol.gate_should_fail("high") is False, "default_policy.yaml says fail_on: critical"
    assert pol.gate_should_fail("none") is False
    assert pol.gate_should_fail(_Sev.CRITICAL) is True, "enum severities work too"

    lenient = Policy.loads("gate:\n  fail_on: none\n  fail_on_mosca_act_now: true\n")
    assert lenient.gate_should_fail("critical") is False
    assert lenient.gate_should_fail("low", mosca_act_now=True) is True
    # min_report_severity drops a finding from the gate decision entirely
    floored = Policy.loads(
        "gate:\n  fail_on: none\n  fail_on_mosca_act_now: true\n  min_report_severity: medium\n"
    )
    assert floored.gate_should_fail("low", mosca_act_now=True) is False
    assert floored.gate_should_fail("medium", mosca_act_now=True) is True
    assert floored.counts_for_gate("low") is False
    assert floored.counts_for_gate("high") is True

    # ---- 8. to_dict / from_dict round trip ---------------------------------
    d = pol.to_dict()
    assert d["resolved"]["Z_quantum_threat_year"] == 2035
    assert d["resolved"]["data_class_X"]["pii"] == 25
    assert d["resolved"]["gate_fail_on"] == "critical"
    assert isinstance(json.dumps(d), str), "to_dict must be JSON-serialisable"
    clone = Policy.from_dict(d)
    assert clone.z_year() == pol.z_year()
    assert clone.data_class_for("src/payments/x.py") == "financial"
    assert clone.criticality_for("tests/t.py") == pol.criticality_for("tests/t.py")
    assert clone.is_ignored("node_modules/x.js")
    assert clone.fail_on() == "critical"
    assert "resolved" not in clone.data and "_meta" not in clone.data, "bookkeeping stripped"

    # ---- 9. degrade gracefully ---------------------------------------------
    junk = Policy.from_dict({"mosca": "nonsense", "data_class_paths": 5, "ignore_paths": 7})
    assert junk.z_year() == 2035 and junk.y_default() == 3
    assert junk.data_class_for("a/b.py") == "default"
    assert junk.is_ignored("a/b.py") is False
    assert len(junk.errors) >= 3, junk.errors
    assert junk.rule_counts()["data_class_paths"] == 0, "an inert policy is visible to callers"

    # an undeclared data class is reported, not silently swallowed
    typo = Policy.loads(
        'inherit_defaults: false\n'
        'data_classes:\n  default: { X_protection_lifetime: 10 }\n'
        'data_class_paths:\n  "**/kyc/**": piii\n',
        inherit_defaults=False,
    )
    assert typo.data_class_for("a/kyc/b.py") == "default"
    assert any("piii" in e for e in typo.errors), typo.errors

    # an unknown gate severity is reported and falls back safely
    badgate = Policy.loads("gate:\n  fail_on: extreme\n")
    assert badgate.fail_on() == "critical"
    assert any("gate.fail_on" in e for e in badgate.errors), badgate.errors

    # no TLS endpoints configured -> the probe must not reach the network
    assert pol.tls_endpoints() == []
    assert pol.probe_timeout() == 5.0

    print("policy self-test: OK")
    print(f"  loaded: {pol.source}")
    print(f"  {pol}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
