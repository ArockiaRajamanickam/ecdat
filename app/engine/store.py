"""SQLite scan history and crypto-agility diffing for ECDAT.

The store answers the question a CISO actually asks after the first scan:
*did we get better or worse since last time?*

* :func:`save_scan`   - persist a ``ScanResult``, returns the new scan id.
* :func:`list_scans`  - history rows, newest first, optionally filtered by target.
* :func:`get_scan`    - one history row plus its stored artefacts.
* :func:`diff_scans`  - added / removed / unchanged / changed artefacts between
  two scans, with a severity delta summary and an overall posture verdict.
* :func:`latest_two`  - the two most recent scans for a target, oldest first, so
  the pair drops straight into :func:`diff_scans`.

Pure stdlib (``sqlite3`` + ``json``).  Tables are created on demand; the same
database file can be reused across releases because every write goes through
``CREATE TABLE IF NOT EXISTS`` and a small schema-version row.

Severity ranking is imported from :mod:`app.engine.models` - this module does
not keep its own copy.  The documented direction is **critical == highest
weight**, which is what the posture verdict below assumes.
"""

from __future__ import annotations

import json
import os
import sqlite3
from enum import Enum
from typing import Any, Iterable

from .models import SEVERITY_RANK

__all__ = [
    "SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "save_scan",
    "list_scans",
    "get_scan",
    "diff_scans",
    "latest_two",
    "delete_scan",
    "init_db",
]

SCHEMA_VERSION = 1


def _val(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _severity_table() -> dict[str, int]:
    """Normalise ``models.SEVERITY_RANK`` keys (Enum or str) to lower-case names."""
    table: dict[str, int] = {}
    for raw_key, raw_weight in SEVERITY_RANK.items():
        name = _val(raw_key)
        if not isinstance(name, str):
            continue
        try:
            table[name.strip().lower()] = int(raw_weight)
        except (TypeError, ValueError):
            continue
    return table


#: severity -> weight, straight from the shared model.  Critical is highest.
_SEVERITY_WEIGHT: dict[str, int] = _severity_table()

#: Worst-first ordering, derived from the shared table.
SEVERITY_ORDER: tuple[str, ...] = tuple(
    sorted(_SEVERITY_WEIGHT, key=lambda name: (-_SEVERITY_WEIGHT[name], name))
)

_LOWEST_SEVERITY: str = SEVERITY_ORDER[-1] if SEVERITY_ORDER else "none"

#: The five severities that have their own column in the ``scans`` table.  This
#: is a database-schema fact, not a second ranking: the ordering above is the
#: only thing that decides what "worse" means.
_COLUMN_SEVERITIES = ("critical", "high", "medium", "low", "none")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    started        TEXT,
    finished       TEXT,
    policy_name    TEXT,
    files_scanned  INTEGER NOT NULL DEFAULT 0,
    artefact_count INTEGER NOT NULL DEFAULT 0,
    occurrence_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    low_count      INTEGER NOT NULL DEFAULT 0,
    none_count     INTEGER NOT NULL DEFAULT 0,
    act_now_count  INTEGER NOT NULL DEFAULT 0,
    error_count    INTEGER NOT NULL DEFAULT 0,
    errors_json    TEXT    NOT NULL DEFAULT '[]',
    result_json    TEXT    NOT NULL DEFAULT '{}',
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS artefacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    artefact_key  TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    family        TEXT,
    kind          TEXT,
    threat        TEXT,
    severity      TEXT,
    score         REAL    NOT NULL DEFAULT 0,
    occurrences   INTEGER NOT NULL DEFAULT 0,
    act_now       INTEGER NOT NULL DEFAULT 0,
    shortfall     REAL,
    recommendation TEXT,
    data_json     TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target, id DESC);
CREATE INDEX IF NOT EXISTS idx_art_scan       ON artefacts(scan_id);
CREATE INDEX IF NOT EXISTS idx_art_key        ON artefacts(scan_id, artefact_key);
"""


# --------------------------------------------------------------------------- #
# Shape-tolerant accessors (objects or dicts, Enums or strings)
# --------------------------------------------------------------------------- #


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    value = obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)
    return default if value is None else value


def _severity(artefact: Any) -> str:
    text = str(_val(_get(artefact, "severity", _LOWEST_SEVERITY)) or _LOWEST_SEVERITY)
    text = text.strip().lower()
    return text if text in _SEVERITY_WEIGHT else _LOWEST_SEVERITY


def _weight(severity: Any) -> int:
    text = str(_val(severity) or _LOWEST_SEVERITY).strip().lower()
    return _SEVERITY_WEIGHT.get(text, 0)


def _threat(artefact: Any) -> str:
    return str(_val(_get(artefact, "threat", "unknown")) or "unknown").strip().lower()


def _score(artefact: Any) -> float:
    try:
        return float(_get(artefact, "score", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _float_or_none(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _artefact_key(artefact: Any) -> str:
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
    params = _get(artefact, "params", {}) or {}
    parts = [str(_get(artefact, "family", "") or "")]
    for name in ("key_size", "curve", "mode"):
        parts.append(str(_get(params, name, None)))
    return "|".join(parts)


def _identity(artefact: Any) -> str:
    """Diff identity: the artefact key plus the display name and kind.

    ``Artefact.key()`` deliberately omits ``name``, so SHA-256 and SHA-512 (both
    family ``SHA-2`` with no key size) share a key.  Folding them together in the
    history would make a genuine change look like no change, so the stored
    identity carries the name as well.
    """
    return "|".join(
        (
            _artefact_key(artefact),
            str(_get(artefact, "name", "") or ""),
            str(_val(_get(artefact, "kind", "algorithm")) or "algorithm"),
        )
    )


def _artefact_dict(artefact: Any) -> dict[str, Any]:
    """JSON-safe dict for one artefact, using ``to_dict()`` when it exists."""
    to_dict = getattr(artefact, "to_dict", None)
    if callable(to_dict):
        try:
            return json.loads(json.dumps(to_dict(), default=_json_default))
        except Exception:
            pass
    if isinstance(artefact, dict):
        try:
            return json.loads(json.dumps(artefact, default=_json_default))
        except Exception:
            return {"name": str(_get(artefact, "name", "unknown"))}
    fields = (
        "name", "family", "kind", "params", "occurrences", "threat", "threat_reason",
        "severity", "score", "data_class", "x_years", "y_years", "mosca_act_now",
        "mosca_shortfall", "criticality", "recommendation", "rec_rationale",
        "trade_offs", "fix_patch",
    )
    raw = {name: _get(artefact, name, None) for name in fields}
    try:
        return json.loads(json.dumps(raw, default=_json_default))
    except Exception:
        return {"name": str(_get(artefact, "name", "unknown"))}


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    for attr in ("to_dict", "isoformat"):
        method = getattr(value, attr, None)
        if callable(method):
            try:
                return method()
            except Exception:
                break
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def _result_dict(scan_result: Any) -> dict[str, Any]:
    to_dict = getattr(scan_result, "to_dict", None)
    if callable(to_dict):
        try:
            return json.loads(json.dumps(to_dict(), default=_json_default))
        except Exception:
            pass
    if isinstance(scan_result, dict):
        try:
            return json.loads(json.dumps(scan_result, default=_json_default))
        except Exception:
            pass
    return {
        "target": str(_get(scan_result, "target", "")),
        "artefacts": [_artefact_dict(a) for a in (_get(scan_result, "artefacts", []) or [])],
        "files_scanned": _get(scan_result, "files_scanned", 0),
        "started": str(_get(scan_result, "started", "")),
        "finished": str(_get(scan_result, "finished", "")),
        "policy_name": str(_get(scan_result, "policy_name", "default")),
        "errors": [str(e) for e in (_get(scan_result, "errors", []) or [])],
    }


# --------------------------------------------------------------------------- #
# Connection / schema
# --------------------------------------------------------------------------- #


def _connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    path = os.fspath(db_path)
    parent = os.path.dirname(os.path.abspath(path))
    if parent and path != ":memory:":
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | os.PathLike[str]) -> None:
    """Create the schema if it is not there yet.  Safe to call repeatedly."""
    conn = _connect(db_path)
    try:
        with conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #


def save_scan(db_path: str | os.PathLike[str], scan_result: Any) -> int:
    """Persist a scan and its artefacts.  Returns the new scan id.

    Artefacts are inserted in the order the caller supplied them, which is the
    risk engine's severity ordering, so ``get_scan`` can hand back a ranked list.
    """
    init_db(db_path)
    payload = _result_dict(scan_result)
    artefacts = list(_get(scan_result, "artefacts", []) or [])
    errors = [str(e) for e in (_get(scan_result, "errors", []) or [])]

    counts = {name: 0 for name in SEVERITY_ORDER}
    occurrence_total = 0
    act_now_total = 0
    rows: list[tuple[Any, ...]] = []
    for artefact in artefacts:
        severity = _severity(artefact)
        counts[severity] = counts.get(severity, 0) + 1
        occurrences = len(_get(artefact, "occurrences", []) or [])
        occurrence_total += occurrences
        act_now = 1 if _get(artefact, "mosca_act_now", False) else 0
        act_now_total += act_now
        rows.append(
            (
                _identity(artefact),
                str(_get(artefact, "name", "unknown")),
                str(_get(artefact, "family", "") or ""),
                str(_val(_get(artefact, "kind", "algorithm")) or "algorithm"),
                _threat(artefact),
                severity,
                _score(artefact),
                occurrences,
                act_now,
                _float_or_none(_get(artefact, "mosca_shortfall", None)),
                str(_get(artefact, "recommendation", "") or ""),
                json.dumps(_artefact_dict(artefact), default=_json_default),
            )
        )

    conn = _connect(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO scans(
                    target, started, finished, policy_name, files_scanned,
                    artefact_count, occurrence_count, critical_count, high_count,
                    medium_count, low_count, none_count, act_now_count,
                    error_count, errors_json, result_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(_get(scan_result, "target", "") or "unknown"),
                    str(_get(scan_result, "started", "") or ""),
                    str(_get(scan_result, "finished", "") or ""),
                    str(_get(scan_result, "policy_name", "default") or "default"),
                    int(_get(scan_result, "files_scanned", 0) or 0),
                    len(artefacts),
                    occurrence_total,
                    *[counts.get(name, 0) for name in _COLUMN_SEVERITIES],
                    act_now_total,
                    len(errors),
                    json.dumps(errors),
                    json.dumps(payload, default=_json_default),
                ),
            )
            scan_id = int(cursor.lastrowid)
            if rows:
                conn.executemany(
                    """
                    INSERT INTO artefacts(
                        scan_id, artefact_key, name, family, kind, threat, severity,
                        score, occurrences, act_now, shortfall, recommendation, data_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    [(scan_id, *row) for row in rows],
                )
        return scan_id
    finally:
        conn.close()


def delete_scan(db_path: str | os.PathLike[str], scan_id: int) -> bool:
    """Remove one scan and its artefacts.  Returns ``True`` if a row was deleted."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM artefacts WHERE scan_id = ?", (int(scan_id),))
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
            deleted = cursor.rowcount > 0
        return deleted
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #

_SCAN_COLUMNS = (
    "id, target, started, finished, policy_name, files_scanned, artefact_count, "
    "occurrence_count, critical_count, high_count, medium_count, low_count, "
    "none_count, act_now_count, error_count, created_at"
)


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    data = {key: row[key] for key in row.keys()}
    data["severity_counts"] = {
        name: data.get(f"{name}_count", 0) for name in _COLUMN_SEVERITIES
    }
    return data


def list_scans(
    db_path: str | os.PathLike[str],
    target: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """History rows, newest first.  Filter by ``target`` when given."""
    init_db(db_path)
    conn = _connect(db_path)
    try:
        if target:
            cursor = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans WHERE target = ? "
                "ORDER BY id DESC LIMIT ?",
                (str(target), int(limit)),
            )
        else:
            cursor = conn.execute(
                f"SELECT {_SCAN_COLUMNS} FROM scans ORDER BY id DESC LIMIT ?",
                (int(limit),),
            )
        return [_scan_row(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_scan(db_path: str | os.PathLike[str], scan_id: int) -> dict[str, Any] | None:
    """One history row with its artefact rows and the stored ``ScanResult`` dict.

    Artefacts come back worst-first (severity, then score), matching the order
    the report and the CBOM use.
    """
    init_db(db_path)
    conn = _connect(db_path)
    try:
        row = conn.execute(
            f"SELECT {_SCAN_COLUMNS}, errors_json, result_json FROM scans WHERE id = ?",
            (int(scan_id),),
        ).fetchone()
        if row is None:
            return None
        record = _scan_row(row)
        record["errors"] = _loads(record.pop("errors_json", "[]"), [])
        record["result"] = _loads(record.pop("result_json", "{}"), {})
        artefacts = [
            _artefact_row(art)
            for art in conn.execute(
                "SELECT artefact_key, name, family, kind, threat, severity, score, "
                "occurrences, act_now, shortfall, recommendation, data_json "
                "FROM artefacts WHERE scan_id = ? ORDER BY id ASC",
                (int(scan_id),),
            ).fetchall()
        ]
        artefacts.sort(
            key=lambda a: (
                -_weight(a.get("severity")),
                -float(a.get("score") or 0.0),
                str(a.get("name") or "").lower(),
            )
        )
        record["artefacts"] = artefacts
        return record
    finally:
        conn.close()


def _artefact_row(row: sqlite3.Row) -> dict[str, Any]:
    data = {key: row[key] for key in row.keys()}
    data["act_now"] = bool(data.get("act_now", 0))
    data["data"] = _loads(data.pop("data_json", "{}"), {})
    return data


def _loads(text: Any, fallback: Any) -> Any:
    try:
        return json.loads(text) if text else fallback
    except (TypeError, ValueError):
        return fallback


def latest_two(
    db_path: str | os.PathLike[str],
    target: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """The two most recent scans for ``target``, returned **oldest first**.

    The ordering means the pair feeds :func:`diff_scans` directly::

        older, newer = latest_two(db, "/srv/app")
        if older and newer:
            delta = diff_scans(db, older["id"], newer["id"])

    Returns ``(None, None)`` when there is no history and ``(None, row)`` when
    only one scan exists.
    """
    rows = list_scans(db_path, target=target, limit=2)
    if not rows:
        return (None, None)
    if len(rows) == 1:
        return (None, rows[0])
    return (rows[1], rows[0])


# --------------------------------------------------------------------------- #
# Agility diff
# --------------------------------------------------------------------------- #


def _artefact_index(conn: sqlite3.Connection, scan_id: int) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT artefact_key, name, family, kind, threat, severity, score, "
        "occurrences, act_now, shortfall, recommendation FROM artefacts "
        "WHERE scan_id = ?",
        (int(scan_id),),
    ):
        record = {key: row[key] for key in row.keys()}
        record["act_now"] = bool(record.get("act_now", 0))
        key = record.get("artefact_key") or record.get("name") or "unknown"
        existing = index.get(key)
        # Same key twice in one scan: keep the worst instance.
        if existing is None or _weight(record.get("severity")) > _weight(
            existing.get("severity")
        ):
            index[key] = record
    return index


def diff_scans(
    db_path: str | os.PathLike[str],
    id_a: int,
    id_b: int,
) -> dict[str, Any]:
    """Crypto-agility diff between scan ``id_a`` (baseline) and ``id_b`` (current).

    Returns a dict with:

    ``added`` / ``removed`` / ``unchanged``
        Sorted artefact **names**.
    ``changed``
        Artefacts present in both whose severity, threat, score, recommendation or
        occurrence count moved, each with ``from``/``to`` and a ``direction`` of
        ``better`` / ``worse`` / ``same``.
    ``severity_delta``
        Per-severity ``{"a": n, "b": m, "delta": m - n}`` plus totals.
    ``posture``
        ``improved`` / ``regressed`` / ``unchanged`` - the one-word verdict.
    ``summary``
        A human sentence suitable for a CI comment.
    """
    init_db(db_path)
    conn = _connect(db_path)
    try:
        meta_a = conn.execute(
            f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?", (int(id_a),)
        ).fetchone()
        meta_b = conn.execute(
            f"SELECT {_SCAN_COLUMNS} FROM scans WHERE id = ?", (int(id_b),)
        ).fetchone()
        missing = [str(i) for i, row in ((id_a, meta_a), (id_b, meta_b)) if row is None]
        if missing:
            raise ValueError(f"unknown scan id(s): {', '.join(missing)}")

        index_a = _artefact_index(conn, int(id_a))
        index_b = _artefact_index(conn, int(id_b))
    finally:
        conn.close()

    keys_a, keys_b = set(index_a), set(index_b)
    added_keys = sorted(keys_b - keys_a)
    removed_keys = sorted(keys_a - keys_b)
    common_keys = sorted(keys_a & keys_b)

    changed: list[dict[str, Any]] = []
    unchanged_names: list[str] = []
    for key in common_keys:
        before, after = index_a[key], index_b[key]
        tracked = ("severity", "threat", "score", "occurrences", "recommendation", "act_now")
        moved = {name for name in tracked if before.get(name) != after.get(name)}
        if not moved:
            unchanged_names.append(str(after.get("name", key)))
            continue
        delta_weight = _weight(after.get("severity")) - _weight(before.get("severity"))
        direction = "worse" if delta_weight > 0 else "better" if delta_weight < 0 else "same"
        changed.append(
            {
                "key": key,
                "name": str(after.get("name", key)),
                "fields": sorted(moved),
                "direction": direction,
                "from": {
                    "severity": before.get("severity"),
                    "threat": before.get("threat"),
                    "score": before.get("score"),
                    "occurrences": before.get("occurrences"),
                    "recommendation": before.get("recommendation"),
                    "act_now": before.get("act_now"),
                },
                "to": {
                    "severity": after.get("severity"),
                    "threat": after.get("threat"),
                    "score": after.get("score"),
                    "occurrences": after.get("occurrences"),
                    "recommendation": after.get("recommendation"),
                    "act_now": after.get("act_now"),
                },
            }
        )

    def _names(keys: Iterable[str], index: dict[str, dict[str, Any]]) -> list[str]:
        return sorted(str(index[k].get("name", k)) for k in keys)

    severity_delta: dict[str, Any] = {}
    for name in SEVERITY_ORDER:
        count_a = sum(1 for rec in index_a.values() if rec.get("severity") == name)
        count_b = sum(1 for rec in index_b.values() if rec.get("severity") == name)
        severity_delta[name] = {"a": count_a, "b": count_b, "delta": count_b - count_a}
    severity_delta["total"] = {
        "a": len(index_a),
        "b": len(index_b),
        "delta": len(index_b) - len(index_a),
    }

    risk_a = sum(_weight(r.get("severity")) for r in index_a.values())
    risk_b = sum(_weight(r.get("severity")) for r in index_b.values())
    act_now_a = sum(1 for r in index_a.values() if r.get("act_now"))
    act_now_b = sum(1 for r in index_b.values() if r.get("act_now"))

    if risk_b < risk_a:
        posture = "improved"
    elif risk_b > risk_a:
        posture = "regressed"
    else:
        posture = "unchanged"

    added_names = _names(added_keys, index_b)
    removed_names = _names(removed_keys, index_a)
    worse = [c for c in changed if c["direction"] == "worse"]
    better = [c for c in changed if c["direction"] == "better"]

    critical = severity_delta.get("critical", {"a": 0, "b": 0})
    summary = (
        f"Posture {posture}: {len(added_names)} added, {len(removed_names)} removed, "
        f"{len(unchanged_names)} unchanged, {len(changed)} changed "
        f"({len(worse)} worse, {len(better)} better). "
        f"Weighted risk {risk_a} -> {risk_b}; "
        f"critical {critical.get('a', 0)} -> {critical.get('b', 0)}; "
        f"Mosca act-now {act_now_a} -> {act_now_b}."
    )

    return {
        "scan_a": _scan_row(meta_a),
        "scan_b": _scan_row(meta_b),
        "added": added_names,
        "removed": removed_names,
        "unchanged": sorted(unchanged_names),
        "changed": changed,
        "severity_delta": severity_delta,
        "risk_score": {"a": risk_a, "b": risk_b, "delta": risk_b - risk_a},
        "act_now": {"a": act_now_a, "b": act_now_b, "delta": act_now_b - act_now_a},
        "posture": posture,
        "summary": summary,
    }
