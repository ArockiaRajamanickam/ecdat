"""
ECDAT - normalization / de-duplication stage.

The detectors are deliberately noisy: the same RSA-1024 key generation can be
reported by the tree-sitter Python detector, the regex fallback detector and the
dependency-manifest detector, each with its own provenance.  This module folds
those raw findings into one artefact per *cryptographic identity* while
preserving every piece of evidence, because provenance is what an auditor
actually reviews.

Identity
--------
``Artefact.key()`` alone (``family|key_size|curve|mode``) is **not** an identity.
Several detectors legitimately encode the discriminating variant only in
``name``: ``source_python._HASHES`` maps sha256/sha384/sha512 all to family
``SHA-2``; ``_TLS_CONST`` maps SSLv3/TLSv1.0/TLSv1.2 all to family ``TLS``; every
HMAC variant shares family ``HMAC``.  Grouping on ``key()`` alone collapsed those
distinct algorithms into one artefact that kept the first name and inherited
everybody else's occurrences.  The grouping identity used here is therefore
``key() | name | kind``, which matches what the detectors' own sinks
(``source_python._Sink``, ``_srcutil.Collector``) already key on.

Guarantees
----------
* one artefact per ``(key(), name, kind)``
* occurrences are the union of all inputs, de-duplicated on
  ``(file, line, evidence)`` keeping the strongest confidence seen
* occurrences sorted by ``(file, line)`` - stable, diff-friendly output
* the richest ``Params`` wins field-by-field (a non-None value always beats None)
* low-confidence-only artefacts are dropped when the same family is already
  anchored by a high-confidence artefact (kills regex echo/comment noise without
  ever hiding a family we would otherwise never report)
* output order is risk-first when the risk engine has already run
  (``-severity, -score, family, name``) and alphabetical otherwise, so re-running
  normalize after enrichment does not destroy the ranking ``apply_risk`` built
* never raises on odd input; malformed artefacts are skipped, not fatal

Severity ordering comes from the single shared table
``app.engine.models.SEVERITY_RANK``, whose documented direction is
**higher rank == more severe** (``critical`` is the maximum).  There is no local
mirror of that table and no direction guard: one source of truth.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .models import SEVERITY_RANK, Artefact, Occurrence, Params, Severity

__all__ = [
    "merge_artefacts",
    "merge_occurrences",
    "merge_params",
    "artefact_identity",
    "CONFIDENCE_RANK",
]

# Higher is better.  Unknown/odd strings fall back to "medium" so a detector that
# invents its own vocabulary is never silently discarded.
CONFIDENCE_RANK: dict[str, int] = {"high": 3, "medium": 2, "low": 1}
_DEFAULT_CONFIDENCE_RANK = 2

# Optional fields written by later stages (risk engine, recommender).  When two
# artefacts merge we carry these across from whichever copy actually has them so
# normalize() can be re-run after enrichment without losing work.
_CARRIED_FIELDS: tuple[str, ...] = (
    "threat", "threat_reason", "severity", "score", "data_class",
    "x_years", "y_years", "mosca_act_now", "mosca_shortfall", "criticality",
    "recommendation", "rec_rationale", "trade_offs", "fix_patch",
)

# Preference order when two artefacts with the same identity disagree about
# `kind`.  A concrete asset (a certificate on disk, a key file) outranks a
# generic algorithm mention of the same primitive.
_KIND_PRIORITY: dict[str, int] = {
    "certificate": 5, "key": 4, "protocol": 3, "library": 2, "algorithm": 1,
}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _confidence_rank(value: Any) -> int:
    if not isinstance(value, str):
        return _DEFAULT_CONFIDENCE_RANK
    return CONFIDENCE_RANK.get(value.strip().lower(), _DEFAULT_CONFIDENCE_RANK)


def _occ_confidence(occ: Any) -> str:
    value = getattr(occ, "confidence", "high")
    return value if isinstance(value, str) else "high"


def _occ_sort_key(occ: Any) -> tuple[str, int, str, str]:
    """Sort by file, then line (unknown lines last), then evidence/detector."""
    line = getattr(occ, "line", None)
    line_key = line if isinstance(line, int) else 10**9
    return (
        str(getattr(occ, "file", "") or ""),
        line_key,
        str(getattr(occ, "evidence", "") or ""),
        str(getattr(occ, "detector", "") or ""),
    )


def _occ_identity(occ: Any) -> tuple[str, Optional[int], str]:
    """Identity used for de-duplication: file + line + evidence text."""
    line = getattr(occ, "line", None)
    return (
        str(getattr(occ, "file", "") or ""),
        line if isinstance(line, int) else None,
        str(getattr(occ, "evidence", "") or "").strip(),
    )


def _params_richness(params: Any) -> int:
    """How many of the interesting parameter slots are actually populated."""
    if params is None:
        return 0
    score = 0
    for field_name in ("key_size", "curve", "mode", "padding", "not_after"):
        if getattr(params, field_name, None) is not None:
            score += 1
    extra = getattr(params, "extra", None)
    if isinstance(extra, dict) and extra:
        score += 1
    return score


def _kind_priority(kind: Any) -> int:
    if not isinstance(kind, str):
        return 0
    return _KIND_PRIORITY.get(kind.strip().lower(), 0)


def _best_confidence(occurrences: Iterable[Any]) -> int:
    best = 0
    for occ in occurrences:
        best = max(best, _confidence_rank(_occ_confidence(occ)))
    return best


def _severity_weight(value: Any) -> int:
    """Rank a severity through the shared table. Unset/unknown sorts last (-1).

    ``SEVERITY_RANK`` may be keyed by ``Severity`` members or by their string
    values depending on how models.py was written, and ``Enum.__hash__`` is not
    the string hash, so both spellings are probed.
    """
    if value is None or value == "":
        return -1
    if isinstance(value, Severity):
        severity: Optional[Severity] = value
    else:
        try:
            severity = Severity(str(value).strip().lower())
        except (ValueError, TypeError):
            return -1
    for candidate in (severity, severity.value, str(severity.value).lower()):
        try:
            if candidate in SEVERITY_RANK:
                return int(SEVERITY_RANK[candidate])
        except TypeError:  # unhashable candidate - cannot happen, but be safe
            continue
    return -1


def _score(artefact: Any) -> float:
    try:
        return float(getattr(artefact, "score", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


# --------------------------------------------------------------------------- #
# public helpers
# --------------------------------------------------------------------------- #
def artefact_identity(artefact: Any) -> str:
    """The grouping identity: cryptographic key plus display name and kind.

    ``Artefact.key()`` deliberately omits ``name``, so it cannot separate
    SHA-256 from SHA-512 (both family ``SHA-2``) or TLS 1.0 from TLS 1.2 (both
    family ``TLS``).  Appending name and kind restores the distinction while
    still folding the multiple detector reports of one algorithm together.
    """
    try:
        base = artefact.key()
    except Exception:
        base = f"<unkeyable>|{id(artefact)}"
    name = str(getattr(artefact, "name", "") or "")
    kind = str(getattr(artefact, "kind", "") or "")
    return f"{base}|{name}|{kind}"


def merge_occurrences(occurrences: Iterable[Any]) -> list[Occurrence]:
    """Union occurrences, de-duplicating on (file, line, evidence).

    When the same site is reported twice the record with the *higher* confidence
    wins, so a high-confidence AST hit is never downgraded by a regex echo of the
    same line.
    """
    best: dict[tuple[str, Optional[int], str], Any] = {}
    for occ in occurrences or []:
        if occ is None:
            continue
        identity = _occ_identity(occ)
        current = best.get(identity)
        if current is None:
            best[identity] = occ
            continue
        if _confidence_rank(_occ_confidence(occ)) > _confidence_rank(_occ_confidence(current)):
            best[identity] = occ
    return sorted(best.values(), key=_occ_sort_key)


def merge_params(primary: Any, other: Any) -> Params:
    """Field-by-field merge; `primary` wins, `other` fills the None holes."""
    if primary is None and other is None:
        return Params()
    if primary is None:
        return other
    if other is None:
        return primary

    for field_name in ("key_size", "curve", "mode", "padding", "not_after"):
        if getattr(primary, field_name, None) is None:
            value = getattr(other, field_name, None)
            if value is not None:
                try:
                    setattr(primary, field_name, value)
                except Exception:  # frozen/odd Params implementation
                    pass

    primary_extra = getattr(primary, "extra", None)
    other_extra = getattr(other, "extra", None)
    if isinstance(other_extra, dict) and other_extra:
        if isinstance(primary_extra, dict):
            for k, v in other_extra.items():
                if primary_extra.get(k) in (None, "", [], {}):
                    primary_extra[k] = v
        else:
            try:
                primary.extra = dict(other_extra)
            except Exception:
                pass
    return primary


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def merge_artefacts(artefacts: list[Artefact]) -> list[Artefact]:
    """Fold raw detector output into one artefact per :func:`artefact_identity`.

    Returns a new list; the artefact objects themselves are reused (mutated) so
    that any enrichment already attached by other stages survives.
    """
    if not artefacts:
        return []

    order: list[str] = []
    groups: dict[str, list[Artefact]] = {}

    for artefact in artefacts:
        if artefact is None:
            continue
        identity = artefact_identity(artefact)
        if identity not in groups:
            groups[identity] = []
            order.append(identity)
        groups[identity].append(artefact)

    merged: list[Artefact] = []
    for identity in order:
        base = _merge_group(groups[identity])
        if base is not None:
            merged.append(base)

    merged = _drop_low_confidence_noise(merged)

    # Deterministic output ordering.  When the risk engine has scored these
    # artefacts, keep its ranking (most severe first) so downstream consumers
    # that trust input order - gate.py's "top offenders", store.py's insert
    # order - stay correct even if normalize is re-run after enrichment.
    # Unscored artefacts fall back to alphabetical and sort last.
    merged.sort(key=lambda a: (
        -_severity_weight(getattr(a, "severity", None)),
        -_score(a),
        str(getattr(a, "family", "") or ""),
        str(getattr(a, "name", "") or ""),
        artefact_identity(a),
    ))
    return merged


def _merge_group(group: list[Artefact]) -> Optional[Artefact]:
    """Collapse one same-identity group into a single artefact."""
    group = [a for a in group if a is not None]
    if not group:
        return None
    if len(group) == 1:
        base = group[0]
        base.occurrences = merge_occurrences(getattr(base, "occurrences", []) or [])
        return base

    # The "base" is the richest description: most populated params, then the most
    # concrete kind, then the most specific (longest) name, then input order for
    # determinism.
    indexed = list(enumerate(group))
    base_index, base = min(
        indexed,
        key=lambda pair: (
            -_params_richness(getattr(pair[1], "params", None)),
            -_kind_priority(getattr(pair[1], "kind", "")),
            -len(str(getattr(pair[1], "name", "") or "")),
            pair[0],
        ),
    )

    all_occurrences: list[Any] = []
    for artefact in group:
        all_occurrences.extend(getattr(artefact, "occurrences", []) or [])

    for index, artefact in indexed:
        if index == base_index:
            continue
        base.params = merge_params(getattr(base, "params", None), getattr(artefact, "params", None))
        if _kind_priority(getattr(artefact, "kind", "")) > _kind_priority(getattr(base, "kind", "")):
            base.kind = artefact.kind
        _carry_fields(base, artefact)

    base.occurrences = merge_occurrences(all_occurrences)
    return base


def _carry_fields(base: Any, other: Any) -> None:
    """Copy enrichment fields from `other` onto `base` where `base` has none."""
    for field_name in _CARRIED_FIELDS:
        if not hasattr(other, field_name):
            continue
        incoming = getattr(other, field_name, None)
        if incoming in (None, "", 0, 0.0, [], {}, False):
            continue
        current = getattr(base, field_name, None)
        if current in (None, "", 0, 0.0, [], {}, False):
            try:
                setattr(base, field_name, incoming)
            except Exception:
                pass


def _drop_low_confidence_noise(artefacts: list[Artefact]) -> list[Artefact]:
    """Drop artefacts whose every occurrence is low-confidence *when* the same
    family is already anchored by a high-confidence artefact.

    Rationale: a regex hit on the string "aes" inside a comment is worthless once
    we have an AST-confirmed AES-256-GCM in the same family, but it is the only
    signal we have if nothing else in that family was found - so we keep it then.
    """
    anchored_families: set[str] = set()
    for artefact in artefacts:
        occurrences = getattr(artefact, "occurrences", []) or []
        if not occurrences:
            continue
        if _best_confidence(occurrences) >= CONFIDENCE_RANK["high"]:
            anchored_families.add(str(getattr(artefact, "family", "") or "").upper())

    kept: list[Artefact] = []
    for artefact in artefacts:
        occurrences = getattr(artefact, "occurrences", []) or []
        family = str(getattr(artefact, "family", "") or "").upper()
        low_only = bool(occurrences) and _best_confidence(occurrences) <= CONFIDENCE_RANK["low"]
        if low_only and family in anchored_families:
            continue
        kept.append(artefact)
    return kept
