"""
ECDAT risk engine: turn a raw inventory of cryptographic artefacts into a
ranked, defensible remediation queue.

For every artefact the engine does five things, in order:

1. **Classify** the primitive through :mod:`app.engine.kb` -> ``threat`` and a
   cited ``threat_reason``.
2. **Locate** the artefact in the organisation by matching the *first
   occurrence's* file path against the policy's path globs -> ``data_class``
   (which yields X, the data shelf life) and ``criticality``.
3. **Decide urgency** with Mosca's inequality using X, the policy's Y
   (migration time) and Z (the assumed CRQC year) -> ``mosca_act_now`` and
   ``mosca_shortfall``.
4. **Score** it (0-100) so two CRITICALs can still be ordered against each other.
5. **Assign severity** from the threat class and the Mosca verdict.

The scoring formula
-------------------
::

    score = 100 x quantum_weight x criticality_weight

``criticality_weight`` comes straight from the policy (``critical`` 1.00,
``high`` 0.80, ``medium`` 0.55, ``low`` 0.30, ``none`` 0.15). It answers
"how much does this asset matter?".

``quantum_weight`` answers "how badly is this primitive hurt, and how late are
we?". It is the threat's base weight scaled by a bounded urgency factor::

    quantum_weight = base_weight x (URGENCY_FLOOR + (1 - URGENCY_FLOOR) x urgency)

    base_weight:  shor_broken 1.00 | legacy_broken 0.95 | grover_weakened 0.50
                  unknown 0.25 | quantum_safe 0.05 | pqc 0.00

    urgency    :  0.0                                   when Mosca says there is slack
                  min(1.0, shortfall / max(1, X + Y))   when Mosca says act now

    URGENCY_FLOOR = 0.7

Two consequences are deliberate:

* An artefact with slack still scores 70% of its threat weight - a Shor-broken
  key in a low-value path is not a zero, it is just not this quarter's problem.
* Urgency is normalised by the artefact's own (X + Y) budget, so a 30-year
  shelf-life secret that overshoots by 6 years does not automatically outrank a
  2-year secret that overshoots by 6 years; proportional lateness is what
  matters, and the absolute shortfall is still reported separately.

Because both factors are in [0, 1], the score is in [0, 100] and is directly
comparable across a whole estate.

Severity (the rule the CLI, the report and the CBOM all agree on)
-----------------------------------------------------------------
======================================  ==========
condition                               severity
======================================  ==========
SHOR_BROKEN or LEGACY_BROKEN + act_now  CRITICAL
SHOR_BROKEN, not act_now                HIGH
LEGACY_BROKEN, not act_now              HIGH
GROVER_WEAKENED                         MEDIUM
UNKNOWN                                 LOW
QUANTUM_SAFE / PQC                      NONE
======================================  ==========

Policy shape
------------
A policy may be a plain ``dict`` (from JSON or the YAML subset parser), an
object exposing the same names as attributes, or anything with ``.to_dict()``.
Anything missing falls back to :data:`DEFAULT_POLICY`, so the engine runs with
``policy=None``.

.. code-block:: yaml

    name: "NTRO baseline"
    z_year: 2035          # NIST IR 8547: classical PKC disallowed after 2035
    y_years: 5            # how long our migration takes
    defaults:
      data_class: internal
      criticality: medium
    data_classes:
      top_secret:   { x_years: 30 }
      secret:       { x_years: 25 }
      confidential: { x_years: 15 }
      restricted:   { x_years: 10 }
      internal:     { x_years: 5 }
      public:       { x_years: 0 }
    criticality_weights:
      critical: 1.0
      high: 0.8
      medium: 0.55
      low: 0.3
      none: 0.15
    paths:
      - glob: "**/keys/**"        # most specific pattern wins
        data_class: secret
        criticality: critical
      - glob: "**/test/**"
        data_class: public
        criticality: low
"""

from __future__ import annotations

import datetime
import fnmatch
import posixpath
from typing import Any, Iterable, Optional, Sequence

try:  # normal package import
    from .. import kb
    from ..models import SEVERITY_RANK, Severity, Threat
    from .mosca import mosca_detail
except ImportError:  # pragma: no cover - direct execution / flat layout
    from app.engine import kb  # type: ignore
    from app.engine.models import SEVERITY_RANK, Severity, Threat  # type: ignore
    from app.engine.risk.mosca import mosca_detail  # type: ignore

__all__ = [
    "DEFAULT_POLICY",
    "QUANTUM_WEIGHTS",
    "CRITICALITY_WEIGHTS",
    "URGENCY_FLOOR",
    "apply_risk",
    "score_artefact",
    "summarize",
    "resolve_policy",
]

# --------------------------------------------------------------------------
# Weights
# --------------------------------------------------------------------------
QUANTUM_WEIGHTS: dict[str, float] = {
    Threat.SHOR_BROKEN.value: 1.00,
    Threat.LEGACY_BROKEN.value: 0.95,
    Threat.GROVER_WEAKENED.value: 0.50,
    Threat.UNKNOWN.value: 0.25,
    Threat.QUANTUM_SAFE.value: 0.05,
    Threat.PQC.value: 0.00,
}

CRITICALITY_WEIGHTS: dict[str, float] = {
    "critical": 1.00,
    "high": 0.80,
    "medium": 0.55,
    "low": 0.30,
    "none": 0.15,
    "info": 0.15,
}

URGENCY_FLOOR = 0.7

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]

# --------------------------------------------------------------------------
# Default policy (NTRO / CNSA 2.0 flavoured, deliberately conservative)
# --------------------------------------------------------------------------
DEFAULT_POLICY: dict[str, Any] = {
    "name": "ECDAT baseline (NIST IR 8547 / CNSA 2.0 aligned)",
    "z_year": 2035,
    "y_years": 5,
    "defaults": {"data_class": "internal", "criticality": "medium", "x_years": 5},
    "data_classes": {
        "top_secret": {"x_years": 30, "label": "Top Secret / national security"},
        "secret": {"x_years": 25, "label": "Secret"},
        "confidential": {"x_years": 15, "label": "Confidential"},
        "restricted": {"x_years": 10, "label": "Restricted / regulated PII"},
        "internal": {"x_years": 5, "label": "Internal"},
        "public": {"x_years": 0, "label": "Public"},
    },
    "criticality_weights": dict(CRITICALITY_WEIGHTS),
    "paths": [
        {"glob": "**/*.pem", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/*.key", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/*.p12", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/*.pfx", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/*.jks", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/keys/**", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/secrets/**", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/crypto/**", "data_class": "confidential", "criticality": "critical"},
        {"glob": "**/auth/**", "data_class": "confidential", "criticality": "critical"},
        {"glob": "**/identity/**", "data_class": "confidential", "criticality": "critical"},
        {"glob": "**/payment*/**", "data_class": "confidential", "criticality": "critical"},
        {"glob": "**/kms/**", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/hsm/**", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/vault/**", "data_class": "secret", "criticality": "critical"},
        {"glob": "**/session*/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/token*/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/tls/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/network/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/api/**", "data_class": "internal", "criticality": "high"},
        {"glob": "**/backup*/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/archive/**", "data_class": "confidential", "criticality": "high"},
        {"glob": "**/migrations/**", "data_class": "internal", "criticality": "medium"},
        {"glob": "**/scripts/**", "data_class": "internal", "criticality": "low"},
        {"glob": "**/docs/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/examples/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/samples/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/test/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/tests/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/*_test.*", "data_class": "public", "criticality": "low"},
        {"glob": "**/*test*.py", "data_class": "public", "criticality": "low"},
        {"glob": "**/spec/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/fixtures/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/vendor/**", "data_class": "internal", "criticality": "low"},
        {"glob": "**/node_modules/**", "data_class": "public", "criticality": "low"},
        {"glob": "**/third_party/**", "data_class": "internal", "criticality": "low"},
    ],
    # Optional: raise criticality one step for artefacts whose kind is a key or
    # a certificate, wherever they were found. Off by default so that path
    # globs stay the single, explainable source of criticality.
    "escalate_key_material": False,
}


# --------------------------------------------------------------------------
# Policy access - tolerant of dict / object / to_dict()
# --------------------------------------------------------------------------
def _to_mapping(policy: Any) -> dict:
    if policy is None:
        return {}
    if isinstance(policy, dict):
        return policy
    to_dict = getattr(policy, "to_dict", None)
    if callable(to_dict):
        try:
            result = to_dict()
            if isinstance(result, dict):
                return result
        except Exception:
            pass
    as_dict = getattr(policy, "__dict__", None)
    if isinstance(as_dict, dict) and as_dict:
        return {k: v for k, v in as_dict.items() if not k.startswith("_")}
    keys = ("name", "z_year", "y_years", "defaults", "data_classes", "criticality_weights",
            "paths", "escalate_key_material")
    collected = {k: getattr(policy, k) for k in keys if hasattr(policy, k)}
    return collected


def _num(value: Any, default: float) -> float:
    if value is None or isinstance(value, bool):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class _PolicyView:
    """Normalised, crash-proof read-only view over whatever policy object we got."""

    def __init__(self, policy: Any = None) -> None:
        raw = _to_mapping(policy)
        self.raw = raw
        self.name: str = str(raw.get("name") or DEFAULT_POLICY["name"])
        self.z_year: int = int(_num(raw.get("z_year"), DEFAULT_POLICY["z_year"]))
        self.y_years: int = int(_num(raw.get("y_years"), DEFAULT_POLICY["y_years"]))

        defaults = raw.get("defaults")
        defaults = defaults if isinstance(defaults, dict) else {}
        base_defaults = dict(DEFAULT_POLICY["defaults"])
        base_defaults.update({k: v for k, v in defaults.items() if v is not None})
        self.default_data_class: str = str(base_defaults.get("data_class", "internal")).lower()
        self.default_criticality: str = str(base_defaults.get("criticality", "medium")).lower()
        self.default_x: int = int(_num(base_defaults.get("x_years"), 5))

        classes = raw.get("data_classes")
        self.data_classes: dict[str, dict] = {}
        source = classes if isinstance(classes, dict) else DEFAULT_POLICY["data_classes"]
        for name, spec in source.items():
            key = str(name).strip().lower()
            if isinstance(spec, dict):
                self.data_classes[key] = dict(spec)
            else:  # allow "secret: 25" shorthand
                self.data_classes[key] = {"x_years": _num(spec, self.default_x)}

        weights = raw.get("criticality_weights")
        self.criticality_weights: dict[str, float] = dict(CRITICALITY_WEIGHTS)
        if isinstance(weights, dict):
            for name, val in weights.items():
                self.criticality_weights[str(name).strip().lower()] = _num(val, 0.5)

        self.escalate_key_material: bool = bool(raw.get("escalate_key_material", False))
        self.rules: list[dict[str, Any]] = self._compile_rules(raw.get("paths"))

    # -- rule compilation ------------------------------------------------
    @staticmethod
    def _compile_rules(paths: Any) -> list[dict[str, Any]]:
        if paths is None:
            paths = DEFAULT_POLICY["paths"]
        rules: list[dict[str, Any]] = []

        def add(glob: Any, spec: Any) -> None:
            pattern = str(glob or "").strip()
            if not pattern:
                return
            if isinstance(spec, dict):
                rule = dict(spec)
            elif isinstance(spec, str):
                rule = {"data_class": spec}
            else:
                rule = {}
            rule["glob"] = pattern.replace("\\", "/")
            rules.append(rule)

        if isinstance(paths, dict):
            for glob, spec in paths.items():
                add(glob, spec)
        elif isinstance(paths, (list, tuple)):
            for item in paths:
                if isinstance(item, dict):
                    add(item.get("glob") or item.get("path") or item.get("pattern"), item)
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    add(item[0], item[1])
        # Most specific pattern first: longer, less wildcard-y patterns win.
        rules.sort(key=lambda r: (-len(r["glob"]), r["glob"].count("*")))
        return rules

    # -- lookups ---------------------------------------------------------
    def match(self, path: str) -> Optional[dict[str, Any]]:
        """First (most specific) rule whose glob matches the path, or None."""
        if not path:
            return None
        norm = str(path).replace("\\", "/")
        candidates = {norm, norm.lstrip("./"), posixpath.basename(norm)}
        if not norm.startswith("/"):
            candidates.add("/" + norm)
        for rule in self.rules:
            pattern = rule["glob"]
            simple = pattern.replace("**/", "*").replace("/**", "/*")
            for cand in candidates:
                if fnmatch.fnmatch(cand, pattern) or fnmatch.fnmatch(cand, simple):
                    return rule
        return None

    def x_years_for(self, data_class: str, rule: Optional[dict[str, Any]]) -> int:
        if rule and rule.get("x_years") is not None:
            return int(_num(rule.get("x_years"), self.default_x))
        spec = self.data_classes.get(str(data_class).lower())
        if spec and spec.get("x_years") is not None:
            return int(_num(spec.get("x_years"), self.default_x))
        return self.default_x

    def criticality_weight(self, criticality: str) -> float:
        return self.criticality_weights.get(str(criticality).lower(), 0.5)


def resolve_policy(policy: Any = None) -> _PolicyView:
    """Public helper so the CLI and the reporter can show the effective policy."""
    return _PolicyView(policy)


# --------------------------------------------------------------------------
# Artefact helpers
# --------------------------------------------------------------------------
def _first_path(artefact: Any) -> str:
    occurrences = getattr(artefact, "occurrences", None) or []
    for occ in occurrences:
        path = getattr(occ, "file", None) if not isinstance(occ, dict) else occ.get("file")
        if path:
            return str(path)
    return ""


def _threat_value(threat: Any) -> str:
    if isinstance(threat, Threat):
        return threat.value
    return str(threat or Threat.UNKNOWN.value)


def _bump(criticality: str) -> str:
    ladder = ["none", "low", "medium", "high", "critical"]
    key = str(criticality).lower()
    if key in ladder:
        return ladder[min(len(ladder) - 1, ladder.index(key) + 1)]
    return criticality


def _severity_for(threat: Threat, act_now: bool) -> Severity:
    """The severity rule table. See the module docstring."""
    if threat in (Threat.SHOR_BROKEN, Threat.LEGACY_BROKEN) and act_now:
        return Severity.CRITICAL
    if threat is Threat.SHOR_BROKEN:
        return Severity.HIGH
    if threat is Threat.LEGACY_BROKEN:
        return Severity.HIGH
    if threat is Threat.GROVER_WEAKENED:
        return Severity.MEDIUM
    if threat in (Threat.QUANTUM_SAFE, Threat.PQC):
        return Severity.NONE
    return Severity.LOW  # UNKNOWN: worth a look, never silently dropped


def score_artefact(threat: Any, criticality: str, act_now: bool, shortfall: int,
                   x_years: int, y_years: int, view: Optional[_PolicyView] = None) -> float:
    """``100 x quantum_weight x criticality_weight`` - see the module docstring."""
    view = view or _PolicyView(None)
    base = QUANTUM_WEIGHTS.get(_threat_value(threat), 0.25)
    budget = max(1, int(x_years) + int(y_years))
    urgency = min(1.0, max(0, int(shortfall)) / budget) if act_now else 0.0
    quantum_weight = base * (URGENCY_FLOOR + (1.0 - URGENCY_FLOOR) * urgency)
    crit_weight = view.criticality_weight(criticality)
    return round(100.0 * quantum_weight * crit_weight, 2)


def _severity_sort_key(severity: Any) -> int:
    """Most severe first, whichever direction models.SEVERITY_RANK happens to run."""
    try:
        sev = severity if isinstance(severity, Severity) else Severity(str(severity))
    except ValueError:
        sev = Severity.LOW
    rank = SEVERITY_RANK or {}
    crit = rank.get(Severity.CRITICAL, rank.get("critical"))
    none = rank.get(Severity.NONE, rank.get("none"))
    if isinstance(crit, (int, float)) and isinstance(none, (int, float)):
        value = rank.get(sev, rank.get(sev.value))
        if isinstance(value, (int, float)):
            return int(-value) if crit > none else int(value)
    return _SEVERITY_ORDER.index(sev)


# --------------------------------------------------------------------------
# The entry point
# --------------------------------------------------------------------------
def apply_risk(artefacts: Sequence[Any], policy: Any = None, now_year: Optional[int] = None,
               errors: Optional[list] = None) -> list:
    """Classify, score and rank every artefact in place.

    Args:
        artefacts: the raw inventory from the detectors.
        policy:    a policy dict/object (see the module docstring); ``None``
                   uses :data:`DEFAULT_POLICY`.
        now_year:  the reference year; defaults to the current calendar year.
        errors:    optional list that per-artefact failures are appended to,
                   so a bad artefact degrades instead of aborting the scan.

    Returns:
        The same list object, mutated and sorted by (severity, -score).

    Fields written on each artefact: ``threat``, ``threat_reason``, ``severity``,
    ``score``, ``data_class``, ``x_years``, ``y_years``, ``mosca_act_now``,
    ``mosca_shortfall``, ``criticality``. Also written, for the report:
    ``z_year``, ``mosca_deadline_year``, ``mosca_statement``, ``policy_rule``,
    ``policy_name``, ``kb_citation``.
    """
    items = list(artefacts) if artefacts is not None else []
    view = _PolicyView(policy)
    year = int(now_year) if now_year else datetime.date.today().year

    for artefact in items:
        try:
            _risk_one(artefact, view, year)
        except Exception as exc:  # a single bad artefact must never kill a scan
            message = (f"risk engine failed on artefact "
                       f"'{getattr(artefact, 'name', '<unnamed>')}': {exc.__class__.__name__}: {exc}")
            if errors is not None:
                errors.append(message)
            _set_fallback(artefact, view, year, message)

    items.sort(key=lambda a: (
        _severity_sort_key(getattr(a, "severity", Severity.LOW)),
        -float(getattr(a, "score", 0.0) or 0.0),
        -len(getattr(a, "occurrences", []) or []),
        str(getattr(a, "name", "")),
    ))

    if isinstance(artefacts, list):
        artefacts[:] = items
        return artefacts
    return items


def _risk_one(artefact: Any, view: _PolicyView, year: int) -> None:
    family = getattr(artefact, "family", None) or getattr(artefact, "name", "")
    params = getattr(artefact, "params", None)

    # 1. classify
    threat, reason = kb.classify(family, params)

    # 2. locate in the organisation
    path = _first_path(artefact)
    rule = view.match(path)
    data_class = str((rule or {}).get("data_class") or view.default_data_class).lower()
    criticality = str((rule or {}).get("criticality") or view.default_criticality).lower()
    if view.escalate_key_material and str(getattr(artefact, "kind", "")).lower() in ("key", "certificate"):
        criticality = _bump(criticality)

    x_years = view.x_years_for(data_class, rule)
    y_years = view.y_years

    # 3. Mosca
    detail = mosca_detail(x_years, y_years, view.z_year, year)

    # 4 + 5. score and severity
    severity = _severity_for(threat, detail.act_now)
    score = score_artefact(threat, criticality, detail.act_now, detail.shortfall_years,
                           x_years, y_years, view)
    # A quantum-safe or PQC artefact is inventory, not a finding.
    if severity is Severity.NONE:
        score = min(score, 5.0)

    artefact.threat = threat
    artefact.threat_reason = reason
    artefact.severity = severity
    artefact.score = score
    artefact.data_class = data_class
    artefact.x_years = x_years
    artefact.y_years = y_years
    artefact.mosca_act_now = detail.act_now
    artefact.mosca_shortfall = detail.shortfall_years
    artefact.criticality = criticality

    # Extra provenance for the report / CBOM - harmless if the model ignores it.
    artefact.z_year = view.z_year
    artefact.mosca_deadline_year = detail.deadline_year
    artefact.mosca_statement = detail.statement
    artefact.policy_rule = (rule or {}).get("glob", "")
    artefact.policy_name = view.name
    artefact.kb_citation = kb.citation(family, params)
    if not getattr(artefact, "name", ""):
        artefact.name = kb.canonical_name(family, params)


def _set_fallback(artefact: Any, view: _PolicyView, year: int, message: str) -> None:
    """Give a broken artefact honest, conservative fields instead of dropping it."""
    try:
        artefact.threat = Threat.UNKNOWN
        artefact.threat_reason = message
        artefact.severity = Severity.LOW
        artefact.score = 0.0
        artefact.data_class = view.default_data_class
        artefact.x_years = view.default_x
        artefact.y_years = view.y_years
        artefact.mosca_act_now = False
        artefact.mosca_shortfall = 0
        artefact.criticality = view.default_criticality
        artefact.z_year = view.z_year
        artefact.policy_name = view.name
    except Exception:  # pragma: no cover - artefact is beyond saving
        pass


def summarize(artefacts: Iterable[Any]) -> dict[str, Any]:
    """Counts by severity and threat, plus the headline numbers for the dashboard."""
    sev_counts = {s.value: 0 for s in _SEVERITY_ORDER}
    threat_counts = {t.value: 0 for t in Threat}
    act_now = 0
    total_score = 0.0
    worst = 0.0
    items = list(artefacts or [])
    for a in items:
        sev = getattr(a, "severity", None)
        sev_key = sev.value if isinstance(sev, Severity) else str(sev or Severity.LOW.value)
        sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1
        th = getattr(a, "threat", None)
        th_key = th.value if isinstance(th, Threat) else str(th or Threat.UNKNOWN.value)
        threat_counts[th_key] = threat_counts.get(th_key, 0) + 1
        if getattr(a, "mosca_act_now", False):
            act_now += 1
        score = float(getattr(a, "score", 0.0) or 0.0)
        total_score += score
        worst = max(worst, score)
    return {
        "total_artefacts": len(items),
        "by_severity": sev_counts,
        "by_threat": threat_counts,
        "act_now_count": act_now,
        "highest_score": round(worst, 2),
        "mean_score": round(total_score / len(items), 2) if items else 0.0,
        "quantum_vulnerable": threat_counts.get(Threat.SHOR_BROKEN.value, 0)
                              + threat_counts.get(Threat.LEGACY_BROKEN.value, 0)
                              + threat_counts.get(Threat.GROVER_WEAKENED.value, 0),
    }
