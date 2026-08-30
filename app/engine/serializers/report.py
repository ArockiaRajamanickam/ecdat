"""Executive Markdown report for an ECDAT scan.

``to_markdown(scan_result, policy)`` produces a report an NTRO reviewer can read
top-to-bottom in two minutes:

1. a header with the target, scan facts and the active policy;
2. the Mosca verdict - the one line that says whether migration must start now;
3. counts by severity;
4. a ranked table (# | Asset | Threat | Severity | Score | Recommendation);
5. per-artefact detail with full provenance (capped at 6 occurrences plus an
   "and N more" line), trade-offs, and the fix patch in a fenced ``diff`` block.

Pure stdlib.  Tolerates missing risk/recommender fields and both object and
``dict`` shapes.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

try:  # normal package import
    from ._common import (
        SEVERITY_ORDER,
        TOOL_NAME,
        TOOL_VERSION,
        artefacts_of,
        display_params,
        engine_extra,
        field,
        iso8601,
        name_of,
        family_of,
        occurrences_of,
        rank_artefacts,
        relative_path,
        score_of,
        severity_counts,
        severity_of,
        threat_of,
        trade_offs_of,
    )
except ImportError:  # pragma: no cover - direct execution / partial tree
    from app.engine.serializers._common import (  # type: ignore[no-redef]
        SEVERITY_ORDER,
        TOOL_NAME,
        TOOL_VERSION,
        artefacts_of,
        display_params,
        engine_extra,
        field,
        iso8601,
        name_of,
        family_of,
        occurrences_of,
        rank_artefacts,
        relative_path,
        score_of,
        severity_counts,
        severity_of,
        threat_of,
        trade_offs_of,
    )

__all__ = ["to_markdown", "MAX_OCCURRENCES_SHOWN"]

#: Provenance lines printed per artefact before collapsing into "and N more".
MAX_OCCURRENCES_SHOWN = 6

_THREAT_LABEL = {
    "shor_broken": "Shor-breakable",
    "legacy_broken": "Already broken (classical)",
    "grover_weakened": "Grover-weakened",
    "quantum_safe": "Quantum-safe (symmetric)",
    "pqc": "Post-quantum algorithm",
    "unknown": "Unclassified",
}

_SEVERITY_BADGE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "NONE",
}


def _badge(severity: str) -> str:
    return _SEVERITY_BADGE.get(severity, str(severity).upper())


def _esc(text: Any) -> str:
    """Make a value safe inside a Markdown table cell."""
    value = str(text if text is not None else "")
    value = value.replace("\\", "\\\\").replace("|", "\\|")
    value = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return " ".join(value.split())


def _trunc(text: Any, limit: int) -> str:
    value = _esc(text)
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _num(value: Any, suffix: str = "") -> str:
    if value in (None, ""):
        return "n/a"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    rendered = f"{number:.0f}" if abs(number - round(number)) < 1e-9 else f"{number:.1f}"
    return f"{rendered}{suffix}"


def _policy_field(policy: Any, *names: Any, default: Any = None) -> Any:
    """Read a value off a policy object, its ``.data`` mapping, or a plain dict.

    A :class:`app.engine.policy.Policy` exposes most values as methods, so a
    callable result is invoked before it is accepted.
    """
    sources: list[Any] = [policy]
    data = getattr(policy, "data", None)
    if isinstance(data, dict):
        sources.append(data)
    for source in sources:
        for name in names:
            value = field(source, name, None)
            if callable(value):
                try:
                    value = value()
                except Exception:
                    value = None
            if value not in (None, "", [], {}):
                return value
    return default


def _resolve_z(policy: Any, artefacts: list[Any]) -> Any:
    """The quantum horizon Z, in whatever form the active policy states it.

    Resolution order, worst-to-best-known-source last:

    1. ``Policy.z_year()`` - the accessor the policy module actually exposes;
    2. ``policy.data['mosca']['Z_quantum_threat_year']`` - the raw YAML key;
    3. the value the risk engine already stamped onto an artefact;
    4. the literal ``z_year`` key used by the risk engine's DEFAULT_POLICY.
    """
    getter = getattr(policy, "z_year", None)
    if callable(getter):
        try:
            value = getter()
            if value not in (None, ""):
                return value
        except Exception:
            pass

    data = getattr(policy, "data", None)
    if not isinstance(data, dict) and isinstance(policy, dict):
        data = policy
    if isinstance(data, dict):
        mosca = data.get("mosca")
        if isinstance(mosca, dict):
            for key in ("Z_quantum_threat_year", "z_quantum_threat_year", "z_year", "z"):
                if mosca.get(key) not in (None, ""):
                    return mosca[key]

    for artefact in artefacts:
        value = engine_extra(artefact, "z_year", None)
        if value not in (None, ""):
            return value

    return _policy_field(policy, "z_year", "z_years", "quantum_years", "threat_years", "z")


def _render_z(value: Any) -> str:
    """Render Z as a calendar year (``2035``) or as a duration (``8 y``)."""
    if value in (None, ""):
        return "n/a"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return _esc(value)
    if number >= 1900:  # a calendar year, as default_policy.yaml states it
        year = int(round(number))
        this_year = _dt.datetime.now(_dt.timezone.utc).year
        remaining = year - this_year
        if remaining > 0:
            return f"{year} (~{remaining} y away)"
        return str(year)
    return _num(number, " y")


def _mosca_verdict(artefacts: list[Any], policy: Any) -> list[str]:
    """The headline paragraph: does X + Y exceed Z for anything we found?"""
    z_value = _resolve_z(policy, artefacts)
    act_now = [a for a in artefacts if field(a, "mosca_act_now", False)]
    shortfalls = [
        float(field(a, "mosca_shortfall", 0) or 0)
        for a in artefacts
        if field(a, "mosca_shortfall", None) not in (None, "")
    ]
    worst = max(shortfalls) if shortfalls else None
    worst_asset = None
    if act_now:
        worst_asset = max(act_now, key=lambda a: float(field(a, "mosca_shortfall", 0) or 0))
    elif artefacts:
        worst_asset = artefacts[0]

    lines = ["## Mosca verdict", ""]
    if worst_asset is not None:
        x = _num(field(worst_asset, "x_years", None), " y")
        y = _num(field(worst_asset, "y_years", None), " y")
        lines.append(
            f"> **X + Y vs Z** - worst asset `{_esc(name_of(worst_asset))}`: "
            f"shelf life X = {x}, migration time Y = {y}, "
            f"quantum horizon Z = {_render_z(z_value)}."
        )
        statement = engine_extra(worst_asset, "mosca_statement", "")
        if statement:
            lines.append(">")
            lines.append(f"> {_esc(statement)}")
    else:
        lines.append(f"> Quantum horizon Z = {_render_z(z_value)}.")
    if act_now:
        lines.append(">")
        lines.append(
            f"> **ACT NOW.** Mosca's inequality holds for **{len(act_now)} of "
            f"{len(artefacts)}** assets"
            + (f" - worst shortfall **{_num(worst, ' years')}**." if worst is not None else ".")
        )
        lines.append(">")
        lines.append(
            "> Data protected by these assets is already harvestable today and will be "
            "readable once a cryptographically relevant quantum computer exists. "
            "Migration must begin before the shortfall closes, not after."
        )
    elif artefacts:
        lines.append(">")
        lines.append(
            f"> **No Mosca breach.** None of the {len(artefacts)} discovered assets have "
            "X + Y > Z under the active policy. Keep the inventory under continuous scan; "
            "the horizon Z moves, the inventory moves faster."
        )
    else:
        lines.append(">")
        lines.append("> No cryptographic assets were discovered in this target.")
    lines.append("")
    return lines


def _summary_table(artefacts: list[Any]) -> list[str]:
    counts = severity_counts(artefacts)
    total = len(artefacts)
    lines = [
        "## Risk summary",
        "",
        "| Severity | Assets | Share |",
        "| --- | ---: | ---: |",
    ]
    for name in SEVERITY_ORDER:
        count = counts.get(name, 0)
        share = f"{(count / total * 100):.0f}%" if total else "0%"
        lines.append(f"| {_badge(name)} | {count} | {share} |")
    lines.append(f"| **Total** | **{total}** | **100%** |")
    lines.append("")

    threats: dict[str, int] = {}
    for artefact in artefacts:
        key = threat_of(artefact)
        threats[key] = threats.get(key, 0) + 1
    if threats:
        lines.append("**Quantum threat classes:** " + ", ".join(
            f"{_THREAT_LABEL.get(name, name)} ({count})"
            for name, count in sorted(threats.items(), key=lambda kv: -kv[1])
        ))
        lines.append("")
    occurrences = sum(len(occurrences_of(a)) for a in artefacts)
    files = len({
        str(field(occ, "file", ""))
        for a in artefacts
        for occ in occurrences_of(a)
        if field(occ, "file", "")
    })
    lines.append(
        f"**Provenance:** {occurrences} occurrence(s) across {files} file(s) with "
        "file + line evidence for every finding."
    )
    lines.append("")
    return lines


def _ranked_table(artefacts: list[Any]) -> list[str]:
    lines = [
        "## Ranked findings",
        "",
        "| # | Asset | Threat | Severity | Score | Recommendation |",
        "| ---: | --- | --- | --- | ---: | --- |",
    ]
    if not artefacts:
        lines.append("| - | _no cryptographic assets discovered_ | - | - | - | - |")
        lines.append("")
        return lines
    for index, artefact in enumerate(artefacts, start=1):
        threat = _THREAT_LABEL.get(threat_of(artefact), threat_of(artefact))
        severity = _badge(severity_of(artefact))
        recommendation = field(artefact, "recommendation", "") or "-"
        flag = " **!**" if field(artefact, "mosca_act_now", False) else ""
        lines.append(
            f"| {index} | `{_esc(name_of(artefact))}`{flag} "
            f"| {_esc(threat)} | {severity} | {score_of(artefact):.1f} "
            f"| {_trunc(recommendation, 70)} |"
        )
    lines.append("")
    lines.append("`!` marks assets where Mosca's inequality already holds.")
    lines.append("")
    return lines


def _occurrence_lines(artefact: Any, root: Any) -> list[str]:
    occurrences = occurrences_of(artefact)
    if not occurrences:
        return ["- _no provenance recorded_"]
    lines: list[str] = []
    for occ in occurrences[:MAX_OCCURRENCES_SHOWN]:
        path = relative_path(field(occ, "file", ""), root) or "unknown"
        line_no = field(occ, "line", None)
        where = f"`{_esc(path)}:{line_no}`" if line_no not in (None, "") else f"`{_esc(path)}`"
        evidence = _trunc(field(occ, "evidence", ""), 120)
        detector = _esc(field(occ, "detector", ""))
        confidence = _esc(field(occ, "confidence", ""))
        tail = ", ".join(part for part in (
            f"detector: {detector}" if detector else "",
            f"confidence: {confidence}" if confidence else "",
        ) if part)
        entry = f"- {where}"
        if evidence:
            entry += f" - `{evidence}`"
        if tail:
            entry += f"  _({tail})_"
        lines.append(entry)
    remaining = len(occurrences) - MAX_OCCURRENCES_SHOWN
    if remaining > 0:
        lines.append(f"- _and {remaining} more occurrence(s)_")
    return lines


def _detail_section(index: int, artefact: Any, root: Any) -> list[str]:
    name = name_of(artefact)
    severity = _badge(severity_of(artefact))
    lines = [
        f"### {index}. {name} - {severity} (score {score_of(artefact):.1f})",
        "",
    ]

    facts = [
        f"- **Family / kind:** {_esc(family_of(artefact))} / "
        f"{_esc(field(artefact, 'kind', 'algorithm'))}",
    ]
    params = display_params(artefact)
    if params:
        facts.append(f"- **Parameters:** `{_esc(params)}`")
    threat = _THREAT_LABEL.get(threat_of(artefact), threat_of(artefact))
    reason = field(artefact, "threat_reason", "")
    facts.append(
        f"- **Quantum threat:** {_esc(threat)}"
        + (f" - {_esc(reason)}" if reason else "")
    )
    mosca_bits = []
    for label, key in (("X (shelf life)", "x_years"), ("Y (migration)", "y_years")):
        value = field(artefact, key, None)
        if value not in (None, ""):
            mosca_bits.append(f"{label} = {_num(value, ' y')}")
    z_value = engine_extra(artefact, "z_year", None)
    if z_value not in (None, ""):
        mosca_bits.append(f"Z (horizon) = {_render_z(z_value)}")
    shortfall = field(artefact, "mosca_shortfall", None)
    if shortfall not in (None, ""):
        mosca_bits.append(f"shortfall = {_num(shortfall, ' y')}")
    if field(artefact, "mosca_act_now", False):
        mosca_bits.append("**act now**")
    if mosca_bits:
        facts.append("- **Mosca:** " + ", ".join(mosca_bits))
    for label, key in (("Data class", "data_class"), ("Criticality", "criticality")):
        value = field(artefact, key, "")
        if value:
            facts.append(f"- **{label}:** {_esc(value)}")
    rule = engine_extra(artefact, "policy_rule", "")
    if rule:
        facts.append(f"- **Policy rule:** `{_esc(rule)}`")
    citation = engine_extra(artefact, "kb_citation", "")
    if citation:
        facts.append(f"- **Citation:** {_esc(citation)}")
    facts.append(f"- **Occurrences:** {len(occurrences_of(artefact))}")
    lines.extend(facts)
    lines.append("")

    recommendation = field(artefact, "recommendation", "")
    if recommendation:
        lines.append(f"**Recommendation - {_esc(recommendation)}**")
        rationale = field(artefact, "rec_rationale", "")
        if rationale:
            lines.append("")
            lines.append(_esc(rationale))
        lines.append("")

    trade_offs = trade_offs_of(artefact)
    if trade_offs:
        lines.append("**Trade-offs**")
        lines.append("")
        for label, text in trade_offs.items():
            lines.append(f"- **{_esc(label)}:** {_esc(text)}")
        lines.append("")

    lines.append("**Provenance**")
    lines.append("")
    lines.extend(_occurrence_lines(artefact, root))
    lines.append("")

    patch = str(field(artefact, "fix_patch", "") or "").strip()
    if patch:
        lines.append("**Suggested fix**")
        lines.append("")
        lines.append("```diff")
        lines.extend(patch.splitlines())
        lines.append("```")
        lines.append("")
    return lines


def to_markdown(scan_result: Any, policy: Any = None) -> str:
    """Render a scan as an executive Markdown report.

    Args:
        scan_result: a ``ScanResult`` (or its ``to_dict()`` form).
        policy: the active policy object/dict; used for the policy name and the
            Mosca ``Z`` horizon.  ``None`` is fine.

    Returns:
        A Markdown document as a single string.
    """
    target = str(field(scan_result, "target", "") or "unknown target")
    artefacts = rank_artefacts(artefacts_of(scan_result))
    errors = list(field(scan_result, "errors", []) or [])
    policy_name = str(
        _policy_field(policy, "name", "policy_name")
        or field(scan_result, "policy_name", "default")
        or "default"
    )

    out: list[str] = [
        "# ECDAT - Cryptographic Discovery & Quantum Risk Report",
        "",
        f"**Target:** `{_esc(target)}`  ",
        f"**Files scanned:** {field(scan_result, 'files_scanned', 0)}  ",
        f"**Assets discovered:** {len(artefacts)}  ",
        f"**Policy:** {_esc(policy_name)}  ",
        f"**Scan window:** {iso8601(field(scan_result, 'started', None))} "
        f"to {iso8601(field(scan_result, 'finished', None))}  ",
        f"**Generated by:** {TOOL_NAME} v{TOOL_VERSION}",
        "",
        "---",
        "",
    ]
    out.extend(_mosca_verdict(artefacts, policy))
    out.extend(_summary_table(artefacts))
    out.extend(_ranked_table(artefacts))

    if artefacts:
        out.append("---")
        out.append("")
        out.append("## Asset detail")
        out.append("")
        for index, artefact in enumerate(artefacts, start=1):
            out.extend(_detail_section(index, artefact, target))

    if errors:
        out.append("---")
        out.append("")
        out.append(f"## Scan errors ({len(errors)})")
        out.append("")
        out.append("These files could not be parsed; their contents are not represented above.")
        out.append("")
        for err in errors[:50]:
            out.append(f"- {_esc(err)}")
        if len(errors) > 50:
            out.append(f"- _and {len(errors) - 50} more_")
        out.append("")

    out.append("---")
    out.append("")
    out.append(
        "_Every finding above carries file and line provenance. "
        "Severity combines quantum threat class with data sensitivity and blast radius; "
        "ranking is by Mosca urgency first, score second._"
    )
    out.append("")
    return "\n".join(out)
