"""
ECDAT - CI gate.

Turns a scan result into a process exit code and a compact, copy-pasteable
summary for a build log. The gate is the difference between an inventory tool
and a control: once ECDAT runs in CI, a new RSA-1024 key cannot enter the
repository without a human either fixing it or writing a dated, reasoned waiver
into the policy file.

Exit codes
----------
0  pass - nothing at or above the threshold
1  fail - blocking findings (or a per-severity budget exceeded)
2  error - the scan itself reported errors and the policy says that blocks

Design notes
------------
* Works on a ``ScanResult`` object *or* on the plain dict produced by
  ``ScanResult.to_dict()`` - CI usually reads back a ``report.json``.
* **The policy owns the threshold.** ``fail_on`` uses an ``_UNSET`` sentinel, so
  "not supplied" (consult ``gate.fail_on`` in the policy) is distinguishable
  from an explicit ``None`` (disable the gate, report only). Previously the
  signature defaulted to a real ``Severity``, which parsed successfully and so
  never reached the policy lookup - a policy saying ``fail_on: critical`` still
  failed builds at ``high``.
* **One implementation of the decision.** When the supplied policy exposes
  ``gate_should_fail()``, ``min_report_severity()`` or ``fail_on_scan_errors()``
  those are used directly rather than reimplemented here, so the two cannot
  drift. An explicit ``fail_on`` argument (a ``--fail-on`` flag) always wins over
  the policy.
* **Path globs are path globs.** ``ignore_paths`` entries such as
  ``**/node_modules/**`` are matched with real ``**`` semantics, via
  ``Policy.is_ignored`` when available. Bare ``fnmatch`` silently failed to
  exclude *top-level* vendored directories while excluding nested ones.
* Waivers are explicit, matched narrowly and expire. An expired waiver blocks
  again and says so in the summary, which is the whole point of an expiry.
* Artefacts with no severity (risk engine not run) never silently pass: they are
  counted and called out as unscored.

Severity ordering comes from the single shared table
``app.engine.models.SEVERITY_RANK``, whose documented direction is
**higher rank == more severe** (``critical`` is the maximum). There is no local
mirror and no direction guard.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from typing import Any, Optional

from .models import SEVERITY_RANK, Severity

__all__ = [
    "evaluate", "format_summary", "main",
    "EXIT_PASS", "EXIT_FAIL", "EXIT_ERROR",
]

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2

#: Sentinel meaning "caller did not supply a threshold - ask the policy".
#: An explicit ``None`` means "disable the gate entirely".
_UNSET: Any = object()

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE,
)


# --------------------------------------------------------------------------- #
# tolerant accessors (object or dict)
# --------------------------------------------------------------------------- #
def _get(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        value = obj.get(name, default)
    else:
        value = getattr(obj, name, default)
    return default if value is None else value


def _policy_get(policy: Any, *path: str, default: Any = None) -> Any:
    """Walk a nested policy (dict, object, or Policy with a .data mapping)."""
    roots: list[Any] = [policy]
    data = getattr(policy, "data", None)
    if isinstance(data, dict):
        roots.append(data)

    for root in roots:
        node: Any = root
        ok = True
        for part in path:
            if node is None:
                ok = False
                break
            if isinstance(node, dict):
                if part not in node:
                    ok = False
                    break
                node = node[part]
            else:
                if not hasattr(node, part):
                    ok = False
                    break
                node = getattr(node, part)
        if ok and node is not None and not callable(node):
            return node
    return default


def _as_severity(value: Any) -> Optional[Severity]:
    if value is None or value == "":
        return None
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().lower())
    except (ValueError, TypeError):
        return None


def _rank(severity: Any) -> int:
    """Rank through the shared table; unset/unknown ranks below everything.

    ``SEVERITY_RANK`` may be keyed by ``Severity`` members or by their string
    values, and ``Enum.__hash__`` is not the string hash, so both are probed.
    """
    sev = _as_severity(severity)
    if sev is None:
        return -1
    for candidate in (sev, sev.value, str(sev.value).lower()):
        try:
            if candidate in SEVERITY_RANK:
                return int(SEVERITY_RANK[candidate])
        except TypeError:
            continue
    return 0


def _posix(path: str) -> str:
    return str(path or "").replace(os.sep, "/")


def _today() -> _dt.date:
    return _dt.date.today()


# --------------------------------------------------------------------------- #
# path globbing with real ** semantics
# --------------------------------------------------------------------------- #
def _compile_glob(pattern: str) -> "re.Pattern[str]":
    """Translate a path glob to a regex.

    ``**/`` matches zero or more leading path segments, a trailing ``/**``
    matches everything below the directory, ``*`` does not cross ``/`` and ``?``
    matches a single non-separator character. This is the semantics
    ``app.engine.policy`` documents; ``fnmatch`` does not implement it, which is
    why ``**/node_modules/**`` never matched a top-level ``node_modules/``.
    """
    pattern = _posix(pattern)
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                if pattern.startswith("**/", index):
                    out.append("(?:[^/]+/)*")
                    index += 3
                    continue
                if index + 2 >= length:            # trailing "**"
                    out.append(".*")
                    index += 2
                    continue
                out.append(".*")
                index += 2
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        out.append(re.escape(char))
        index += 1
    body = "".join(out)
    # A trailing "/**" should also match the directory itself.
    if body.endswith("/.*"):
        body = body[:-3] + "(?:/.*)?"
    return re.compile(rf"^{body}$")


_GLOB_CACHE: dict[str, "re.Pattern[str]"] = {}


def _glob_match(path: str, pattern: str) -> bool:
    compiled = _GLOB_CACHE.get(pattern)
    if compiled is None:
        try:
            compiled = _compile_glob(pattern)
        except re.error:
            return False
        _GLOB_CACHE[pattern] = compiled
    candidate = _posix(path)
    if compiled.match(candidate):
        return True
    # A bare name pattern ("node_modules", "*.pem") matches any path component
    # or the basename, which is what a user writing that entry means.
    if "/" not in pattern:
        segments = [s for s in candidate.split("/") if s]
        return any(compiled.match(segment) for segment in segments)
    return False


def _ignored_globs(policy: Any) -> list[str]:
    globs = (_policy_get(policy, "gate", "ignore_paths")
             or _policy_get(policy, "ignore_paths")
             or _policy_get(policy, "exclude")
             or [])
    if isinstance(globs, str):
        globs = [globs]
    if not isinstance(globs, (list, tuple, set)):
        return []
    return [str(g) for g in globs if str(g)]


def _path_ignored(path: str, globs: list[str], policy: Any = None) -> bool:
    """Prefer the policy's own matcher; fall back to the local `**`-aware one."""
    candidate = _posix(path)
    if not candidate:
        return False
    is_ignored = getattr(policy, "is_ignored", None)
    if callable(is_ignored):
        try:
            return bool(is_ignored(candidate))
        except Exception:
            pass
    return any(_glob_match(candidate, glob) for glob in globs)


# --------------------------------------------------------------------------- #
# policy pieces
# --------------------------------------------------------------------------- #
def _call_policy(policy: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    """Call an accessor on a Policy object if it has one; else return None."""
    method = getattr(policy, name, None)
    if not callable(method):
        return None
    try:
        return method(*args, **kwargs)
    except TypeError:
        try:
            return method(*args)
        except Exception:
            return None
    except Exception:
        return None


def _policy_should_fail(policy: Any, severity: Any, act_now: bool) -> Optional[bool]:
    """Delegate the decision to ``Policy.gate_should_fail`` when it exists."""
    method = getattr(policy, "gate_should_fail", None)
    if not callable(method):
        return None
    attempts = (
        lambda: method(severity, mosca_act_now=act_now),
        lambda: method(severity, act_now),
        lambda: method(severity),
    )
    for attempt in attempts:
        try:
            return bool(attempt())
        except TypeError:
            continue
        except Exception:
            return None
    return None


def _fail_on_scan_errors(policy: Any) -> bool:
    value = _call_policy(policy, "fail_on_scan_errors")
    if value is None:
        value = _policy_get(policy, "gate", "fail_on_scan_errors", default=False)
    return bool(value)


def _fail_on_mosca_act_now(policy: Any) -> bool:
    value = _call_policy(policy, "fail_on_mosca_act_now")
    if value is None:
        value = _policy_get(policy, "gate", "fail_on_mosca_act_now", default=False)
    return bool(value)


def _min_report_severity(policy: Any) -> Optional[Severity]:
    value = _call_policy(policy, "min_report_severity")
    if value is None:
        value = _policy_get(policy, "gate", "min_report_severity")
    return _as_severity(value)


def _waivers(policy: Any) -> list[dict]:
    raw = (_policy_get(policy, "waivers")
           or _policy_get(policy, "gate", "waivers") or [])
    out: list[dict] = []
    if isinstance(raw, dict):
        raw = [dict(value, key=key) for key, value in raw.items()]
    if not isinstance(raw, (list, tuple)):
        return out
    for item in raw:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str):
            out.append({"key": item})
    return out


def _budgets(policy: Any) -> dict[Severity, int]:
    """Per-severity budgets, e.g. gate.max_critical: 0."""
    budgets: dict[Severity, int] = {}
    for severity in _SEVERITY_ORDER:
        for key in (f"max_{severity.value}", f"max_{severity.value}s"):
            value = _policy_get(policy, "gate", key)
            if value is None:
                value = _policy_get(policy, key)
            if value is None:
                continue
            try:
                budgets[severity] = int(value)
            except (TypeError, ValueError):
                continue
            break
    return budgets


# --------------------------------------------------------------------------- #
# artefact helpers
# --------------------------------------------------------------------------- #
def _artefact_key(artefact: Any) -> str:
    if isinstance(artefact, dict):
        params = artefact.get("params") or {}
        return (f"{artefact.get('family')}|{params.get('key_size')}|"
                f"{params.get('curve')}|{params.get('mode')}")
    try:
        return artefact.key()
    except Exception:
        return str(_get(artefact, "name", ""))


def _occurrences(artefact: Any) -> list[Any]:
    occurrences = _get(artefact, "occurrences", []) or []
    return list(occurrences) if isinstance(occurrences, (list, tuple)) else []


def _params_extra(artefact: Any) -> dict:
    params = _get(artefact, "params", None)
    extra = params.get("extra") if isinstance(params, dict) else getattr(params, "extra", None)
    return extra if isinstance(extra, dict) else {}


def _mosca_act_now(artefact: Any) -> bool:
    """The risk engine may record this on the artefact or in params.extra."""
    value = _get(artefact, "mosca_act_now", None)
    if value is None:
        value = _params_extra(artefact).get("mosca_act_now")
    return bool(value)


def _relative(path: str, target: Any) -> str:
    """Show a repo-relative path when we can; CI logs are narrow."""
    path = _posix(path)
    target = _posix(str(target or ""))
    if target and path.startswith(target.rstrip("/") + "/"):
        return path[len(target.rstrip("/")) + 1:]
    return path


def _first_location(artefact: Any, target: Any = None) -> str:
    for occ in _occurrences(artefact):
        path = _relative(_get(occ, "file", ""), target)
        line = _get(occ, "line", None)
        if path:
            return f"{path}:{line}" if isinstance(line, int) else path
    return "(no location)"


def _match_waiver(artefact: Any, waiver: dict) -> bool:
    """Every field present in the waiver must match - waivers are narrow by design."""
    matched_any = False
    if waiver.get("key"):
        if str(waiver["key"]) != _artefact_key(artefact):
            return False
        matched_any = True
    if waiver.get("name"):
        if str(waiver["name"]) != str(_get(artefact, "name", "")):
            return False
        matched_any = True
    if waiver.get("family"):
        if str(waiver["family"]).upper() != str(_get(artefact, "family", "")).upper():
            return False
        matched_any = True
    if waiver.get("file"):
        pattern = str(waiver["file"])
        files = [_posix(_get(o, "file", "")) for o in _occurrences(artefact)]
        if not files or not all(_glob_match(f, pattern) for f in files):
            return False
        matched_any = True
    return matched_any


def _waiver_expired(waiver: dict) -> bool:
    expires = waiver.get("expires") or waiver.get("expiry")
    if not expires:
        return False
    text = str(expires).strip()[:10]
    try:
        return _dt.date.fromisoformat(text) < _today()
    except ValueError:
        # An unparseable expiry is treated as expired: fail closed.
        return True


# --------------------------------------------------------------------------- #
# evaluation
# --------------------------------------------------------------------------- #
def evaluate(scan_result: Any, policy: Any = None, fail_on: Any = _UNSET) -> tuple[int, str]:
    """Decide pass/fail for a scan. Returns ``(exit_code, summary)``.

    ``fail_on`` resolution:

    * not supplied (``_UNSET``) - use the policy's ``gate.fail_on``, defaulting
      to ``high`` when the policy is silent or absent;
    * explicit ``None`` - the gate is disabled (report only, always exit 0, and
      per-severity budgets are skipped too);
    * an explicit ``Severity`` or equivalent string - that value wins over the
      policy, which is what a ``--fail-on`` flag must do.

    When the policy exposes ``gate_should_fail()`` and no explicit threshold was
    given, the per-artefact decision is delegated to it so gate.py and policy.py
    cannot disagree.
    """
    explicit = fail_on is not _UNSET
    if not explicit:
        threshold: Optional[Severity] = (
            _as_severity(_policy_get(policy, "gate", "fail_on")) or Severity.HIGH)
    elif fail_on is None:
        threshold = None
    else:
        threshold = (_as_severity(fail_on)
                     or _as_severity(_policy_get(policy, "gate", "fail_on"))
                     or Severity.HIGH)

    delegate = (not explicit) and callable(getattr(policy, "gate_should_fail", None))

    artefacts = list(_get(scan_result, "artefacts", []) or [])
    ignore_globs = _ignored_globs(policy)
    waivers = _waivers(policy)
    budgets = _budgets(policy)
    min_report = _min_report_severity(policy)
    mosca_blocks = _fail_on_mosca_act_now(policy)

    counts: dict[Severity, int] = {s: 0 for s in _SEVERITY_ORDER}
    unscored = 0
    ignored = 0
    below_report = 0
    blocking: list[Any] = []
    mosca_blocking: list[Any] = []
    waived: list[tuple[Any, dict]] = []
    expired: list[tuple[Any, dict]] = []

    for artefact in artefacts:
        occurrences = _occurrences(artefact)
        if ignore_globs and occurrences and all(
                _path_ignored(_get(o, "file", ""), ignore_globs, policy) for o in occurrences):
            ignored += 1
            continue

        severity = _as_severity(_get(artefact, "severity", None))
        act_now = _mosca_act_now(artefact)

        # gate.min_report_severity trims the noise floor of the *report*; it
        # never hides something that would otherwise block.
        # _rank is 0-is-most-severe, so an artefact is BELOW the reporting floor
        # when its rank is GREATER than the floor's. The comparison was inverted,
        # which silently discarded every critical finding.
        if (min_report is not None and severity is not None
                and _rank(severity) > _rank(min_report)
                and not (mosca_blocks and act_now)):
            below_report += 1
            continue

        if severity is None:
            unscored += 1
        else:
            counts[severity] = counts.get(severity, 0) + 1

        if threshold is None:
            continue

        if mosca_blocks and act_now:
            should_fail = True
        elif delegate:
            delegated = _policy_should_fail(policy, severity, act_now)
            should_fail = (delegated if delegated is not None
                           else (severity is not None and _rank(severity) >= _rank(threshold)))
        else:
            should_fail = severity is not None and _rank(severity) >= _rank(threshold)

        if not should_fail:
            continue

        applicable = [w for w in waivers if _match_waiver(artefact, w)]
        active = [w for w in applicable if not _waiver_expired(w)]
        if active:
            waived.append((artefact, active[0]))
            continue
        if applicable:
            expired.append((artefact, applicable[0]))
        blocking.append(artefact)
        if mosca_blocks and act_now and (
                severity is None or _rank(severity) < _rank(threshold)):
            mosca_blocking.append(artefact)

    over_budget: list[tuple[Severity, int, int]] = []
    if threshold is not None:  # fail_on=None disables the gate entirely
        for severity_key, allowed in budgets.items():
            actual = counts.get(severity_key, 0)
            if actual > allowed:
                over_budget.append((severity_key, actual, allowed))

    scan_errors = list(_get(scan_result, "errors", []) or [])
    errors_block = _fail_on_scan_errors(policy)

    blocking.sort(key=lambda a: (-_rank(_get(a, "severity", None)),
                                 -float(_get(a, "score", 0) or 0),
                                 str(_get(a, "name", ""))))

    if blocking or over_budget:
        exit_code = EXIT_FAIL
    elif scan_errors and errors_block:
        exit_code = EXIT_ERROR
    else:
        exit_code = EXIT_PASS

    summary = format_summary(
        scan_result=scan_result, exit_code=exit_code, threshold=threshold,
        counts=counts, unscored=unscored, ignored=ignored, below_report=below_report,
        min_report=min_report, blocking=blocking, mosca_blocking=mosca_blocking,
        waived=waived, expired=expired, over_budget=over_budget,
        scan_errors=scan_errors, errors_block=errors_block, delegated=delegate,
    )
    return exit_code, summary


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def _truncate(text: str, width: int) -> str:
    text = str(text or "")
    return text if len(text) <= width else text[: width - 1] + "~"


def _truncate_left(text: str, width: int) -> str:
    """Drop leading path components, never the file name and line number."""
    text = str(text or "")
    return text if len(text) <= width else "~" + text[-(width - 1):]


def format_summary(*, scan_result: Any, exit_code: int, threshold: Optional[Severity],
                   counts: dict, unscored: int, ignored: int, blocking: list,
                   waived: list, expired: list, over_budget: list,
                   scan_errors: list, errors_block: bool,
                   below_report: int = 0, min_report: Optional[Severity] = None,
                   mosca_blocking: Optional[list] = None, delegated: bool = False,
                   max_offenders: int = 10) -> str:
    """Render the CI log block. Plain ASCII, stable column widths, no colour."""
    mosca_blocking = mosca_blocking or []
    verdict = {EXIT_PASS: "PASS", EXIT_FAIL: "FAIL", EXIT_ERROR: "ERROR"}.get(
        exit_code, "FAIL")
    threshold_text = threshold.value if threshold else "disabled (report only)"

    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"ECDAT quantum-readiness gate: {verdict}   "
                 f"(fail_on = {threshold_text})")
    lines.append("=" * 72)

    target = _get(scan_result, "target", "(unknown)")
    files_scanned = _get(scan_result, "files_scanned", 0)
    policy_name = _get(scan_result, "policy_name", "(none)")
    total = len(list(_get(scan_result, "artefacts", []) or []))
    lines.append(f"target        : {target}")
    lines.append(f"files scanned : {files_scanned}    artefacts: {total}    "
                 f"policy: {policy_name}")
    if delegated:
        lines.append("decision      : delegated to policy.gate_should_fail()")
    lines.append("")

    lines.append("severity   count   blocking")
    for severity in _SEVERITY_ORDER:
        count = counts.get(severity, 0)
        blocks = (threshold is not None and _rank(severity) >= _rank(threshold))
        marker = str(sum(1 for a in blocking
                         if _as_severity(_get(a, "severity", None)) is severity)) \
            if blocks else "-"
        lines.append(f"{severity.value:<10} {count:>5}   {marker:>8}")
    if unscored:
        lines.append(f"{'unscored':<10} {unscored:>5}   {'-':>8}   "
                     "(risk engine did not score these)")
    if ignored:
        lines.append(f"{'ignored':<10} {ignored:>5}   {'-':>8}   "
                     "(all occurrences matched policy ignore_paths)")
    if below_report:
        floor = min_report.value if min_report else "?"
        lines.append(f"{'below':<10} {below_report:>5}   {'-':>8}   "
                     f"(under gate.min_report_severity = {floor})")
    lines.append("")

    if blocking:
        shown = blocking[:max_offenders]
        lines.append(f"top offenders ({len(blocking)} blocking, showing {len(shown)}):")
        for artefact in shown:
            severity = _as_severity(_get(artefact, "severity", None))
            sev_text = severity.value if severity else "?"
            name = _truncate(_get(artefact, "name", "?"), 22)
            location = _truncate_left(_first_location(artefact, target), 40)
            recommendation = _truncate(
                _get(artefact, "recommendation", "") or "(recommender not run)", 34)
            autofix = " [autofix]" if _get(artefact, "fix_patch", "") else ""
            mosca = " [mosca]" if _mosca_act_now(artefact) else ""
            occ_count = len(_occurrences(artefact))
            lines.append(f"  {sev_text:<8} {name:<22} {location:<40} "
                         f"-> {recommendation}{autofix}{mosca} ({occ_count} site(s))")
        if len(blocking) > len(shown):
            lines.append(f"  ... and {len(blocking) - len(shown)} more")
        lines.append("")

    if mosca_blocking:
        lines.append(f"blocked by gate.fail_on_mosca_act_now ({len(mosca_blocking)}) - "
                     "below the severity threshold, but Mosca says migrate now:")
        for artefact in mosca_blocking[:max_offenders]:
            lines.append(f"  {_truncate(_get(artefact, 'name', '?'), 24):<24} "
                         f"shortfall: {_get(artefact, 'mosca_shortfall', 'n/a')}")
        lines.append("")

    if waived:
        lines.append(f"waived ({len(waived)}) - accepted risk, recorded in policy:")
        for artefact, waiver in waived[:max_offenders]:
            reason = _truncate(waiver.get("reason", "no reason recorded"), 46)
            expires = waiver.get("expires") or waiver.get("expiry") or "no expiry"
            lines.append(f"  {_truncate(_get(artefact, 'name', '?'), 24):<24} "
                         f"{reason:<46} expires: {expires}")
        lines.append("")

    if expired:
        lines.append(f"EXPIRED WAIVERS ({len(expired)}) - these no longer suppress anything:")
        for artefact, waiver in expired[:max_offenders]:
            expires = waiver.get("expires") or waiver.get("expiry") or "unparseable"
            lines.append(f"  {_truncate(_get(artefact, 'name', '?'), 24):<24} "
                         f"expired {expires}")
        lines.append("")

    for severity, actual, allowed in over_budget:
        lines.append(f"budget exceeded: {actual} {severity.value} artefact(s), "
                     f"policy allows {allowed}")
    if over_budget:
        lines.append("")

    if scan_errors:
        label = "scan errors" if errors_block else "scan warnings (non-blocking)"
        lines.append(f"{label} ({len(scan_errors)}):")
        for error in scan_errors[:5]:
            lines.append(f"  - {_truncate(error, 68)}")
        if len(scan_errors) > 5:
            lines.append(f"  ... and {len(scan_errors) - 5} more")
        lines.append("")

    autofixable = sum(1 for a in blocking if _get(a, "fix_patch", ""))
    if exit_code == EXIT_PASS:
        lines.append("Result: PASS - no artefact at or above the threshold. "
                     "Inventory still recorded in the CBOM.")
    elif exit_code == EXIT_ERROR:
        lines.append("Result: ERROR - the scan reported errors and policy "
                     "gate.fail_on_scan_errors is true.")
    else:
        lines.append(f"Result: FAIL - {len(blocking)} artefact(s) at or above "
                     f"'{threshold_text}'.")
        if autofixable:
            lines.append(f"        {autofixable} of them ship a mechanical patch "
                         "(ecdat fix --apply) - review it before merging.")
        lines.append("        Remediate, or add a dated waiver with a reason to the "
                     "policy file.")
    lines.append("=" * 72)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI: ecdat-gate report.json [policy.json] [--fail-on high]
# --------------------------------------------------------------------------- #
_USAGE = ("usage: gate.py <report.json> [policy.json] "
          "[--fail-on critical|high|medium|low|none|off]")


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Left as the sentinel unless --fail-on is actually passed, so the policy's
    # gate.fail_on is honoured by default.
    fail_on: Any = _UNSET
    positional: list[str] = []

    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--fail-on" and index + 1 < len(argv):
            fail_on = argv[index + 1]
            index += 2
            continue
        if argument.startswith("--fail-on="):
            fail_on = argument.split("=", 1)[1]
            index += 1
            continue
        if argument in ("-h", "--help"):
            print(_USAGE)
            return EXIT_PASS
        positional.append(argument)
        index += 1

    # "off"/"none-gate" spellings mean "report only".
    if isinstance(fail_on, str) and fail_on.strip().lower() in ("off", "disabled", "never"):
        fail_on = None

    if not positional:
        print(_USAGE, file=sys.stderr)
        return EXIT_ERROR

    try:
        report = _load_json(positional[0])
    except (OSError, ValueError) as error:
        print(f"ECDAT gate: cannot read scan report: {error}", file=sys.stderr)
        return EXIT_ERROR

    policy: Any = None
    if len(positional) > 1:
        try:
            policy = _load_json(positional[1])
        except (OSError, ValueError) as error:
            print(f"ECDAT gate: cannot read policy (continuing without it): {error}",
                  file=sys.stderr)

    exit_code, summary = evaluate(report, policy, fail_on)
    print(summary)
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
