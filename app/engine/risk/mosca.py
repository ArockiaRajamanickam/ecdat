"""
Mosca's inequality: the decision rule for "should we be migrating already?".

    if  X + Y  >  Z   then you are already too late.

    X  how long the data must stay confidential (or a signature trustworthy)
       once it is created - the shelf life.
    Y  how long this organisation's migration takes (rewrite, test, roll out,
       retire the old path).
    Z  how long until a cryptographically relevant quantum computer exists.

Reference: M. Mosca, "Cybersecurity in an era with quantum computers: will we
be ready?", IEEE Security & Privacy 16(5), 2018 (first presented 2015).

ECDAT expresses Z as an absolute calendar year (``z_year``, default 2035, the
year NIST IR 8547 ipd disallows classical public-key algorithms) rather than a
duration, because a policy that says "2035" stays correct as time passes while
one that says "10 years" silently rots::

    years_until_z = z_year - now_year
    shortfall     = (X + Y) - years_until_z
    act_now       = shortfall > 0

``shortfall`` is the headline number: how many years of exposure the
organisation is carrying right now. +4 means data encrypted today will still
need protecting four years after the quantum deadline; a negative shortfall is
slack still in hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["MoscaResult", "mosca", "mosca_detail", "migration_deadline_year"]


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce anything to an int without raising; used so a malformed policy
    downgrades to a default instead of killing a scan."""
    if value is None:
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def mosca(x_years: Any, y_years: Any, z_year: Any, now_year: Any) -> tuple[bool, int]:
    """Evaluate Mosca's inequality.

    Args:
        x_years:  data shelf life in years (X).
        y_years:  migration time in years (Y).
        z_year:   calendar year a CRQC is assumed to arrive (Z as a year).
        now_year: the year the scan is run.

    Returns:
        ``(act_now, shortfall_years)`` where ``shortfall = (X + Y) - (z_year - now_year)``
        and ``act_now`` is ``shortfall > 0``.

    Never raises: non-numeric inputs are coerced, negatives for X and Y are
    clamped to zero (a negative shelf life is meaningless).

    >>> mosca(10, 5, 2035, 2026)          # 15 > 9
    (True, 6)
    >>> mosca(2, 1, 2035, 2026)           # 3 < 9
    (False, -6)
    >>> mosca(9, 0, 2035, 2026)           # exactly on the line, not yet late
    (False, 0)
    """
    x = max(0, _as_int(x_years))
    y = max(0, _as_int(y_years))
    z = _as_int(z_year, 2035)
    now = _as_int(now_year, 2026)

    years_until_z = z - now
    shortfall = (x + y) - years_until_z
    return shortfall > 0, shortfall


@dataclass
class MoscaResult:
    """The full working, so a report can show its arithmetic instead of a verdict."""

    x_years: int
    y_years: int
    z_year: int
    now_year: int
    years_until_z: int
    shortfall_years: int
    act_now: bool
    deadline_year: int          # latest year migration can start and still finish in time
    years_until_deadline: int   # negative once the deadline has passed
    statement: str

    def to_dict(self) -> dict:
        return {
            "x_years": self.x_years,
            "y_years": self.y_years,
            "z_year": self.z_year,
            "now_year": self.now_year,
            "years_until_z": self.years_until_z,
            "shortfall_years": self.shortfall_years,
            "act_now": self.act_now,
            "deadline_year": self.deadline_year,
            "years_until_deadline": self.years_until_deadline,
            "statement": self.statement,
        }


def migration_deadline_year(x_years: Any, y_years: Any, z_year: Any) -> int:
    """The last calendar year migration can *start* and still land before Z.

    ``deadline = z_year - x_years - y_years``
    """
    x = max(0, _as_int(x_years))
    y = max(0, _as_int(y_years))
    return _as_int(z_year, 2035) - x - y


def mosca_detail(x_years: Any, y_years: Any, z_year: Any, now_year: Any) -> MoscaResult:
    """Same computation as :func:`mosca`, with every intermediate kept for the report."""
    x = max(0, _as_int(x_years))
    y = max(0, _as_int(y_years))
    z = _as_int(z_year, 2035)
    now = _as_int(now_year, 2026)

    act_now, shortfall = mosca(x, y, z, now)
    years_until_z = z - now
    deadline = migration_deadline_year(x, y, z)

    if act_now:
        statement = (
            f"X({x}) + Y({y}) = {x + y} years of exposure exceeds the {years_until_z} years left "
            f"until Z={z}. Migration should already have started in {deadline}; the organisation is "
            f"carrying {shortfall} year(s) of uncovered risk."
        )
    elif shortfall == 0:
        statement = (
            f"X({x}) + Y({y}) = {x + y} years exactly equals the {years_until_z} years left until "
            f"Z={z}. There is zero slack: any delay puts this asset over the line."
        )
    else:
        statement = (
            f"X({x}) + Y({y}) = {x + y} years fits inside the {years_until_z} years left until Z={z}, "
            f"with {-shortfall} year(s) of slack. Migration must begin by {deadline}."
        )

    return MoscaResult(
        x_years=x,
        y_years=y,
        z_year=z,
        now_year=now,
        years_until_z=years_until_z,
        shortfall_years=shortfall,
        act_now=act_now,
        deadline_year=deadline,
        years_until_deadline=deadline - now,
        statement=statement,
    )


if __name__ == "__main__":  # pragma: no cover
    for args in [(25, 5, 2035, 2026), (10, 5, 2035, 2026), (2, 1, 2035, 2026), (9, 0, 2035, 2026)]:
        r = mosca_detail(*args)
        print(f"X={r.x_years:>3} Y={r.y_years:>2} Z={r.z_year}  act_now={str(r.act_now):<5} "
              f"shortfall={r.shortfall_years:>3}  {r.statement}")
