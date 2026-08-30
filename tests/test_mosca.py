"""X + Y > Z arithmetic."""
from engine.risk.mosca import mosca

def test_act_now_when_exposure_exceeds_runway():
    act, short = mosca(10, 5, 2035, 2026)      # 15 vs 9
    assert act is True and short == 6

def test_no_action_when_inside_runway():
    act, short = mosca(2, 1, 2035, 2026)       # 3 vs 9
    assert act is False and short == -6

def test_exact_boundary_is_not_yet_late():
    act, short = mosca(9, 0, 2035, 2026)
    assert act is False and short == 0

def test_longer_shelf_life_increases_urgency():
    _, a = mosca(5, 3, 2035, 2026)
    _, b = mosca(25, 3, 2035, 2026)
    assert b > a

def test_non_numeric_inputs_do_not_raise():
    act, short = mosca("junk", None, 2035, 2026)
    assert isinstance(act, bool) and isinstance(short, int)

def test_negative_years_clamped():
    act, short = mosca(-5, -5, 2035, 2026)
    assert short == -9
