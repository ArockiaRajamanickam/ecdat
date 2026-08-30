"""Policy: globs, data classes, criticality."""
from engine.policy import Policy

def test_defaults_load_without_a_file():
    p = Policy.load(None)
    assert isinstance(p.z_year(), int) and p.z_year() > 2020
    assert p.y_default() >= 0

def test_glob_matches_at_root_and_nested():
    p = Policy.load(None)
    assert p.criticality_for("payments/charge.py") == p.criticality_for("svc/payments/charge.py")

def test_payments_outranks_default():
    p = Policy.load(None)
    assert p.criticality_for("payments/a.py") > p.criticality_for("misc/a.py")

def test_x_is_a_positive_horizon():
    p = Policy.load(None)
    assert p.x_for("anything/a.py") >= 0

def test_is_ignored_returns_bool():
    p = Policy.load(None)
    assert isinstance(p.is_ignored("a/b.py"), bool)
