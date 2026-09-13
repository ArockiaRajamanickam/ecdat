"""CI gate."""
import pytest
from engine.pipeline import scan
from engine.gate import evaluate
from engine.policy import Policy
from engine.models import Severity

def test_gate_fails_on_critical(py_corpus):
    code, summary = evaluate(scan(str(py_corpus)), Policy.load(None), Severity.CRITICAL)
    assert code != 0
    assert isinstance(summary, str) and summary

def test_gate_passes_on_clean_tree(tmp_path):
    (tmp_path / "plain.py").write_text("def add(a, b):\n    return a + b\n")
    code, _ = evaluate(scan(str(tmp_path)), Policy.load(None), Severity.CRITICAL)
    assert code == 0

def test_gate_summary_is_reportable(py_corpus):
    _, summary = evaluate(scan(str(py_corpus)), Policy.load(None), Severity.CRITICAL)
    assert len(summary.strip()) > 0



def test_gate_threshold_direction_end_to_end(tmp_path):
    """Regression: SEVERITY_RANK was lower-is-worse while every comparison assumed
    higher-is-worse, so a clean repo with only SHA-256 FAILED --fail-on critical and
    a repo full of criticals PASSED --fail-on high. Pin the real contract."""
    clean = tmp_path / "clean"; clean.mkdir()
    (clean / "a.py").write_text("import hashlib\ndef h(b): return hashlib.sha256(b).hexdigest()\n")
    dirty = tmp_path / "dirty"; dirty.mkdir()
    (dirty / "b.py").write_text("import hashlib\ndef h(b): return hashlib.md5(b).hexdigest()\n")
    pol = Policy.load(None)
    rc = scan(str(clean), target="c"); rd = scan(str(dirty), target="d")
    assert evaluate(rc, pol, Severity.CRITICAL)[0] == 0
    assert evaluate(rc, pol, Severity.NONE)[0] == 1
    assert evaluate(rd, pol, Severity.CRITICAL)[0] == 1
    assert evaluate(rd, pol, Severity.HIGH)[0] == 1
    assert evaluate(rd, pol, Severity.LOW)[0] == 1
