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
