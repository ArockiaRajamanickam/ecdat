"""CBOM / SARIF / report output shapes."""
import pytest
from engine.pipeline import scan
from engine.serializers import cbom, sarif, report
from engine.policy import Policy

@pytest.fixture
def res(py_corpus):
    return scan(str(py_corpus))

def test_cbom_is_cyclonedx_16(res):
    c = cbom.to_cbom(res)
    assert c["bomFormat"] == "CycloneDX" and c["specVersion"] == "1.6"
    assert c["components"]

def test_cbom_components_carry_crypto_properties(res):
    c = cbom.to_cbom(res)
    assert any("cryptoProperties" in comp for comp in c["components"])

def test_sarif_is_210_with_rules_and_results(res):
    s = sarif.to_sarif(res)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["rules"] and run["results"]

def test_sarif_results_have_locations(res):
    s = sarif.to_sarif(res)
    r = s["runs"][0]["results"][0]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] >= 1

def test_markdown_report_mentions_target(res):
    md = report.to_markdown(res, Policy.load(None))
    assert isinstance(md, str) and len(md) > 100
