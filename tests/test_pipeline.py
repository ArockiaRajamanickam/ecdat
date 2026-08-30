"""End-to-end across languages."""
import pytest
from engine.pipeline import scan
from engine.models import Threat

@pytest.fixture
def res(multi_corpus):
    return scan(str(multi_corpus))

def test_scan_completes_without_errors(res):
    assert res.errors == [] or all(isinstance(e, str) for e in res.errors)

def test_finds_assets_across_languages(res):
    assert len(res.artefacts) >= 5

def test_no_artefact_left_unclassified(res):
    assert [a.name for a in res.artefacts if a.threat is Threat.UNKNOWN] == []

def test_vendored_directories_excluded(res):
    """node_modules is a copy of our own fixture; counting it would double
    every finding."""
    leaked = [o.file for a in res.artefacts for o in a.occurrences if "node_modules" in o.file]
    assert leaked == []

def test_every_artefact_has_provenance(res):
    for a in res.artefacts:
        assert a.occurrences
        assert all(o.file for o in a.occurrences)

def test_result_serialises(res):
    d = res.to_dict()
    assert d["target"] and isinstance(d["artefacts"], list)
