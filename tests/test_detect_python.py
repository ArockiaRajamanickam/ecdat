"""Python detector: parameter extraction, alias resolution, false-positive traps."""
import pytest
pytest.importorskip("tree_sitter_python")
from engine.detectors import source_python
from conftest import by_family

@pytest.fixture
def arts(py_corpus):
    a, _, errs = source_python.detect(str(py_corpus), None)
    assert errs == []
    return a

def test_extracts_rsa_key_size(arts):
    rsa = by_family(arts, "RSA")
    assert rsa and rsa[0].params.key_size == 1024
    assert "1024" in rsa[0].name

def test_extracts_ec_curve(arts):
    ec = by_family(arts, "ECDSA")
    assert ec and ec[0].params.curve == "secp256r1"

def test_finds_ed25519(arts):
    """Ed25519 is Shor-broken and easy to miss - a name-only rule table skips it."""
    assert by_family(arts, "Ed25519")

def test_finds_x25519(arts):
    assert by_family(arts, "X25519")

def test_resolves_import_alias(arts):
    """import hashlib as h; h.md5() must resolve through the alias."""
    assert by_family(arts, "MD5")

def test_extracts_cipher_mode(arts):
    modes = {a.params.mode for a in by_family(arts, "AES")}
    assert "GCM" in modes and "ECB" in modes

def test_ignores_comments_and_raise_strings(arts):
    """The fixture's trap lines mention RSA/DES/ECDSA in a comment and an
    exception message. Neither is a usage."""
    trap_lines = {o.line for a in arts for o in a.occurrences if (o.line or 0) >= 16}
    assert not trap_lines

def test_every_occurrence_has_provenance(arts):
    for a in arts:
        for o in a.occurrences:
            assert o.file and isinstance(o.line, int) and o.line > 0
