"""Recommendations are a deterministic NIST-keyed lookup, and autofix refuses to guess."""
import pytest
from engine.pipeline import scan
from conftest import by_family

@pytest.fixture
def scanned(py_corpus):
    return scan(str(py_corpus))

def test_signature_families_map_to_ml_dsa(scanned):
    for fam in ("ECDSA", "Ed25519"):
        got = by_family(scanned.artefacts, fam)
        if got:
            assert "ML-DSA" in got[0].recommendation

def test_key_exchange_maps_to_ml_kem(scanned):
    x = by_family(scanned.artefacts, "X25519")
    assert x and "ML-KEM" in x[0].recommendation

def test_broken_hashes_map_to_sha256(scanned):
    for fam in ("MD5", "SHA-1"):
        got = by_family(scanned.artefacts, fam)
        if got:
            assert "SHA-256" in got[0].recommendation

def test_legacy_ciphers_map_to_aes_gcm(scanned):
    got = by_family(scanned.artefacts, "3DES")
    if got:
        assert "AES-256" in got[0].recommendation

def test_recommendations_are_deterministic(py_corpus):
    a = {x.name: x.recommendation for x in scan(str(py_corpus)).artefacts}
    b = {x.name: x.recommendation for x in scan(str(py_corpus)).artefacts}
    assert a == b

def test_autofix_emits_a_real_diff(tmp_path):
    (tmp_path / "m.py").write_text("import hashlib\ndef d(b):\n    return hashlib.md5(b).hexdigest()\n")
    res = scan(str(tmp_path))
    md5 = by_family(res.artefacts, "MD5")
    assert md5 and md5[0].fix_patch
    p = md5[0].fix_patch
    assert "---" in p and "+++" in p and "hashlib.sha256(" in p

def test_autofix_refuses_when_it_cannot_be_sure(tmp_path):
    """An aliased call is not a safe textual substitution - refusing beats guessing."""
    (tmp_path / "m.py").write_text("import hashlib as h\ndef d(b):\n    return h.md5(b).hexdigest()\n")
    res = scan(str(tmp_path))
    md5 = by_family(res.artefacts, "MD5")
    assert md5 and md5[0].fix_patch == ""

def test_no_autofix_for_asymmetric_redesign(scanned):
    """Swapping RSA for ML-KEM is a design change, never a text edit."""
    for fam in ("RSA", "ECDSA", "Ed25519", "X25519"):
        for a in by_family(scanned.artefacts, fam):
            assert a.fix_patch == ""
