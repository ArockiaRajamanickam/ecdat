"""Classification correctness. These are cryptographic facts, not opinions."""
import pytest
from engine.kb import classify
from engine.models import Params, Threat

def t(family, **kw):
    return classify(family, Params(**kw))[0]

@pytest.mark.parametrize("fam", ["RSA", "ECDSA", "ECDH", "Ed25519", "X25519", "DSA", "DH"])
def test_public_key_is_shor_broken(fam):
    assert t(fam, key_size=256) is Threat.SHOR_BROKEN

@pytest.mark.parametrize("fam", ["MD5", "SHA-1", "3DES", "DES", "RC4"])
def test_classically_broken_is_not_merely_grover_weakened(fam):
    """MD5/SHA-1/DES/RC4 are broken today, with no quantum computer involved.
    Calling them 'Grover-weakened' understates them."""
    assert t(fam, key_size=128) is Threat.LEGACY_BROKEN

def test_aes256_is_quantum_safe():
    assert t("AES", key_size=256) is Threat.QUANTUM_SAFE

def test_sha256_is_grover_weakened_not_broken():
    assert t("SHA-2", key_size=256) is Threat.GROVER_WEAKENED

def test_sha384_is_quantum_safe():
    assert t("SHA-2", key_size=384) is Threat.QUANTUM_SAFE

@pytest.mark.parametrize("fam", ["ML-KEM", "ML-DSA", "SLH-DSA"])
def test_pqc_families(fam):
    assert t(fam, key_size=768) is Threat.PQC

def test_classify_never_raises_on_garbage():
    for junk in ["", "NOT-A-CIPHER", "  ", "123"]:
        assert classify(junk, Params())[0] in set(Threat)

def test_reason_is_human_readable():
    _, reason = classify("RSA", Params(key_size=1024))
    assert isinstance(reason, str) and len(reason) > 10
