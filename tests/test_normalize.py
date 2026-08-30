"""Merging must never lose a precise finding."""
from engine.models import Artefact, Params, Occurrence
from engine.normalize2 import merge_compatible, infer_missing_params

def art(name, fam, ks=None, curve=None, mode=None, file="a.py", line=1):
    return Artefact(name=name, family=fam, params=Params(key_size=ks, curve=curve, mode=mode),
                    occurrences=[Occurrence(file=file, line=line, evidence="e", detector="t")])

def test_unknown_params_merge_into_known():
    out = merge_compatible([art("Ed25519", "Ed25519", ks=256), art("Ed25519", "Ed25519", file="b.go")])
    assert len(out) == 1 and len(out[0].occurrences) == 2

def test_different_key_sizes_never_merge():
    out = merge_compatible([art("RSA-1024", "RSA", ks=1024), art("RSA-2048", "RSA", ks=2048)])
    assert len(out) == 2
    assert {a.name for a in out} == {"RSA-1024", "RSA-2048"}

def test_precise_artefact_keeps_its_name():
    """A vaguer artefact must not rename a precise one - losing 'RSA-1024'
    would hide a weak key."""
    out = merge_compatible([art("RSA-1024", "RSA", ks=1024), art("RSA-SHA-256", "RSA")])
    assert len(out) == 1 and out[0].name == "RSA-1024"

def test_different_modes_never_merge():
    out = merge_compatible([art("AES-GCM", "AES", mode="GCM"), art("AES-ECB", "AES", mode="ECB")])
    assert len(out) == 2

def test_duplicate_occurrences_deduped():
    a, b = art("MD5", "MD5"), art("MD5", "MD5")
    out = merge_compatible([a, b])
    assert len(out) == 1 and len(out[0].occurrences) == 1

def test_infer_hash_size_from_name():
    a = art("SHA-256", "SHA-2")
    infer_missing_params([a])
    assert a.params.key_size == 256
