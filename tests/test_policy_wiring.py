"""The risk engine must actually consume policy.yaml: X per data class, Y per family,
criticality per path. Before this test existed every asset silently got the built-in
defaults (X=5, Y=5, deadline 2025) and the slide claim was false."""
import os, sys, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from engine.pipeline import scan


def _corpus(tmp_path):
    (tmp_path / "payments").mkdir()
    (tmp_path / "payments" / "checkout.py").write_text(textwrap.dedent('''
        from cryptography.hazmat.primitives.asymmetric import rsa
        def k(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    '''))
    (tmp_path / "public").mkdir(); (tmp_path / "services").mkdir(exist_ok=True)
    (tmp_path / "public" / "banner.py").write_text(textwrap.dedent('''
        from cryptography.hazmat.primitives.asymmetric import rsa
        def k(): return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    '''))
    (tmp_path / "services" / "digest.py").write_text(textwrap.dedent('''
        import hashlib
        def h(b): return hashlib.sha256(b).hexdigest()
    '''))
    (tmp_path / "services").mkdir(exist_ok=True)
    (tmp_path / "services" / "notes.py").write_text(textwrap.dedent('''
        from cryptography.hazmat.primitives.asymmetric import ec
        def k(): return ec.generate_private_key(ec.SECP256R1())
    '''))
    return tmp_path


def test_x_and_criticality_follow_the_path(tmp_path):
    r = scan(str(_corpus(tmp_path)), target="t")
    by = {a.occurrences[0].file: a for a in r.artefacts}
    pay = next(a for f, a in by.items() if f.startswith("payments"))
    pub = next(a for f, a in by.items() if f.startswith("public"))
    doc = next(a for f, a in by.items() if f.startswith("services/notes"))
    sha = next(a for f, a in by.items() if f.startswith("services/digest"))
    # Grover-weakened assets are advisory: no start year, never act-now
    assert sha.mosca_deadline_year is None and sha.mosca_act_now is False
    # payments/ is the financial class (X=15) at criticality 1.0; public/ is X=0
    assert pay.x_years == 15 and pay.data_class == "financial"
    assert pay.criticality == "critical"
    assert pub.x_years == 0 and pub.data_class == "public"
    assert doc.x_years == 10 and doc.data_class == "default"
    # different X means a different Mosca deadline per asset
    assert pay.mosca_deadline_year < doc.mosca_deadline_year < pub.mosca_deadline_year
    assert pay.mosca_act_now is True and pub.mosca_act_now is False


def test_y_follows_the_algorithm_family(tmp_path):
    r = scan(str(_corpus(tmp_path)), target="t")
    ys = {a.family.upper(): a.y_years for a in r.artefacts}
    # hashes migrate faster than asymmetric key material in the default policy
    assert ys.get("SHA-2", 99) < ys.get("RSA", 0)


def test_key_material_is_critical(tmp_path):
    d = _corpus(tmp_path)
    (d / "config").mkdir()
    (d / "config" / "signing-public.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n")
    r = scan(str(d), target="t")
    pem = next(a for a in r.artefacts if a.occurrences[0].file.endswith(".pem"))
    assert pem.data_class == "credential" and pem.x_years == 12
    assert pem.criticality == "critical"
