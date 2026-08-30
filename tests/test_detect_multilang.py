"""JS / Java / Go detectors."""
import pytest
from conftest import by_family, JS_SRC, JAVA_SRC, GO_SRC

def test_js(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    from engine.detectors import source_js
    (tmp_path / "a.js").write_text(JS_SRC)
    arts, _, _ = source_js.detect(str(tmp_path), None)
    fams = {a.family for a in arts}
    assert "RSA" in fams and "Ed25519" in fams
    assert "SHA-1" in fams or "SHA1" in fams

def test_js_ignores_throw_string(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    from engine.detectors import source_js
    (tmp_path / "a.js").write_text(JS_SRC)
    arts, _, _ = source_js.detect(str(tmp_path), None)
    # the only md5 mention is inside `throw new Error("md5 ...")`
    assert not by_family(arts, "MD5")

def test_java_transformation_string(tmp_path):
    pytest.importorskip("tree_sitter_java")
    from engine.detectors import source_java
    (tmp_path / "C.java").write_text(JAVA_SRC)
    arts, _, _ = source_java.detect(str(tmp_path), None)
    fams = {a.family for a in arts}
    assert "DES" in fams, "Cipher.getInstance(\"DES\") must be found"
    assert "MD5" in fams

def test_go(tmp_path):
    from engine.detectors import source_go
    (tmp_path / "main.go").write_text(GO_SRC)
    arts, _, _ = source_go.detect(str(tmp_path), None)
    fams = {a.family for a in arts}
    assert "RSA" in fams and "MD5" in fams
