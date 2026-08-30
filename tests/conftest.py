import os, sys, pytest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
if APP not in sys.path:
    sys.path.insert(0, APP)

PY_SRC = '''"""Docstring mentions RSA and MD5 - must NOT be flagged."""
import hashlib as h
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
k2 = ec.generate_private_key(ec.SECP256R1())
k3 = ed25519.Ed25519PrivateKey.generate()
k4 = x25519.X25519PrivateKey.generate()
d1 = h.md5(b"x")
d2 = h.sha1(b"y")
d3 = h.sha256(b"z")
c1 = Cipher(algorithms.AES(b"0"*32), modes.GCM(b"0"*12))
c2 = Cipher(algorithms.AES(b"0"*16), modes.ECB())
c3 = Cipher(algorithms.TripleDES(b"0"*24), modes.CBC(b"0"*8))
def trap():
    # we used to use RSA and DES here
    raise ValueError("Only RSA keys are supported, not ECDSA")
'''

JS_SRC = '''const crypto = require('crypto');
// comment mentioning md5 and rsa must not be flagged
const A = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const B = crypto.generateKeyPairSync('ed25519');
const D = crypto.createHash('sha1');
const G = crypto.createCipheriv('aes-256-gcm', k, iv);
const H = crypto.createCipheriv('rc4', k, iv);
function err(){ throw new Error("md5 is not supported here"); }
'''

JAVA_SRC = '''import javax.crypto.Cipher;
import java.security.*;
public class C {
  public void go() throws Exception {
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    Cipher d = Cipher.getInstance("DES");
    MessageDigest m = MessageDigest.getInstance("MD5");
  }
}
'''

GO_SRC = '''package main
import ("crypto/rsa"; "crypto/rand"; "crypto/md5")
func main() {
    k, _ := rsa.GenerateKey(rand.Reader, 2048)
    _ = md5.New()
    _ = k
}
'''

@pytest.fixture
def py_corpus(tmp_path):
    (tmp_path / "app.py").write_text(PY_SRC)
    return tmp_path

@pytest.fixture
def multi_corpus(tmp_path):
    (tmp_path / "a.py").write_text(PY_SRC)
    (tmp_path / "a.js").write_text(JS_SRC)
    (tmp_path / "C.java").write_text(JAVA_SRC)
    (tmp_path / "main.go").write_text(GO_SRC)
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "v.js").write_text(JS_SRC)
    return tmp_path

@pytest.fixture
def scan_tmp():
    from engine.pipeline import scan
    return scan

def families(artefacts):
    return {a.family for a in artefacts}

def by_family(artefacts, fam):
    return [a for a in artefacts if a.family == fam]
