"""C / C++ detector (OpenSSL surface). No tree-sitter grammar: masking tokenizer."""
from engine.detectors import source_c

C_SRC = '''
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

/* comment: EVP_sha1() and MD5() here must never be flagged */
static const char *doc = "we do not use RC4 in production";

void keygen(void) {
    RSA *r = RSA_new();
    RSA_generate_key_ex(r, 1024, NULL, NULL);
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    const EVP_CIPHER *a = EVP_aes_256_gcm();
    const EVP_CIPHER *d = EVP_des_ede3_cbc();
    EC_KEY *e = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX *s = SSL_CTX_new(TLSv1_method());
    OQS_KEM *k = OQS_KEM_new("ML-KEM-768");
}
'''

def _fam(arts):
    return {a.family for a in arts}

def test_openssl_surface(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, files, errs = source_c.detect(str(tmp_path), None)
    assert files == 1 and not errs
    fams = _fam(arts)
    assert "RSA" in fams and "MD5" in fams and "3DES" in fams and "EC" in fams

def test_rsa_key_size_from_arg(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, _, _ = source_c.detect(str(tmp_path), None)
    rsa = [a for a in arts if a.family == "RSA" and a.params.key_size]
    assert any(a.params.key_size == 1024 for a in rsa), "RSA modulus must be read from RSA_generate_key_ex"

def test_aes_cipher_name_parsed(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, _, _ = source_c.detect(str(tmp_path), None)
    aes = [a for a in arts if a.family == "AES"]
    assert aes and aes[0].params.key_size == 256 and aes[0].params.mode == "GCM"

def test_ec_curve_from_nid(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, _, _ = source_c.detect(str(tmp_path), None)
    ec = [a for a in arts if a.family == "EC"]
    assert ec and ec[0].params.curve in ("secp256r1", "P-256", "prime256v1")

def test_comment_and_string_decoys_ignored(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, _, _ = source_c.detect(str(tmp_path), None)
    # RC4 appears only inside a string literal; SHA-1 only inside a comment
    assert "RC4" not in _fam(arts)
    assert "SHA-1" not in _fam(arts)

def test_headers_and_pqc(tmp_path):
    (tmp_path / "x.c").write_text(C_SRC)
    arts, _, _ = source_c.detect(str(tmp_path), None)
    names = {a.name for a in arts}
    assert any("OpenSSL" in n for n in names)
    assert any("liboqs" in n for n in names)

def test_cpp_extension(tmp_path):
    (tmp_path / "x.cpp").write_text("#include <openssl/evp.h>\nvoid f(){ const EVP_CIPHER*c=EVP_aes_128_cbc(); }\n")
    arts, files, _ = source_c.detect(str(tmp_path), None)
    assert files == 1
    assert any(a.family == "AES" for a in arts)
