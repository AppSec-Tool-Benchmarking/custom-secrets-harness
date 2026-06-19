"""
private_keys.py
TEST HARNESS: This file contains hardcoded private key material (FAKE, non-functional)
for secrets detection tool benchmarking.
See secrets-manifest.csv for ground truth.
"""

# --- MANIFEST ID 119 ---
# RSA Private Key (PEM format, fake/non-functional)
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vA3ynLMnHpPtMXEFtEpBmifSsRKi
FakeRSAPrivateKeyDataLine2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine3ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine4ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine5ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine6ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine7ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine8ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivateKeyDataLine9ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivatKeyDataLine10ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivatKeyDataLine11ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
FakeRSAPrivatKeyDataLine12ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
Q3X9ABCDEFGHfakevalueQIDAQABAoIBAC5RgZ+hBx7xHNaMpPgwGMnCd2vwhCgm
FakeRSAPrivatKeyDataLine14ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn
-----END RSA PRIVATE KEY-----"""

# --- MANIFEST ID 120 ---
# ED25519 Private Key (OpenSSH format, fake/non-functional)
ED25519_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAAbmOnZQAAAAAAAAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5
AAAAIFakeED25519PrivateKeyDataABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg==
AAAAUFakeED25519PrivateKeyBodyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno
pqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12345
-----END OPENSSH PRIVATE KEY-----"""

# --- MANIFEST ID 121 ---
# ECDSA Private Key
ECDSA_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIFakeECDSAPrivateKeyValueABCDEFGHIJKLMNOPQRSTUVWXYZabc12
oAoGCCqGSM49AwEHoWQDYgAEFakeECPublicKeyXYZABCDEFGHIJKLMNOPQRSTU
VWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTfake
-----END EC PRIVATE KEY-----"""

# --- MANIFEST ID 122 ---
# PEM Certificate with embedded private key (PKCS#12-style PEM bundle)
PEM_BUNDLE = """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUFakeX509CertificateSerialNumber123AgAEwDQYJKoZI
FakeCertLine2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCFakePrivKeyInPEM
FakePKCS8KeyLine2ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu
-----END PRIVATE KEY-----"""
