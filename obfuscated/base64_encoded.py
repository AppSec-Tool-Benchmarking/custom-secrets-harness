"""
base64_encoded.py
TEST HARNESS: Secrets hidden via base64 encoding.
Tools should detect these through entropy analysis or base64 decoding.
See secrets-manifest.csv for ground truth.
"""

import base64

# --- MANIFEST ID 123 ---
# AWS Access Key base64-encoded and stored as a "config" string
# Decoded value: AKIAIOSFODNN7FAKEB64
ENCODED_AWS_KEY_ID = "QUTJQUZPZEZPRE5ON0ZBS0VCNjQ="  # base64

# --- MANIFEST ID 124 ---
# AWS Secret Key fully base64-encoded
# Decoded value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEBASE64KEY
ENCODED_AWS_SECRET = "d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRkFLRUJBU0U2NEtFWQ=="

# --- MANIFEST ID 125 ---
# JWT secret stored as base64 in a "config value"
# Decoded value: my_super_secret_jwt_key_base64_encoded
ENCODED_JWT_SECRET = base64.b64encode(b"my_super_secret_jwt_key_base64_encoded").decode()

# --- MANIFEST ID 126 ---
# Stripe key base64-encoded (double-encoded — encoded once, then stored encoded)
# Decoded: sk_live_51Base64FakeStripeKeyABCDEFGHIJKLMNOPQRSTUVWXYZ0123
import base64 as b64
_raw = b"sk_live_51Base64FakeStripeKeyABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
STRIPE_KEY_B64 = b64.b64encode(_raw).decode("utf-8")

# --- MANIFEST ID 127 ---
# Docker config.json (base64-encoded auth, as seen in ~/.docker/config.json)
# The auth value is base64("username:password")
DOCKER_CONFIG_JSON = """{
    "auths": {
        "registry.example.com": {
            "auth": "ZmFrZXVzZXI6RmFrZURvY2tlclJlZ2lzdHJ5UEBzc3dvcmQhMTIz"
        }
    }
}"""
# Decoded auth: fakeuser:FakeDockerRegistryP@ssword!123
