"""
url_encoded.py
TEST HARNESS: Secrets hidden via URL encoding.
See secrets-manifest.csv for ground truth.
"""

from urllib.parse import quote, unquote

# --- MANIFEST ID 128 ---
# PostgreSQL connection string with URL-encoded password
# Decoded password: P@ssw0rd!Special#Chars
POSTGRES_URL_ENCODED = "postgresql://dbuser:P%40ssw0rd%21Special%23Chars@db.prod.example.com:5432/appdb"

# --- MANIFEST ID 129 ---
# AWS Secret Key with URL encoding applied to special characters
# Original: FakeSecretKey/bPxRfi+CY=EXAMPLE
AWS_SECRET_URL_ENCODED = "FakeSecretKey%2FbPxRfi%2BCY%3DEXAMPLE"

# --- MANIFEST ID 130 ---
# API key embedded in a URL query parameter (common in webhook configs)
WEBHOOK_URL_WITH_SECRET = "https://api.example.com/webhook?secret=URLEncodedApiKeyFake123%21%40%23&event=payment"

# --- MANIFEST ID 131 ---
# Redis URL with special characters URL-encoded in password
REDIS_URL_ENCODED = "redis://:R3d%21sP%40ssword%23Special@redis.prod.example.com:6379/0"
