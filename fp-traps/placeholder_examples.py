"""
placeholder_examples.py
TEST HARNESS - FALSE POSITIVE TRAPS

These are intentional NON-SECRETS. Secrets detection tools should NOT flag these.
They are template placeholders, example values, and documentation strings.

If a tool flags any variable in this file, it is generating a FALSE POSITIVE.
See secrets-manifest.csv (is_fp_trap = true) for ground truth.
"""

# --- MANIFEST FP-01 ---
# Template placeholder strings — tools should recognize these as non-secrets
AWS_ACCESS_KEY = "YOUR_AWS_ACCESS_KEY_HERE"
AWS_SECRET_KEY = "YOUR_AWS_SECRET_KEY_HERE"
STRIPE_KEY = "<INSERT_STRIPE_SECRET_KEY>"
API_KEY = "REPLACE_WITH_YOUR_API_KEY"
DATABASE_PASSWORD = "CHANGE_ME_IN_PRODUCTION"

# --- MANIFEST FP-02 ---
# AWS documentation example key (explicitly non-secret, appears in AWS docs)
# TruffleHog and GitLeaks should have allowlist entries for this
AWS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# --- MANIFEST FP-03 ---
# Lowercase non-secret placeholder
db_password = "changeme"
admin_password = "password123"
secret_key = "development-only-not-for-production"

# --- MANIFEST FP-04 ---
# Test/demo values that are explicitly labeled
TEST_API_KEY = "test_api_key_only_for_unit_tests"
MOCK_SECRET = "mock_secret_for_testing"
DUMMY_TOKEN = "dummy_token_replace_with_real_value"

# --- MANIFEST FP-05 ---
# Format strings / templates
config_template = "postgresql://user:{password}@{host}:{port}/{database}"
aws_key_format = "Access Key ID format: AKIA[A-Z0-9]{16}"

# --- MANIFEST FP-06 ---
# Obvious test data strings used in unit tests
def test_authentication():
    """Unit test with obviously fake credentials."""
    fake_token = "fake_jwt_token_for_unit_test_assertions"
    fake_key = "fake_api_key_for_mock_server"
    assert len(fake_token) > 0
    assert len(fake_key) > 0
