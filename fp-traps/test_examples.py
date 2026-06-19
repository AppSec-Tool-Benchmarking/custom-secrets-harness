"""
test_examples.py
TEST HARNESS - FALSE POSITIVE TRAPS

Test files often contain obviously-fake values used for mocking.
Tools should NOT flag unit test mock values.

If a tool flags any of these, it is generating a FALSE POSITIVE.
See secrets-manifest.csv (is_fp_trap = true) for ground truth.
"""

import unittest
from unittest.mock import patch

# --- MANIFEST FP-19 ---
# Mock values for unit testing — clearly labeled as test data
MOCK_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
MOCK_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
MOCK_STRIPE_KEY = "sk_test_000000000000000000000000"
MOCK_JWT_SECRET = "test_jwt_secret"
MOCK_DB_PASSWORD = "testpassword"

# --- MANIFEST FP-20 ---
# Test fixture with obviously-fake token
class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.test_token = "test_bearer_token_for_unit_tests"
        self.test_api_key = "test_api_key_for_mock_assertions"
        self.test_secret = "test_secret_do_not_use_in_production"

    @patch('requests.get')
    def test_api_call(self, mock_get):
        # Using clearly-named test values
        headers = {"Authorization": f"Bearer {self.test_token}"}
        mock_get.return_value.status_code = 200
        # ... test logic


# --- MANIFEST FP-21 ---
# Pytest fixtures with placeholder secrets
def fake_stripe_client():
    """Returns a mock Stripe client for testing."""
    return {
        "api_key": "sk_test_fake_for_pytest",
        "webhook_secret": "whsec_fake_for_pytest"
    }

def fake_aws_credentials():
    """Returns fake AWS credentials for moto mocking."""
    return {
        "aws_access_key_id": "testing",
        "aws_secret_access_key": "testing",
        "aws_security_token": "testing",
        "aws_session_token": "testing"
    }
