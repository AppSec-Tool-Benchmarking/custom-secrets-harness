"""
partial_redaction.py
TEST HARNESS: Partially-redacted secrets — real prefix/suffix with middle obscured.
Tools that rely only on regex pattern matching may miss these.
See secrets-manifest.csv for ground truth.
"""

# --- MANIFEST ID 137 ---
# Stripe key with middle redacted (common in logs, error messages, docs)
# Real format preserved at start and end — sufficient for regex tools
STRIPE_KEY_REDACTED = "sk_live_51FakeSt...XXXXXXXX...WXYZ0123"

# --- MANIFEST ID 138 ---
# AWS Access Key with middle replaced by asterisks
AWS_KEY_REDACTED = "AKIAIOSFODNN****K01"

# --- MANIFEST ID 139 ---
# GitHub PAT with partial masking
GITHUB_PAT_REDACTED = "ghp_FakeClas...cdefABCD"

# --- MANIFEST ID 140 ---
# SendGrid key with partial redaction
SENDGRID_KEY_REDACTED = "SG.FakeSend...NOPQRS"

# --- MANIFEST ID 141 ---
# JWT secret with last 8 chars shown (common in debug logs)
JWT_SECRET_PARTIAL = "***************************_2024_prod"

# --- MANIFEST ID 142 ---
# Database password partially shown in error message string
ERROR_MESSAGE = "Connection failed: postgresql://appuser:Sup3r***@db.prod.example.com:5432/appdb"
