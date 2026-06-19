"""
split_across_lines.py
TEST HARNESS: Secrets constructed by concatenating split strings across multiple lines.
More advanced tools using semantic analysis should detect these.
See secrets-manifest.csv for ground truth.
"""

# --- MANIFEST ID 132 ---
# AWS Access Key split across a concatenation
# Reconstructed: AKIAIOSFODNN7FAKESPL
AWS_KEY_PART1 = "AKIAIOSFODNN"
AWS_KEY_PART2 = "7FAKESPL"
AWS_ACCESS_KEY_ID = AWS_KEY_PART1 + AWS_KEY_PART2

# --- MANIFEST ID 133 ---
# Stripe key split across f-string concatenation
STRIPE_PREFIX = "sk_live_51"
STRIPE_BODY = "SplitFakeStripeKeyABCDEFGHIJKLMNOPQRSTUVWXYZ"
STRIPE_SUFFIX = "0123456789abcde"
STRIPE_SECRET_KEY = f"{STRIPE_PREFIX}{STRIPE_BODY}{STRIPE_SUFFIX}"

# --- MANIFEST ID 134 ---
# JWT secret built from multiple variables
_jwt_part_a = "split_jwt"
_jwt_part_b = "_secret_key"
_jwt_part_c = "_do_not_share"
JWT_SECRET = _jwt_part_a + _jwt_part_b + _jwt_part_c

# --- MANIFEST ID 135 ---
# Connection string assembled from parts
_db_user = "splituser"
_db_pass = "Spl!tDbP@ssword123"
_db_host = "db.prod.example.com"
_db_name = "appdb"
DATABASE_URL = (
    "postgresql://"
    + _db_user + ":"
    + _db_pass + "@"
    + _db_host + ":5432/"
    + _db_name
)

# --- MANIFEST ID 136 ---
# GitHub token split with implicit string concatenation (Python auto-joins adjacent literals)
GITHUB_TOKEN = (
    "ghp_Split"
    "GitHubPAT"
    "FakeToken"
    "1234567890AB"
)
