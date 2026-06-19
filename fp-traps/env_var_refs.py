"""
env_var_refs.py
TEST HARNESS - FALSE POSITIVE TRAPS

These are environment variable references — the code reads secrets from the environment
rather than hardcoding them. Tools should NOT flag these as secrets.

If a tool flags any of these, it is generating a FALSE POSITIVE.
See secrets-manifest.csv (is_fp_trap = true) for ground truth.
"""

import os

# --- MANIFEST FP-07 ---
# Standard os.environ pattern — correct way to handle secrets
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")

# --- MANIFEST FP-08 ---
# os.getenv with default None
JWT_SECRET = os.getenv("JWT_SECRET")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# --- MANIFEST FP-09 ---
# Shell variable expansion style (in strings, not values)
dockerfile_example = "ENV AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}"
shell_example = "export STRIPE_KEY=${STRIPE_SECRET_KEY}"
yaml_example = "api_key: ${API_KEY}"

# --- MANIFEST FP-10 ---
# Python f-string environment variable reference
def get_connection_string():
    host = os.environ["DB_HOST"]
    port = os.environ["DB_PORT"]
    user = os.environ["DB_USER"]
    password = os.environ["DB_PASSWORD"]
    name = os.environ["DB_NAME"]
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"

# --- MANIFEST FP-11 ---
# Kubernetes-style secret reference in a comment or string
k8s_secret_ref = "valueFrom.secretKeyRef.name: app-secrets"
k8s_env_from = "envFrom.secretRef.name: my-secret"
