"""
AWS configuration module.

TEST HARNESS: This file intentionally contains hardcoded AWS credentials
for secrets detection tool benchmarking. These credentials are FAKE and
will not authenticate against AWS. See secrets-manifest.csv for ground truth.
"""

import boto3

# --- MANIFEST ID 1 ---
# AWS Access Key ID (real format: AKIA[A-Z0-9]{16})
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7FAKEK01"

# --- MANIFEST ID 2 ---
# AWS Secret Access Key (real format: 40-char base64-ish)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKESECRET"

# --- MANIFEST ID 3 ---
# AWS Session Token (STS temporary credentials — longer, base64)
AWS_SESSION_TOKEN = (
    "FwoGZXIvYXdzEJr//////////wEaDKFAKETOKENVALUEtestSESSIONTOKEN"
    "AAABBBCCCDDDEEEFFFGGGHHH111222333444555666777888999000aaabbbccc"
    "dddeeefff=="
)

# --- MANIFEST ID 4 ---
# AWS region — NOT a secret, included to show non-sensitive config alongside secrets
AWS_DEFAULT_REGION = "us-east-1"

# --- MANIFEST ID 5 ---
# S3 bucket name — NOT a secret
S3_BUCKET_NAME = "my-app-uploads-prod"


def get_s3_client():
    """Return a boto3 S3 client using hardcoded credentials."""
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        aws_session_token=AWS_SESSION_TOKEN,
        region_name=AWS_DEFAULT_REGION,
    )


def get_ec2_client():
    """Return a boto3 EC2 client."""
    return boto3.client(
        "ec2",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_DEFAULT_REGION,
    )


# --- MANIFEST ID 6 ---
# Second AWS key pair (different account / role)
BACKUP_AWS_ACCESS_KEY_ID = "AKIAI44QH8DHBEXFAKE2"
BACKUP_AWS_SECRET_ACCESS_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
