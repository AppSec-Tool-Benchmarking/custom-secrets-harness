# main.tf
# TEST HARNESS: This file intentionally contains hardcoded credentials
# for secrets detection tool benchmarking. All credentials are FAKE.
# See secrets-manifest.csv for ground truth.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # --- MANIFEST ID 88 ---
  # Terraform Cloud token hardcoded in backend config
  cloud {
    organization = "my-org"
    token        = "FakeTerraformCloudToken.MNOPQRSTUVWXYZ0123456789abcdefghijklmno"
  }
}

# --- MANIFEST ID 89 ---
# AWS provider with hardcoded credentials (instead of using env vars or IAM role)
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7FAKETF1"
  secret_key = "TerraformFakeSecretKey/bPxRfiCYEXAMPLEKEY1"
}

# --- MANIFEST ID 90 ---
# RDS instance with hardcoded master password
resource "aws_db_instance" "main" {
  identifier        = "prod-database"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  db_name           = "appdb"
  username          = "dbadmin"
  password          = "TerraformRdsP@ssword!Secret789"

  skip_final_snapshot = false
}

# --- MANIFEST ID 91 ---
# ElastiCache (Redis) with hardcoded auth token
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "prod-redis"
  description          = "Production Redis cluster"
  node_type            = "cache.t3.medium"
  auth_token           = "TerraformRedisAuthToken!FakeValue123ABC"
}

# --- MANIFEST ID 92 ---
# Hardcoded Stripe key in locals (sometimes done for module passing)
locals {
  stripe_secret_key  = "sk_live_51TerraformFakeStripeKeyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  sendgrid_api_key   = "SG.TerraformSendGridKey1234.TerraformSendGridSecondSegmentABCDEFGHIJ"
}

resource "aws_ssm_parameter" "stripe_key" {
  name  = "/app/stripe/secret_key"
  type  = "SecureString"
  value = local.stripe_secret_key
}
