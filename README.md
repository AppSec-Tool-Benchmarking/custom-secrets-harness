# Custom Secrets Harness

**Purpose:** Ground-truth test corpus for evaluating secrets detection tools (GitLeaks, TruffleHog, GitHub Secret Scanning, GitGuardian, Detect-Secrets, Semgrep Secrets, SpectralOps).

This repository is an **explicit, obviously-named** test harness. It is NOT disguised as a real application. Its goal is maximum breadth: every major secret type, every storage location, every obfuscation pattern, and intentional false-positive traps — all documented in `secrets-manifest.csv`.

For a realistic application with secrets embedded naturally, see [`custom-secrets-app`](../custom-secrets-app).

---

## Ground Truth

All secrets in this repo are catalogued in [`secrets-manifest.csv`](./secrets-manifest.csv).

**Schema:**
| Column | Description |
|---|---|
| `id` | Unique integer identifier |
| `file_path` | Relative path from repo root |
| `line_number` | Exact line number of the secret |
| `secret_type` | Human-readable type (e.g., `aws_access_key_id`) |
| `provider` | Service provider (e.g., `aws`, `stripe`, `github`) |
| `format_type` | `real-format-fake` or `obvious-fake` |
| `location_category` | `source-code`, `config-file`, `infrastructure`, `notebook`, `binary-artifact`, `obfuscated` |
| `in_head` | `true` if secret exists in HEAD (current state of repo) |
| `in_history_only` | `true` if secret was committed then deleted (only in git history) |
| `is_fp_trap` | `true` if this entry is an intentional false positive — tools should NOT flag it |
| `obfuscation_type` | `none`, `base64`, `url-encoded`, `split-concat`, `partial-redaction` |
| `notes` | Additional context |

---

## Directory Structure

```
custom-secrets-harness/
├── secrets-manifest.csv          ← Ground truth (all secrets catalogued here)
├── README.md
├── source-code/                  ← Secrets hardcoded in application source files
│   ├── aws_config.py
│   ├── database.js
│   ├── auth.ts
│   ├── stripe_payments.rb
│   ├── gcp_client.go
│   └── azure_storage.cs
├── config-files/                 ← Secrets in configuration files
│   ├── .env
│   ├── config.yaml
│   ├── settings.json
│   ├── app.toml
│   ├── database.xml
│   └── secrets.ini
├── infrastructure/               ← Secrets in IaC, Docker, CI/CD
│   ├── main.tf
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── Jenkinsfile
│   └── .github/workflows/
│       ├── deploy.yml
│       └── release.yml
├── notebooks/
│   └── analysis.ipynb            ← Jupyter notebook with embedded secrets
├── binary-artifacts/
│   └── encoded_config.txt        ← Base64-encoded secrets (simulates binary artifacts)
├── fp-traps/                     ← Intentional FALSE POSITIVES — tools should NOT flag
│   ├── placeholder_examples.py
│   ├── env_var_refs.py
│   ├── public_keys.txt
│   ├── commented_placeholders.yml
│   └── test_examples.py
└── obfuscated/                   ← Secrets hidden via encoding/obfuscation
    ├── base64_encoded.py
    ├── url_encoded.py
    ├── split_across_lines.py
    └── partial_redaction.py
```

---

## Secret Types Covered

| Type | Provider | Count |
|---|---|---|
| AWS Access Key ID | AWS | 3 |
| AWS Secret Access Key | AWS | 3 |
| AWS Session Token | AWS | 1 |
| GCP Service Account Key | GCP | 1 |
| Azure Storage Connection String | Azure | 1 |
| Azure Client Secret | Azure | 1 |
| GitHub PAT (classic) | GitHub | 2 |
| GitHub PAT (fine-grained) | GitHub | 1 |
| GitLab PAT | GitLab | 1 |
| Stripe Secret Key (live) | Stripe | 2 |
| Stripe Secret Key (test) | Stripe | 2 |
| Stripe Publishable Key (live) | Stripe | 1 |
| Twilio Account SID + Auth Token | Twilio | 2 |
| SendGrid API Key | SendGrid | 2 |
| Slack Bot Token | Slack | 2 |
| Slack Webhook URL | Slack | 2 |
| Mailgun API Key | Mailgun | 1 |
| RSA Private Key | Generic | 1 |
| ED25519 Private Key | Generic | 1 |
| JWT Signing Secret | Generic | 3 |
| Hardcoded Password | Generic | 4 |
| PostgreSQL Connection String | Generic | 3 |
| MySQL Connection String | Generic | 2 |
| MongoDB Connection String | Generic | 2 |
| Redis Connection String | Generic | 2 |
| Docker Registry Credentials | Docker | 1 |
| NPM Auth Token | NPM | 1 |
| PyPI Token | PyPI | 1 |
| Terraform Cloud Token | Terraform | 1 |

---

## Git History Test Cases

This repo's commit history includes secrets that were committed and later "deleted." These are **not** present in HEAD but exist in git history. Tools that scan full git history (TruffleHog, GitLeaks) should detect them. Tools that only scan HEAD (Detect-Secrets default) will miss them.

History-only secrets are documented in `secrets-manifest.csv` with `in_history_only = true`.

---

## False Positive Traps

The `fp-traps/` directory contains patterns that should NOT be flagged:
- Template placeholders: `your-api-key-here`, `<INSERT_TOKEN>`
- Environment variable references: `${API_KEY}`, `os.environ['SECRET']`
- SSH public keys (not private)
- Commented-out, obviously non-functional placeholder strings
- Test/example values from official documentation (e.g., AWS example key `AKIAIOSFODNN7EXAMPLE`)

A tool that flags any `fp-traps/` entry is generating a false positive.

---

## Usage in Benchmark Scoring

```
TPR = (secrets detected in HEAD that are in manifest with in_head=true AND is_fp_trap=false) / (total manifest entries with in_head=true AND is_fp_trap=false)

FPR = (secrets flagged in fp-traps/ that are in manifest with is_fp_trap=true) / (total manifest entries with is_fp_trap=true)

History TPR = (history-only secrets detected) / (total manifest entries with in_history_only=true)

Youden Index = TPR - FPR
```
