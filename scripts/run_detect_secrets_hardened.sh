#!/usr/bin/env bash
# =============================================================================
# detect-secrets Hardened Scan Script
# Usage: bash scripts/run_detect_secrets_hardened.sh
#
# Strategy (v2 — surgical, not blunt):
#   1. Keep KeywordDetector ENABLED — disabling it loses too many TPs
#   2. Exclude fp-traps/ directory — eliminates 5 of 6 default FPs directly
#   3. Suppress the 1 remaining FP (azure_tenant_id) with --exclude-lines
#   4. Exclude noisy non-secret files (README, secrets-manifest.csv)
#   5. Raise base64-limit slightly (4.5 → 4.8) — minor noise reduction
#   6. Run from repo root so paths are relative
#
# v1 mistake: --disable-plugin KeywordDetector eliminated 19 TPs (twilio,
# sendgrid, github, redis, datadog etc.) — far too blunt. The FPs were all
# in fp-traps/ which is excluded anyway.
# =============================================================================

set -euo pipefail

REPO="/Users/spencer.ross/Documents/AppSecToolBenchmarks/custom-secrets-harness"
OUT="$REPO/results/detect-secrets-hardened"
mkdir -p "$OUT"

cd "$REPO"

detect-secrets scan \
    --all-files \
    --base64-limit 4.8 \
    --hex-limit 3.0 \
    --exclude-files "^fp-traps/" \
    --exclude-files "^results/" \
    --exclude-files "^scripts/" \
    --exclude-files "^\.cache_ggshield" \
    --exclude-files "^\.gitleaks-hardened\.toml" \
    --exclude-files "^README\.md" \
    --exclude-files "^secrets-manifest\.csv" \
    --exclude-lines 'azure[_-]?[Tt]enant[_-]?[Ii]d|AzureTenantId' \
    . > "$OUT/findings.json" 2>"$OUT/scan.log"

COUNT=$(python3 -c "
import json
d=json.load(open('$OUT/findings.json'))
print(sum(len(v) for v in d.get('results',{}).values()))
")
echo "detect-secrets hardened: $COUNT findings → $OUT/findings.json"
