#!/usr/bin/env bash
# =============================================================================
# detect-secrets Hardened Scan — Real-World Tuning
# Usage: bash scripts/run_detect_secrets_hardened.sh
#
# This represents what a practitioner would configure on day 1 of a real
# engagement, WITHOUT knowledge of the specific test corpus contents.
# All suppressions are universally applicable patterns.
#
# What's suppressed and why:
#   --base64-limit 4.8       Minor entropy bump — standard noise reduction
#   --exclude-secrets        AWS documentation example keys (in every AWS tutorial)
#   --exclude-secrets        All-zeros Stripe test key (published format)
#   --exclude-secrets        Moto mock credential value ("testing")
#   --exclude-lines          ${VAR} shell expansion — not a secret value
#   --exclude-lines          os.environ / os.getenv — correct secret handling
#   --exclude-lines          YOUR_.*_HERE / <INSERT_.*> — universal placeholders
#   --exclude-lines          CHANGE_ME / REPLACE_WITH — universal placeholders
#   --exclude-lines          changeme / password123 — universal weak values
#   --exclude-lines          valueFrom.secretKeyRef — k8s reference, not value
#   --exclude-files README   Documentation files — acceptable to exclude
#   --exclude-files manifest CSV cataloguing secrets — artificial test artifact
#
# What's NOT suppressed (would require corpus knowledge):
#   - fp-traps/ directory (not excluded — practitioner wouldn't know it exists)
#   - test_examples.py (not excluded by path — real codebases have test files too)
#   - Public key files (not excluded — practitioner might want to audit these)
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
    --exclude-files "^results/" \
    --exclude-files "^scripts/" \
    --exclude-files "^\.cache_ggshield" \
    --exclude-files "^\.gitleaks-hardened\.toml" \
    --exclude-files "^README\.md" \
    --exclude-files "^secrets-manifest\.csv" \
    --exclude-secrets 'AKIAIOSFODNN7EXAMPLE' \
    --exclude-secrets 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
    --exclude-secrets 'sk_test_0{20,}' \
    --exclude-secrets '^testing$' \
    --exclude-lines '\$\{[A-Z_]+\}' \
    --exclude-lines 'os\.environ|os\.getenv' \
    --exclude-lines 'YOUR_[A-Z_]+_HERE|<INSERT_[^>]+>' \
    --exclude-lines 'CHANGE_ME|REPLACE_WITH|changeme|password123' \
    --exclude-lines 'valueFrom\.secretKeyRef|envFrom\.secretRef' \
    --exclude-lines 'azure[_-]?[Tt]enant[_-]?[Ii]d|AzureTenantId' \
    . > "$OUT/findings.json" 2>"$OUT/scan.log"

COUNT=$(python3 -c "
import json
d=json.load(open('$OUT/findings.json'))
print(sum(len(v) for v in d.get('results',{}).values()))
")
echo "detect-secrets hardened (real-world tuning): $COUNT findings → $OUT/findings.json"
