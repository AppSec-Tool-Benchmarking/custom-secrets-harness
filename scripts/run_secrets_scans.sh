#!/usr/bin/env bash
# =============================================================================
# run_secrets_scans.sh
# =============================================================================
# Runs all local secret scanning tools against the custom-secrets-harness and
# custom-secrets-app repos, saves findings, then scores each tool against the
# ground-truth manifest.
#
# Usage:
#   cd custom-secrets-harness
#   bash scripts/run_secrets_scans.sh [OPTIONS]
#
# Options:
#   --harness-only    Only scan custom-secrets-harness (default: both repos)
#   --app-only        Only scan custom-secrets-app
#   --score-only      Skip scanning, just re-score existing findings files
#   --tool TOOLNAME   Only run a specific tool (gitleaks, betterleaks,
#                     trufflehog, kingfisher, detect-secrets, semgrep,
#                     gitguardian)
#   --no-validate     Pass --no-validate / disable live API calls where supported
#   -h, --help        Show this help
#
# Output layout:
#   custom-secrets-harness/results/<toolname>/findings.<ext>
#   custom-secrets-harness/results/<toolname>/scorecard.csv
#   custom-secrets-harness/results/<toolname>/scorecard-detail.csv
#   custom-secrets-app/results/<toolname>/findings.<ext>
#   custom-secrets-app/results/<toolname>/scorecard.csv
#   custom-secrets-app/results/<toolname>/scorecard-detail.csv
#
# Requirements:
#   gitleaks, betterleaks, trufflehog, kingfisher, detect-secrets,
#   semgrep, ggshield (GitGuardian CLI)
#
# GitGuardian note:
#   ggshield authenticates via OAuth token stored in the system keyring.
#   Run `ggshield auth login` once if not already authenticated.
#   No API key env var needed.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$(cd "$HARNESS_DIR/../custom-secrets-app" && pwd)"
SCORER="$SCRIPT_DIR/score_secrets.py"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RUN_HARNESS=true
RUN_APP=true
SCORE_ONLY=false
ONLY_TOOL=""
NO_VALIDATE=false

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --harness-only) RUN_APP=false ;;
        --app-only)     RUN_HARNESS=false ;;
        --score-only)   SCORE_ONLY=true ;;
        --tool)         ONLY_TOOL="$2"; shift ;;
        --no-validate)  NO_VALIDATE=true ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# ===\+$/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "[warn] Unknown argument: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }

check_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        warn "$tool not found in PATH — skipping"
        return 1
    fi
    return 0
}

should_run() {
    local tool="$1"
    [[ -z "$ONLY_TOOL" || "$ONLY_TOOL" == "$tool" ]]
}

run_scorer() {
    local results_dir="$1"
    local manifest="$2"
    python3 "$SCORER" --all --manifest "$manifest" 2>&1 \
        | grep -v "^$" \
        || true
}

# ---------------------------------------------------------------------------
# Tool runners — each function takes (repo_dir, results_dir)
# ---------------------------------------------------------------------------

run_gitleaks() {
    local repo="$1" out="$2"
    local version; version=$(gitleaks version 2>/dev/null || echo "unknown")
    log "GitLeaks $version — scanning $repo"
    mkdir -p "$out/gitleaks"

    # Full git history scan
    gitleaks git \
        --no-banner \
        --exit-code 0 \
        -f json \
        -r "$out/gitleaks/findings.json" \
        "$repo" 2>"$out/gitleaks/scan.log" || true

    # Normalize null output (gitleaks writes null when no findings)
    python3 - <<EOF
import json, pathlib
p = pathlib.Path("$out/gitleaks/findings.json")
if p.exists():
    raw = p.read_text().strip()
    if raw in ("", "null"):
        p.write_text("[]")
EOF
    local count; count=$(python3 -c "import json; d=json.load(open('$out/gitleaks/findings.json')); print(len(d) if d else 0)" 2>/dev/null || echo "?")
    log "  GitLeaks: $count findings → $out/gitleaks/findings.json"
}

run_betterleaks() {
    local repo="$1" out="$2"
    local version; version=$(betterleaks version 2>/dev/null || echo "unknown")
    log "BetterLeaks $version — scanning $repo"
    mkdir -p "$out/betterleaks"

    betterleaks git \
        --no-banner \
        --exit-code 0 \
        -f json \
        -r "$out/betterleaks/findings.json" \
        "$repo" 2>"$out/betterleaks/scan.log" || true

    python3 - <<EOF
import json, pathlib
p = pathlib.Path("$out/betterleaks/findings.json")
if p.exists():
    raw = p.read_text().strip()
    if raw in ("", "null"):
        p.write_text("[]")
EOF
    local count; count=$(python3 -c "import json; d=json.load(open('$out/betterleaks/findings.json')); print(len(d) if d else 0)" 2>/dev/null || echo "?")
    log "  BetterLeaks: $count findings → $out/betterleaks/findings.json"
}

run_trufflehog() {
    local repo="$1" out="$2"
    local version; version=$(trufflehog --version 2>/dev/null | head -1 || echo "unknown")
    log "TruffleHog $version — scanning $repo"
    mkdir -p "$out/trufflehog"

    local validate_flag=""
    $NO_VALIDATE && validate_flag="--no-verification"

    # file:// URI required for local git repos
    trufflehog git \
        --json \
        $validate_flag \
        "file://$repo" \
        >"$out/trufflehog/findings.jsonl" \
        2>"$out/trufflehog/scan.log" || true

    local count; count=$(wc -l < "$out/trufflehog/findings.jsonl" 2>/dev/null || echo "?")
    log "  TruffleHog: ~$count findings → $out/trufflehog/findings.jsonl"
}

run_kingfisher() {
    local repo="$1" out="$2"
    local version; version=$(kingfisher --version 2>/dev/null || echo "unknown")
    log "Kingfisher $version — scanning $repo"
    mkdir -p "$out/kingfisher"

    local validate_flag=""
    $NO_VALIDATE && validate_flag="--no-validate"

    # Default scans full git history (--git-history full is the default)
    kingfisher scan \
        -f jsonl \
        -o "$out/kingfisher/findings.jsonl" \
        $validate_flag \
        "$repo" \
        2>"$out/kingfisher/scan.log" || true

    local count; count=$(wc -l < "$out/kingfisher/findings.jsonl" 2>/dev/null || echo "?")
    log "  Kingfisher: ~$count findings → $out/kingfisher/findings.jsonl"
}

run_detect_secrets() {
    local repo="$1" out="$2"
    local version; version=$(detect-secrets --version 2>/dev/null || echo "unknown")
    log "detect-secrets $version — scanning $repo"
    mkdir -p "$out/detect-secrets"

    # detect-secrets only scans HEAD; --all-files includes untracked
    detect-secrets scan \
        --all-files \
        "$repo" \
        >"$out/detect-secrets/findings.json" \
        2>"$out/detect-secrets/scan.log" || true

    local count; count=$(python3 -c "
import json
d=json.load(open('$out/detect-secrets/findings.json'))
print(sum(len(v) for v in d.get('results',{}).values()))
" 2>/dev/null || echo "?")
    log "  detect-secrets: $count findings → $out/detect-secrets/findings.json"
}

run_semgrep() {
    local repo="$1" out="$2"
    local version; version=$(semgrep --version 2>/dev/null || echo "unknown")
    log "Semgrep $version — scanning $repo"
    mkdir -p "$out/semgrep"

    # p/secrets is the community secrets ruleset; HEAD only (semgrep doesn't scan git history)
    semgrep \
        --config "p/secrets" \
        --json \
        --quiet \
        "$repo" \
        >"$out/semgrep/findings.json" \
        2>"$out/semgrep/scan.log" || true

    local count; count=$(python3 -c "import json; d=json.load(open('$out/semgrep/findings.json')); print(len(d.get('results',[])))" 2>/dev/null || echo "?")
    log "  Semgrep: $count findings → $out/semgrep/findings.json"
}

run_gitguardian() {
    local repo="$1" out="$2"
    local version; version=$(ggshield --version 2>/dev/null | head -1 || echo "unknown")
    log "GitGuardian ggshield $version — scanning $repo"
    mkdir -p "$out/gitguardian"

    # ggshield authenticates via OAuth token stored in the system keyring.
    # No API key env var required — auth was set up with `ggshield auth login`.
    # repo subcommand scans full git history.
    ggshield secret scan repo \
        --json \
        --exit-zero \
        --output "$out/gitguardian/findings.json" \
        "$repo" \
        2>"$out/gitguardian/scan.log" || true

    local count; count=$(python3 -c "
import json
d=json.load(open('$out/gitguardian/findings.json'))
print(d.get('total_occurrences', '?'))
" 2>/dev/null || echo "?")
    log "  GitGuardian: $count occurrences → $out/gitguardian/findings.json"
}

# ---------------------------------------------------------------------------
# Scan a single repo
# ---------------------------------------------------------------------------

scan_repo() {
    local repo="$1"
    local manifest="$2"
    local label="$3"
    local results_dir="$repo/results"

    echo ""
    echo "======================================================================"
    echo "  Scanning: $label"
    echo "  Repo:     $repo"
    echo "  Results:  $results_dir"
    echo "======================================================================"

    if ! $SCORE_ONLY; then
        should_run "gitleaks"       && check_tool gitleaks       && run_gitleaks       "$repo" "$results_dir"
        should_run "betterleaks"    && check_tool betterleaks    && run_betterleaks    "$repo" "$results_dir"
        should_run "trufflehog"     && check_tool trufflehog     && run_trufflehog     "$repo" "$results_dir"
        should_run "kingfisher"     && check_tool kingfisher     && run_kingfisher     "$repo" "$results_dir"
        should_run "detect-secrets" && check_tool detect-secrets && run_detect_secrets "$repo" "$results_dir"
        should_run "semgrep"        && check_tool semgrep        && run_semgrep        "$repo" "$results_dir"
        should_run "gitguardian"    && check_tool ggshield       && run_gitguardian    "$repo" "$results_dir"
    else
        log "Score-only mode — skipping scans"
    fi

    echo ""
    log "Scoring all tools for $label..."
    # Override the RESULTS_ROOT in the scorer by running it from inside the repo
    python3 "$SCORER" --all --manifest "$manifest" 2>&1 || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ""
echo "======================================================================"
echo "  Secrets Scanner Benchmark Runner"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================================================"

if $RUN_HARNESS; then
    if [[ -d "$HARNESS_DIR" ]]; then
        scan_repo "$HARNESS_DIR" \
                  "$HARNESS_DIR/secrets-manifest.csv" \
                  "custom-secrets-harness"
    else
        err "Harness directory not found: $HARNESS_DIR"
    fi
fi

if $RUN_APP; then
    if [[ -d "$APP_DIR" ]]; then
        scan_repo "$APP_DIR" \
                  "$APP_DIR/secrets-manifest.csv" \
                  "custom-secrets-app"
    else
        warn "custom-secrets-app not found at $APP_DIR — skipping"
    fi
fi

echo ""
log "All done. Results written to:"
$RUN_HARNESS && echo "  $HARNESS_DIR/results/"
$RUN_APP     && [[ -d "$APP_DIR" ]] && echo "  $APP_DIR/results/"
echo ""
