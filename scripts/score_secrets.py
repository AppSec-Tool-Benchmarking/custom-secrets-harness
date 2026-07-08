#!/usr/bin/env python3
"""
Secrets Scanner Scorer
======================
Scores tool output against the secrets-manifest.csv ground truth.

Supports output from:
  - GitLeaks      JSON   (gitleaks dir/git -f json -r findings.json ...)
  - BetterLeaks   JSON   (betterleaks dir/git -f json -r findings.json ...)
  - TruffleHog    JSONL  (trufflehog ... --json > findings.jsonl)
  - Kingfisher    JSONL  (kingfisher scan -f jsonl -o findings.jsonl ...)
  - Detect-Secrets JSON  (detect-secrets scan ... > findings.json)
  - Semgrep       JSON   (semgrep --config p/secrets --json > findings.json ...)
  - GitGuardian   JSON   (ggshield secret scan repo --json ... > findings.json)
  - GitLab SD     JSON   (gl-secret-detection-report.json artifact from CI pipeline)

Usage:
    python3 score_secrets.py \\
        --findings results/gitleaks/findings.json \\
        --manifest secrets-manifest.csv \\
        --tool "GitLeaks v8.30.1" \\
        --format gitleaks \\
        --output results/gitleaks/scorecard.csv

    # Score all tools at once (expects results/<tool>/findings.<ext>):
    python3 score_secrets.py --all --manifest secrets-manifest.csv

Manifest schema (secrets-manifest.csv):
    id, file_path, line_number, secret_type, provider, format_type,
    location_category, in_head, in_history_only, is_fp_trap, obfuscation_type, notes

Scoring logic:
    HEAD secrets  (in_head=true,  is_fp_trap=false, in_history_only=false):
        - tool flagged the file+line → TP
        - tool missed it             → FN

    FP traps      (is_fp_trap=true):
        - tool flagged it            → FP
        - tool ignored it            → TN

    History-only  (in_history_only=true):
        - tool flagged it            → History TP  (reported separately)
        - tool missed it             → History FN

Metrics (per secret_type category and overall):
    TPR        = TP  / (TP  + FN)
    FPR        = FP  / (FP  + TN)
    History TPR = History_TP / (History_TP + History_FN)
    Youden     = TPR - FPR          (range -1..+1)
    Youden_pct = (Youden + 1) / 2 * 100   (OWASP 0-100 scale)
    Precision  = TP  / (TP  + FP)
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOLS = {
    "gitleaks":       {"fmt": "gitleaks-json",        "ext": "json"},
    "betterleaks":    {"fmt": "gitleaks-json",         "ext": "json"},
    "trufflehog":     {"fmt": "trufflehog-jsonl",      "ext": "jsonl"},
    "kingfisher":     {"fmt": "kingfisher-jsonl",      "ext": "jsonl"},
    "detect-secrets": {"fmt": "detect-secrets-json",   "ext": "json"},
    "semgrep":        {"fmt": "semgrep-json",          "ext": "json"},
    "gitguardian":    {"fmt": "ggshield-json",         "ext": "json"},
    "gitlab-sd":      {"fmt": "gitlab-sd-json",        "ext": "json"},
}


# ---------------------------------------------------------------------------
# Load manifest
# ---------------------------------------------------------------------------

def load_manifest(csv_path):
    """
    Returns three structures:
      head_entries    : list of dicts for in_head=true, is_fp_trap=false, in_history_only=false
      fp_trap_entries : list of dicts for is_fp_trap=true
      history_entries : list of dicts for in_history_only=true

    Each dict has: id, file_path, line_number (int), secret_type, provider,
                   obfuscation_type, notes
    """
    head_entries    = []
    fp_trap_entries = []
    history_entries = []

    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = {
                "id":               row["id"].strip(),
                "file_path":        row["file_path"].strip(),
                "line_number":      int(row["line_number"].strip()),
                "secret_type":      row["secret_type"].strip(),
                "provider":         row["provider"].strip(),
                "obfuscation_type": row["obfuscation_type"].strip(),
                "notes":            row.get("notes", "").strip(),
            }
            in_head         = row["in_head"].strip().lower() == "true"
            in_history_only = row["in_history_only"].strip().lower() == "true"
            is_fp_trap      = row["is_fp_trap"].strip().lower() == "true"

            if in_history_only:
                history_entries.append(entry)
            elif is_fp_trap:
                fp_trap_entries.append(entry)
            elif in_head:
                head_entries.append(entry)
            # rows that are neither (e.g. is_fp_trap=true AND in_head=true) → fp_trap wins

    return head_entries, fp_trap_entries, history_entries


# ---------------------------------------------------------------------------
# Normalize file paths for matching
# Findings from tools often include absolute paths or repo-relative paths.
# We normalize both sides to their basename + parent dir suffix so that
# "source-code/aws_config.py" matches "/abs/path/to/repo/source-code/aws_config.py".
# ---------------------------------------------------------------------------

def normalize_path(path):
    """Return lowercase path with forward slashes, stripping leading separators."""
    return path.replace("\\", "/").lower().lstrip("/")


def path_matches(finding_path, manifest_path):
    """
    True if the finding's file path ends with the manifest's relative path.
    e.g. finding_path = "/Users/.../custom-secrets-harness/source-code/aws_config.py"
         manifest_path = "source-code/aws_config.py"
    """
    fp = normalize_path(finding_path)
    mp = normalize_path(manifest_path)
    return fp == mp or fp.endswith("/" + mp)


# ---------------------------------------------------------------------------
# Parse findings — one parser per tool format
# Returns: list of {"file_path": str, "line_number": int or None, "raw": dict}
# line_number may be None for tools that don't surface line numbers (detect-secrets hashes)
# ---------------------------------------------------------------------------

def parse_gitleaks_json(findings_path):
    """GitLeaks and BetterLeaks: JSON array of finding objects."""
    with open(findings_path) as f:
        data = json.load(f)
    if not data:  # gitleaks returns null/[] when nothing found
        return []
    results = []
    for item in data:
        # BetterLeaks adds an "Attributes" dict with path; fall back to "File"
        file_path   = item.get("File", "")
        line_number = item.get("StartLine") or item.get("Line")
        results.append({
            "file_path":   file_path,
            "line_number": int(line_number) if line_number else None,
            "raw":         item,
        })
    return results


def parse_trufflehog_jsonl(findings_path):
    """TruffleHog: newline-delimited JSON (one object per line)."""
    results = []
    with open(findings_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            # SourceMetadata.Data.<SourceType>.file  and  .line
            meta = item.get("SourceMetadata", {}).get("Data", {})
            file_path   = None
            line_number = None
            for source_type, payload in meta.items():
                if isinstance(payload, dict):
                    file_path   = payload.get("file") or payload.get("path")
                    line_number = payload.get("line")
                    break
            results.append({
                "file_path":   file_path or "",
                "line_number": int(line_number) if line_number else None,
                "raw":         item,
            })
    return results


def parse_kingfisher_jsonl(findings_path):
    """Kingfisher: newline-delimited JSON (one finding object per line)."""
    results = []
    with open(findings_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding     = item.get("finding", {})
            file_path   = finding.get("path", "")
            line_number = finding.get("line")
            # If git_metadata is present, prefer the canonical path there
            git_meta = finding.get("git_metadata", {})
            if git_meta:
                git_file = git_meta.get("file", {}).get("path")
                if git_file:
                    file_path = git_file
            results.append({
                "file_path":   file_path,
                "line_number": int(line_number) if line_number else None,
                "raw":         item,
            })
    return results


def parse_detect_secrets_json(findings_path):
    """
    detect-secrets: JSON with a "results" dict keyed by file path.
    Each value is a list of finding objects with "line_number" and "type".
    Note: line numbers are 1-indexed.
    """
    with open(findings_path) as f:
        data = json.load(f)
    results = []
    for file_path, findings in data.get("results", {}).items():
        for item in findings:
            line_number = item.get("line_number")
            results.append({
                "file_path":   file_path,
                "line_number": int(line_number) if line_number else None,
                "raw":         item,
            })
    return results


def parse_semgrep_json(findings_path):
    """Semgrep: JSON with a "results" list. Each has path and start.line."""
    with open(findings_path) as f:
        data = json.load(f)
    results = []
    for item in data.get("results", []):
        file_path   = item.get("path", "")
        line_number = item.get("start", {}).get("line")
        results.append({
            "file_path":   file_path,
            "line_number": int(line_number) if line_number else None,
            "raw":         item,
        })
    return results


def parse_ggshield_json(findings_path):
    """
    GitGuardian ggshield: JSON object with structure:
      { "scans": [ { "entities_with_incidents": [ { "filename": str, "incidents": [
          { "occurrences": [ { "line_start": int, ... } ] }
      ] } ] } ] }

    Flattens to one entry per (filename, line_start) occurrence.
    Note: ggshield redacts secret values — line_start is the primary match key.
    """
    with open(findings_path) as f:
        data = json.load(f)
    results = []
    for scan in data.get("scans", []):
        for entity in scan.get("entities_with_incidents", []):
            file_path = entity.get("filename", "")
            for incident in entity.get("incidents", []):
                for occ in incident.get("occurrences", []):
                    line_number = occ.get("line_start")
                    results.append({
                        "file_path":   file_path,
                        "line_number": int(line_number) if line_number else None,
                        "raw":         {"entity": file_path, "incident": incident,
                                        "occurrence": occ},
                    })
    return results


def parse_gitlab_sd_json(findings_path):
    """
    GitLab Secret Detection report: gl-secret-detection-report.json
    Structure: { "vulnerabilities": [ { "location": { "file": str, "start_line": int,
                "commit": { "sha": str } }, ... } ] }
    File paths are repo-relative (no leading slash).
    History findings have a non-HEAD commit sha in location.commit.sha.
    """
    with open(findings_path) as f:
        data = json.load(f)
    results = []
    for item in data.get("vulnerabilities", []):
        loc         = item.get("location", {})
        file_path   = loc.get("file", "")
        line_number = loc.get("start_line")
        results.append({
            "file_path":   file_path,
            "line_number": int(line_number) if line_number else None,
            "raw":         item,
        })
    return results


PARSERS = {
    "gitleaks-json":          parse_gitleaks_json,
    "betterleaks-json":       parse_gitleaks_json,
    "trufflehog-jsonl":       parse_trufflehog_jsonl,
    "kingfisher-jsonl":       parse_kingfisher_jsonl,
    "detect-secrets-json":    parse_detect_secrets_json,
    "semgrep-json":           parse_semgrep_json,
    "ggshield-json":          parse_ggshield_json,
    "gitlab-sd-json":         parse_gitlab_sd_json,
}


# ---------------------------------------------------------------------------
# Match findings against manifest entries
# Returns set of manifest IDs that the tool flagged
# ---------------------------------------------------------------------------

LINE_TOLERANCE = 2  # lines of slack for tools that report slightly different line numbers


def build_flagged_set(findings, manifest_entries):
    """
    For each manifest entry, check if any finding matches on file path
    and (optionally) line number within LINE_TOLERANCE.

    Returns set of manifest IDs considered detected.
    """
    flagged_ids = set()

    for entry in manifest_entries:
        for finding in findings:
            if not path_matches(finding["file_path"], entry["file_path"]):
                continue
            # Path matched. Check line number if available.
            f_line = finding["line_number"]
            m_line = entry["line_number"]
            if f_line is None:
                # Tool doesn't report line numbers (e.g. detect-secrets with no line) — count as match on path alone
                flagged_ids.add(entry["id"])
                break
            if abs(f_line - m_line) <= LINE_TOLERANCE:
                flagged_ids.add(entry["id"])
                break

    return flagged_ids


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------

def score_entries(head_entries, fp_trap_entries, history_entries, flagged_head,
                  flagged_fp, flagged_history):
    """
    Returns:
      cats        : dict provider -> {TP, FP, TN, FN}
      overall     : {TP, FP, TN, FN}
      history     : {TP, FN}
      detail_rows : list of per-entry result dicts for CSV output
    """
    cats    = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})
    overall = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    history = {"TP": 0, "FN": 0}
    detail_rows = []

    # HEAD secrets
    for entry in head_entries:
        detected = entry["id"] in flagged_head
        result   = "TP" if detected else "FN"
        cats[entry["provider"]][result] += 1
        overall[result] += 1
        detail_rows.append({**entry, "bucket": "head", "result": result})

    # FP traps
    for entry in fp_trap_entries:
        flagged = entry["id"] in flagged_fp
        result  = "FP" if flagged else "TN"
        cats[entry["provider"]][result] += 1
        overall[result] += 1
        detail_rows.append({**entry, "bucket": "fp_trap", "result": result})

    # History-only (separate from main TP/FP counts — reported independently)
    for entry in history_entries:
        detected = entry["id"] in flagged_history
        result   = "TP" if detected else "FN"
        history[result] += 1
        detail_rows.append({**entry, "bucket": "history", "result": result})

    return cats, overall, history, detail_rows


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_rates(counts):
    tp = counts.get("TP", 0)
    fp = counts.get("FP", 0)
    tn = counts.get("TN", 0)
    fn = counts.get("FN", 0)

    tpr       = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    youden    = tpr - fpr
    youden_pct = round((youden + 1) / 2 * 100, 1)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    return {
        "total":      tp + fp + tn + fn,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "TPR":        round(tpr * 100, 1),
        "FPR":        round(fpr * 100, 1),
        "Youden_raw": round(youden * 100, 1),
        "Youden_pct": youden_pct,
        "Precision":  round(precision * 100, 1),
    }


def compute_history_tpr(history):
    tp = history.get("TP", 0)
    fn = history.get("FN", 0)
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return {"TP": tp, "FN": fn, "total": tp + fn, "TPR": round(tpr * 100, 1)}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_table(tool_label, cats, overall, history):
    width = 74
    print(f"\n{'=' * width}")
    print(f"  Secrets Scanner Score — {tool_label}")
    print(f"{'=' * width}")
    print(f"{'Provider':<22} {'Tests':>6} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}  "
          f"{'TPR%':>6} {'FPR%':>6} {'Youden':>8} {'Prec%':>6}")
    print(f"{'-' * width}")

    for provider in sorted(cats.keys()):
        r = compute_rates(cats[provider])
        print(f"{provider:<22} {r['total']:>6} {r['TP']:>5} {r['FP']:>5} {r['FN']:>5} "
              f"{r['TN']:>5}  {r['TPR']:>5.1f}% {r['FPR']:>5.1f}% "
              f"{r['Youden_raw']:>+7.1f}% {r['Precision']:>5.1f}%")

    print(f"{'-' * width}")
    r = compute_rates(overall)
    print(f"{'OVERALL':<22} {r['total']:>6} {r['TP']:>5} {r['FP']:>5} {r['FN']:>5} "
          f"{r['TN']:>5}  {r['TPR']:>5.1f}% {r['FPR']:>5.1f}% "
          f"{r['Youden_raw']:>+7.1f}% {r['Precision']:>5.1f}%")
    print(f"\n  Overall Youden Index (OWASP 0–100 scale): {r['Youden_pct']}")
    print(f"  TPR: {r['TPR']}%   FPR: {r['FPR']}%   Precision: {r['Precision']}%")

    h = compute_history_tpr(history)
    print(f"\n  Git History Scanning: {h['TP']}/{h['total']} detected  "
          f"(History TPR: {h['TPR']}%)")
    print()


def write_scorecard_csv(output_path, tool_label, cats, overall, history, detail_rows):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Summary sheet
    summary_path = output_path
    with open(summary_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Tool", "Provider", "Tests", "TP", "FP", "FN", "TN",
                    "TPR%", "FPR%", "Youden_raw%", "Youden_pct_0-100", "Precision%"])
        for provider in sorted(cats.keys()):
            r = compute_rates(cats[provider])
            w.writerow([tool_label, provider, r["total"],
                        r["TP"], r["FP"], r["FN"], r["TN"],
                        r["TPR"], r["FPR"], r["Youden_raw"], r["Youden_pct"], r["Precision"]])
        r = compute_rates(overall)
        w.writerow([tool_label, "OVERALL", r["total"],
                    r["TP"], r["FP"], r["FN"], r["TN"],
                    r["TPR"], r["FPR"], r["Youden_raw"], r["Youden_pct"], r["Precision"]])
        h = compute_history_tpr(history)
        w.writerow([tool_label, "HISTORY", h["total"],
                    h["TP"], "", h["FN"], "",
                    h["TPR"], "", "", "", ""])
    print(f"Scorecard written: {summary_path}")

    # Detail sheet (per-entry result)
    detail_path = output_path.replace(".csv", "-detail.csv")
    with open(detail_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Tool", "id", "bucket", "file_path", "line_number", "secret_type",
                    "provider", "obfuscation_type", "result", "notes"])
        for row in detail_rows:
            w.writerow([tool_label, row["id"], row["bucket"], row["file_path"],
                        row["line_number"], row["secret_type"], row["provider"],
                        row["obfuscation_type"], row["result"], row["notes"]])
    print(f"Detail rows written: {detail_path}")


# ---------------------------------------------------------------------------
# Single-tool scoring entry point
# ---------------------------------------------------------------------------

def score_tool(findings_path, fmt, manifest_path, tool_label, output_path=None,
               repo_root=None):
    """
    Load manifest, parse findings, score, print, and optionally write CSV.
    repo_root: if set, prepend to manifest file_path entries when matching
               (useful when running from outside the repo dir).
    """
    print(f"\nLoading manifest: {manifest_path}")
    head_entries, fp_trap_entries, history_entries = load_manifest(manifest_path)
    print(f"  HEAD secrets:   {len(head_entries)}")
    print(f"  FP traps:       {len(fp_trap_entries)}")
    print(f"  History-only:   {len(history_entries)}")

    parser = PARSERS.get(fmt)
    if parser is None:
        sys.exit(f"Unknown format: {fmt}. Choices: {list(PARSERS.keys())}")

    print(f"Loading findings ({fmt}): {findings_path}")
    findings = parser(findings_path)
    print(f"  {len(findings)} findings loaded")

    flagged_head    = build_flagged_set(findings, head_entries)
    flagged_fp      = build_flagged_set(findings, fp_trap_entries)
    flagged_history = build_flagged_set(findings, history_entries)

    cats, overall, history, detail_rows = score_entries(
        head_entries, fp_trap_entries, history_entries,
        flagged_head, flagged_fp, flagged_history,
    )

    print_table(tool_label, cats, overall, history)

    if output_path:
        write_scorecard_csv(output_path, tool_label, cats, overall, history, detail_rows)


# ---------------------------------------------------------------------------
# --all mode: score every tool whose results dir exists
# ---------------------------------------------------------------------------

# Default RESULTS_ROOT — overridden at runtime by score_all() based on the manifest path.
RESULTS_ROOT = os.path.join(os.path.dirname(__file__), "..", "results")

ALL_TOOL_CONFIGS = [
    {"name": "gitleaks",       "fmt": "gitleaks-json",        "file": "findings.json"},
    {"name": "betterleaks",    "fmt": "gitleaks-json",         "file": "findings.json"},
    {"name": "trufflehog",     "fmt": "trufflehog-jsonl",      "file": "findings.jsonl"},
    {"name": "kingfisher",     "fmt": "kingfisher-jsonl",      "file": "findings.jsonl"},
    {"name": "detect-secrets", "fmt": "detect-secrets-json",   "file": "findings.json"},
    {"name": "semgrep",        "fmt": "semgrep-json",          "file": "findings.json"},
    {"name": "gitguardian",    "fmt": "ggshield-json",         "file": "findings.json"},
    {"name": "gitlab-sd",      "fmt": "gitlab-sd-json",        "file": "findings.json"},
]


def score_all(manifest_path):
    # Derive results root from the manifest's parent directory, not the script location.
    # This ensures the app repo scores against its own results/, not the harness results/.
    results_root = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), "results")
    found_any = False
    for cfg in ALL_TOOL_CONFIGS:
        findings_path = os.path.join(results_root, cfg["name"], cfg["file"])
        if not os.path.exists(findings_path):
            print(f"[skip] {cfg['name']}: {findings_path} not found")
            continue
        found_any = True
        output_path = os.path.join(results_root, cfg["name"], "scorecard.csv")
        score_tool(findings_path, cfg["fmt"], manifest_path,
                   tool_label=cfg["name"], output_path=output_path)
    if not found_any:
        print("No findings files found. Run the tools first and place output in "
              f"{results_root}/<toolname>/findings.<ext>")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Score secrets scanner output against secrets-manifest.csv ground truth.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Format values:
  gitleaks-json          GitLeaks and BetterLeaks JSON array output
  trufflehog-jsonl       TruffleHog JSONL output (--json flag)
  kingfisher-jsonl       Kingfisher JSONL output (-f jsonl)
  detect-secrets-json    detect-secrets JSON baseline output
  semgrep-json           Semgrep JSON output (--json)
  ggshield-json          GitGuardian ggshield JSON output (--json)

Examples:
  # Score a single tool
  python3 score_secrets.py \\
      --findings results/gitleaks/findings.json \\
      --manifest secrets-manifest.csv \\
      --tool "GitLeaks v8.30.1" \\
      --format gitleaks-json \\
      --output results/gitleaks/scorecard.csv

  # Score all tools at once
  python3 score_secrets.py --all --manifest secrets-manifest.csv

Expected results directory layout:
  custom-secrets-harness/
    results/
      gitleaks/findings.json
      betterleaks/findings.json
      trufflehog/findings.jsonl
      kingfisher/findings.jsonl
      detect-secrets/findings.json
      semgrep/findings.json
  gitguardian/findings.json
    secrets-manifest.csv
    scripts/score_secrets.py   ← this file
""",
    )
    parser.add_argument("--findings",  help="Path to tool output file")
    parser.add_argument("--manifest",  required=True,
                        help="Path to secrets-manifest.csv")
    parser.add_argument("--tool",      default="Tool",
                        help="Tool label for output (e.g. 'GitLeaks v8.30.1')")
    parser.add_argument("--format",    dest="fmt",
                        choices=list(PARSERS.keys()),
                        help="Tool output format (required unless --all)")
    parser.add_argument("--output",    default=None,
                        help="Path to write scorecard CSV (optional)")
    parser.add_argument("--all",       action="store_true",
                        help="Score all tools found under results/")
    args = parser.parse_args()

    if args.all:
        score_all(args.manifest)
    else:
        if not args.findings:
            parser.error("--findings is required unless --all is specified")
        if not args.fmt:
            parser.error("--format is required unless --all is specified")
        score_tool(args.findings, args.fmt, args.manifest,
                   tool_label=args.tool, output_path=args.output)


if __name__ == "__main__":
    main()
