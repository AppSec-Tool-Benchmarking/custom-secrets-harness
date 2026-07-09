#!/usr/bin/env python3
"""
parse_cycode_csv.py
===================
Converts a Cycode "All violations" CSV export into the findings.json
format expected by score_secrets.py (--format cycode-json).

Usage:
    python3 scripts/parse_cycode_csv.py \
        "Cycode - All violations - DATE.csv" \
        results/cycode/findings.json

Cycode CSV structure:
    Lines 0–N:  metadata header block ("Filter","Value" pairs)
    Line M:     column header row starting with "Violation Category"
    Lines M+1+: violation rows (multiline cells due to Tags field)

Output JSON:
    [ { "file_path": str,       # repo-relative path
        "line_number": int|null,
        "policy": str,
        "severity": str,
        "risk_score": str,
        "commit_sha": str|null,
        "repository": str,
        "secret_value": str,
        "raw": { ...full row... }
      }, ... ]
"""

import csv
import io
import json
import os
import re
import sys


def find_data_start(lines):
    for i, line in enumerate(lines):
        if '"Violation Category"' in line or line.startswith("Violation Category"):
            return i
    raise ValueError("Could not find data header row in CSV")


def extract_commit_sha(commit_field):
    """Extract raw SHA from Excel HYPERLINK formula or plain SHA."""
    m = re.search(r'commit/([a-f0-9]{40})', commit_field)
    if m:
        return m.group(1)
    if re.fullmatch(r'[a-f0-9]{40}', commit_field.strip()):
        return commit_field.strip()
    return None


def extract_repo_relative_path(resource_path, repo_name):
    """
    resource_path: /AppSec-Tool-Benchmarking/custom-secrets-harness/infrastructure/file.yml
    Returns:       infrastructure/file.yml
    """
    marker = f"/{repo_name}/"
    if marker in resource_path:
        return resource_path.split(marker, 1)[1]
    # Fallback: strip leading slashes and org prefix
    parts = resource_path.lstrip("/").split("/")
    if len(parts) > 2:
        return "/".join(parts[2:])
    return resource_path.lstrip("/")


def parse(csv_path, repo_name=None):
    lines = open(csv_path, encoding="utf-8-sig").readlines()
    data_start = find_data_start(lines)
    raw_data = "".join(lines[data_start:])

    reader = csv.DictReader(io.StringIO(raw_data))
    findings = []

    for row in reader:
        resource_path = row.get("Resource Path", "")
        repo = row.get("Repository", repo_name or "")

        # Determine repo name from resource path if not provided
        if not repo_name:
            # /Org/repo-name/path/to/file → repo-name
            parts = resource_path.lstrip("/").split("/")
            repo = parts[1] if len(parts) > 1 else repo

        file_path = extract_repo_relative_path(resource_path, repo)

        line_raw = row.get("Line Number", "").strip()
        try:
            line_number = int(line_raw)
        except (ValueError, TypeError):
            line_number = None

        commit_sha = extract_commit_sha(row.get("Commit ID", ""))

        findings.append({
            "file_path":    file_path,
            "line_number":  line_number,
            "policy":       row.get("Policy", "").strip(),
            "severity":     row.get("Severity", "").strip(),
            "risk_score":   row.get("Risk Score", "").strip(),
            "commit_sha":   commit_sha,
            "repository":   row.get("Repository", "").strip(),
            "secret_value": row.get("Secret Value", "").strip(),
            "raw":          dict(row),
        })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 parse_cycode_csv.py <input.csv> <output.json>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]
    repo_name   = sys.argv[3] if len(sys.argv) > 3 else None

    findings = parse(input_path, repo_name)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Parsed {len(findings)} findings → {output_path}")


if __name__ == "__main__":
    main()
