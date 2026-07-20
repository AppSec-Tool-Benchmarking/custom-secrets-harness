#!/usr/bin/env python3
"""
parse_sonarcloud_results.py
============================
Converts SonarCloud/SonarQube Issues API secrets response into the
findings.json format expected by score_secrets.py (--format sonarcloud-json).

Usage:
    python3 scripts/parse_sonarcloud_results.py <input.json> <output.json> [repo_root_marker]

Input format (raw SonarCloud API response):
    {
        "total": N,
        "issues": [
            {
                "rule": "secrets:S6290",
                "component": "ORG_PROJECTKEY:relative/path/to/file.ext",
                "line": 20,
                "message": "Make sure this AWS Secret Access Key gets revoked...",
                ...
            }
        ]
    }

How to obtain:
    curl -H "Authorization: Bearer $SONAR_TOKEN" \\
        "https://sonarcloud.io/api/issues/search?componentKeys=<PROJECT_KEY>&languages=secrets&ps=500" \\
        -o results.json

    python3 scripts/parse_sonarcloud_results.py results.json results/sonarcloud/findings.json

Output JSON:
    [ { "file_path": str (repo-relative),
        "line_number": int|null,
        "rule": str,           # e.g. "secrets:S6290"
        "message": str,
        "severity": str,
        "raw": { ...full issue object... }
      }, ... ]

Notes:
- The "component" field format is "<projectKey>:<relative-path>". This script
  strips the projectKey prefix automatically.
- Rules starting with a non-secrets prefix (e.g. python:S1234) are filtered
  out — only issues where the SonarQube "language" facet is "secrets" should
  be in the input if you used the API call above with languages=secrets.
"""

import json
import os
import sys


def parse(input_path):
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    issues = data.get("issues", []) if isinstance(data, dict) else data

    findings = []
    for item in issues:
        rule = item.get("rule", "")
        # Only keep secrets: rules (defensive filter in case input wasn't pre-filtered)
        if rule and not rule.startswith("secrets:"):
            continue

        component = item.get("component", "")
        # component format: "<projectKey>:<relative/path>"
        if ":" in component:
            file_path = component.split(":", 1)[1]
        else:
            file_path = component

        line_number = item.get("line")

        findings.append({
            "file_path":   file_path,
            "line_number": int(line_number) if line_number else None,
            "rule":        rule,
            "message":     item.get("message", ""),
            "severity":    item.get("severity", ""),
            "raw":         item,
        })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 parse_sonarcloud_results.py <input.json> <output.json>")
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]

    findings = parse(input_path)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Parsed {len(findings)} findings → {output_path}")


if __name__ == "__main__":
    main()
