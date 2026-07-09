#!/usr/bin/env python3
"""
parse_cxone_results.py
======================
Converts Checkmarx One (CxOne) Secret Detection API results into the
findings.json format expected by score_secrets.py (--format checkmarx-json).

Usage:
    python3 scripts/parse_cxone_results.py <input.json> <output.json>

Input format (CxOne API response body):
    {
        "results": [
            {
                "type": "sscs-secret-detection",
                "severity": "HIGH",
                "data": {
                    "ruleName": "Stripe-Access-Token",
                    "fileName": "/source-code/payments.py",
                    "line": 17,
                    "snippet": "sk_l***",
                    "validity": "Unknown"
                },
                ...
            }
        ],
        "totalCount": N
    }

How to obtain:
    1. Get bearer token:
       curl -X POST \\
           "https://us.iam.checkmarx.net/auth/realms/<tenant>/protocol/openid-connect/token" \\
           -d "grant_type=refresh_token&client_id=ast-app&refresh_token=<API_KEY>" \\
           | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"

    2. Get project ID:
       curl "https://us.ast.checkmarx.net/api/projects/?limit=100" \\
           -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

    3. Get latest scan ID for project:
       curl "https://us.ast.checkmarx.net/api/scans/?project-id=<ID>&limit=1&sort=-created_at" \\
           -H "Authorization: Bearer $TOKEN"

    4. Get secret detection results:
       curl "https://us.ast.checkmarx.net/api/results/?scan-id=<SCAN_ID>&type=sscs-secret-detection&limit=1000" \\
           -H "Authorization: Bearer $TOKEN" > results.json

    5. Parse:
       python3 scripts/parse_cxone_results.py results.json results/checkmarx/findings.json

Output JSON:
    [ { "file_path": str,        # repo-relative path (leading slash stripped)
        "line_number": int|null,
        "rule_name": str,
        "severity": str,
        "validity": str,
        "snippet": str,
        "raw": { ...full result object... }
      }, ... ]
"""

import json
import os
import sys


def parse(input_path):
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    # Accept both { "results": [...] } and a bare list
    if isinstance(data, list):
        results = data
    else:
        results = data.get("results", [])

    findings = []
    for item in results:
        # Filter to secret detection only (skip SAST/SCA/etc. if mixed)
        if item.get("type") and "secret" not in item["type"].lower():
            continue

        d = item.get("data", {})
        file_path = d.get("fileName", "").lstrip("/")
        line_raw  = d.get("line")
        try:
            line_number = int(line_raw)
        except (TypeError, ValueError):
            line_number = None

        findings.append({
            "file_path":   file_path,
            "line_number": line_number,
            "rule_name":   d.get("ruleName", ""),
            "severity":    item.get("severity", ""),
            "validity":    d.get("validity", ""),
            "snippet":     d.get("snippet", ""),
            "raw":         item,
        })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 parse_cxone_results.py <input.json> <output.json>")
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
