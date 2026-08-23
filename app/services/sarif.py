from __future__ import annotations

import json
from typing import Any

from app.models import Scan

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _security_severity(risk_score: float) -> str:
    """Convert CloudSentinel's 0-100 risk score to GitHub's SARIF 0.0-10.0 scale."""
    scaled = max(0.0, min(100.0, float(risk_score))) / 10
    rendered = f"{scaled:.2f}".rstrip("0")
    return rendered if not rendered.endswith(".") else f"{rendered}0"


def scan_sarif(scan: Scan) -> bytes:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in scan.findings:
        rule_id = finding.policy.policy_key if finding.policy else (finding.control_id or f"finding-{finding.id}")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation or "Review and remediate this finding."},
            "properties": {"security-severity": _security_severity(finding.risk_score), "tags": [finding.category, finding.provider]},
        })
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": LEVELS.get(finding.severity, "warning"),
            "message": {"text": finding.title},
            "fingerprints": {"cloudSentinel/v1": finding.fingerprint},
            "properties": {"severity": finding.severity, "riskScore": finding.risk_score},
        }
        if finding.file_path:
            region: dict[str, int] = {"startLine": max(1, finding.line_number or 1)}
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file_path, "uriBaseId": "%SRCROOT%"},
                "region": region,
            }}]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CloudSentinel", "version": "1.1.0", "informationUri": "https://github.com/sarahalqaisi/CloudSentinel", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2).encode()
