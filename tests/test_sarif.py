import json
from types import SimpleNamespace

from app.services.sarif import _security_severity, scan_sarif


def finding(risk_score: float, suffix: str):
    return SimpleNamespace(
        id=suffix,
        policy=SimpleNamespace(policy_key=f"CS-AWS-TST-{suffix}"),
        control_id=None,
        title="Test finding",
        remediation="Fix the test finding.",
        category="Test",
        provider="aws",
        severity="critical",
        fingerprint=f"fingerprint-{suffix}",
        risk_score=risk_score,
        file_path="main.tf",
        line_number=1,
    )


def test_sarif_security_severity_uses_github_scale_and_clamps():
    assert _security_severity(95) == "9.5"
    assert _security_severity(100) == "10.0"
    assert _security_severity(150) == "10.0"
    assert _security_severity(-10) == "0.0"


def test_sarif_keeps_cloudsentinel_risk_score_unchanged():
    payload = json.loads(scan_sarif(SimpleNamespace(findings=[finding(95, "001"), finding(100, "002"), finding(150, "003")])))
    run = payload["runs"][0]
    severities = [float(rule["properties"]["security-severity"]) for rule in run["tool"]["driver"]["rules"]]
    assert severities == [9.5, 10.0, 10.0]
    assert all(0 <= value <= 10 for value in severities)
    assert [result["properties"]["riskScore"] for result in run["results"]] == [95, 100, 150]
