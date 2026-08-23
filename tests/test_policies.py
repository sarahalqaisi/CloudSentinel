from __future__ import annotations

from pathlib import Path

from app.config import settings
from app.services.parser import parse_tf_text
from app.services.policies import CHECKS, load_policy_file


def test_all_35_policy_files_are_valid():
    files = list(settings.policy_dir.rglob("*.yml"))
    assert len(files) == 35
    loaded = [load_policy_file(path) for path in files]
    assert all(item["check"] in CHECKS for item in loaded)


def test_public_admin_ingress_check_detects_ssh():
    resource = parse_tf_text('''resource "aws_security_group" "ssh" {\n ingress { from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"] }\n}''')[0]
    result = CHECKS["public_admin_ingress"](resource, [resource])
    assert result and result["from_port"] == 22


def test_lambda_secret_name_detection():
    resource = parse_tf_text('''resource "aws_lambda_function" "x" { environment { variables = { API_TOKEN = "placeholder" } } }''')[0]
    result = CHECKS["lambda_env_secrets"](resource, [resource])
    assert "API_TOKEN" in result["suspicious_keys"]


def test_policy_schema_rejects_invalid_severity(tmp_path):
    policy = tmp_path / "invalid.yml"
    policy.write_text("id: CS-AWS-TST-001\ntitle: Test\nseverity: urgent\ncategory: Test\ncheck: public_admin_ingress\nremediation: Fix it\n")
    try:
        load_policy_file(policy)
    except ValueError as exc:
        assert "severity" in str(exc)
    else:
        raise AssertionError("invalid policy should be rejected")
