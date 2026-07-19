from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.services.parser import ParseError, parse_json_data, parse_path, parse_tf_text, safe_extract_zip


def test_parses_terraform_resource_and_nested_ingress():
    resources = parse_tf_text('''resource "aws_security_group" "ssh" {\n ingress { from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"] }\n}''')
    assert len(resources) == 1
    resource = resources[0]
    assert resource.address == "aws_security_group.ssh"
    assert resource.configuration["ingress"][0]["from_port"] == 22


def test_parses_plan_json():
    data = {"planned_values": {"root_module": {"resources": [{"address": "aws_s3_bucket.demo", "type": "aws_s3_bucket", "name": "demo", "values": {"acl": "public-read"}}]}}}
    resources = parse_json_data(data, "plan.json")
    assert resources[0].provider == "aws"
    assert resources[0].configuration["acl"] == "public-read"


def test_safe_zip_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.tf", 'resource "aws_s3_bucket" "x" {}')
    with pytest.raises(ParseError):
        safe_extract_zip(archive, tmp_path / "extract")


def test_parses_safe_zip(tmp_path: Path):
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("infra/main.tf", 'resource "aws_ebs_volume" "x" { encrypted = false }')
    resources = parse_path(archive, tmp_path / "extract")
    assert [item.resource_type for item in resources] == ["aws_ebs_volume"]
