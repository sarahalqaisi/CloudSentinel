from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Policy


def _config(resource) -> dict[str, Any]:
    if isinstance(resource, dict):
        value = resource.get("configuration", resource)
    else:
        value = getattr(resource, "configuration", {})
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


def _walk(data: Any, path: str, default=None):
    current = data
    for part in path.split(".") if path else []:
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return default
        elif isinstance(current, dict):
            if part not in current:
                return default
            current = current[part]
        else:
            return default
    return current


def _listify(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def public_admin_ingress(resource, all_resources):
    for rule in _listify(_config(resource).get("ingress")):
        if not isinstance(rule, dict):
            continue
        cidrs = _listify(rule.get("cidr_blocks")) + _listify(rule.get("ipv6_cidr_blocks"))
        start = rule.get("from_port")
        end = rule.get("to_port", start)
        public = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)
        if public and isinstance(start, int) and isinstance(end, int):
            if any(start <= port <= end for port in (22, 3389, 3306, 5432, 1433, 27017, 9200)):
                return {"cidrs": cidrs, "from_port": start, "to_port": end}
    return None


def public_all_ingress(resource, all_resources):
    for rule in _listify(_config(resource).get("ingress")):
        if not isinstance(rule, dict):
            continue
        cidrs = _listify(rule.get("cidr_blocks")) + _listify(rule.get("ipv6_cidr_blocks"))
        if any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs):
            if rule.get("protocol") in {"-1", "all"} or rule.get("from_port") in {0, None}:
                return {"cidrs": cidrs, "protocol": rule.get("protocol")}
    return None


def s3_public_acl(resource, all_resources):
    acl = _config(resource).get("acl")
    return {"acl": acl} if acl in {"public-read", "public-read-write", "authenticated-read"} else None


def public_access_block_disabled(resource, all_resources):
    config = _config(resource)
    keys = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
    disabled = [key for key in keys if config.get(key) is not True]
    return {"disabled_or_missing": disabled} if disabled else None


def missing_companion(resource, all_resources, resource_type: str):
    return None if any(item.resource_type == resource_type for item in all_resources) else {"missing_resource_type": resource_type}


def s3_encryption_missing(resource, all_resources):
    return missing_companion(resource, all_resources, "aws_s3_bucket_server_side_encryption_configuration")


def s3_versioning_missing(resource, all_resources):
    companions = [item for item in all_resources if item.resource_type == "aws_s3_bucket_versioning"]
    if not companions:
        return {"missing_resource_type": "aws_s3_bucket_versioning"}
    enabled = any(str(_walk(_config(item), "versioning_configuration.0.status", "")).lower() == "enabled" for item in companions)
    return None if enabled else {"versioning": "not enabled"}


def bool_false(path: str):
    def check(resource, all_resources):
        value = _walk(_config(resource), path)
        return {path: value} if value is False else None
    return check


def bool_not_true(path: str):
    def check(resource, all_resources):
        value = _walk(_config(resource), path)
        return {path: value} if value is not True else None
    return check


def missing_or_empty(path: str):
    def check(resource, all_resources):
        value = _walk(_config(resource), path)
        return {path: value} if value in (None, "", [], {}) else None
    return check


def numeric_less(path: str, minimum: float):
    def check(resource, all_resources):
        value = _walk(_config(resource), path)
        try:
            bad = float(value) < minimum
        except (TypeError, ValueError):
            bad = True
        return {path: value, "minimum": minimum} if bad else None
    return check


def iam_wildcard(resource, all_resources):
    raw = _config(resource).get("policy")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {"policy": "wildcard pattern in dynamic policy"} if '"*"' in raw or "'*'" in raw else None
    if not isinstance(raw, dict):
        return None
    for statement in _listify(raw.get("Statement")):
        if not isinstance(statement, dict):
            continue
        actions = _listify(statement.get("Action"))
        resources = _listify(statement.get("Resource"))
        if "*" in actions and "*" in resources:
            return {"Action": actions, "Resource": resources}
    return None


def access_key_present(resource, all_resources):
    return {"access_key": "Terraform-managed long-lived credential"}


def lambda_env_secrets(resource, all_resources):
    config = _config(resource)
    variables = _walk(config, "environment.0.variables", {}) or _walk(config, "environment.variables", {}) or {}
    keywords = ("secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "access_key")
    matches = [key for key in variables if any(word in key.lower() for word in keywords)] if isinstance(variables, dict) else []
    return {"suspicious_keys": matches} if matches else None


def privileged_container(resource, all_resources):
    raw = _config(resource).get("container_definitions")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {"container_definitions": "contains privileged=true"} if "privileged" in raw and "true" in raw.lower() else None
    for container in _listify(raw):
        if isinstance(container, dict) and container.get("privileged") is True:
            return {"container": container.get("name"), "privileged": True}
    return None


def weak_password_policy(resource, all_resources):
    config = _config(resource)
    problems = {}
    if (config.get("minimum_password_length") or 0) < 14:
        problems["minimum_password_length"] = config.get("minimum_password_length")
    for key in ("require_lowercase_characters", "require_uppercase_characters", "require_numbers", "require_symbols"):
        if config.get(key) is not True:
            problems[key] = config.get(key)
    if (config.get("max_password_age") or 999) > 90:
        problems["max_password_age"] = config.get("max_password_age")
    return problems or None


def missing_resource_type_factory(resource_type: str):
    def check(resource, all_resources):
        return {"missing_resource_type": resource_type} if not any(item.resource_type == resource_type for item in all_resources) else None
    return check


def default_sg_rules(resource, all_resources):
    config = _config(resource)
    return {"ingress": config.get("ingress"), "egress": config.get("egress")} if config.get("ingress") or config.get("egress") else None


def secret_recovery_zero(resource, all_resources):
    value = _config(resource).get("recovery_window_in_days")
    return {"recovery_window_in_days": value} if value in (0, "0") else None


def api_gateway_logging_missing(resource, all_resources):
    config = _config(resource)
    return {"access_log_settings": config.get("access_log_settings")} if not config.get("access_log_settings") else None


CHECKS: dict[str, Callable] = {
    "public_admin_ingress": public_admin_ingress,
    "public_all_ingress": public_all_ingress,
    "s3_public_acl": s3_public_acl,
    "public_access_block_disabled": public_access_block_disabled,
    "s3_encryption_missing": s3_encryption_missing,
    "s3_versioning_missing": s3_versioning_missing,
    "rds_public": lambda resource, _: {"publicly_accessible": True} if _config(resource).get("publicly_accessible") is True else None,
    "rds_unencrypted": bool_false("storage_encrypted"),
    "rds_backup_short": numeric_less("backup_retention_period", 7),
    "rds_deletion_protection": bool_not_true("deletion_protection"),
    "iam_wildcard": iam_wildcard,
    "access_key_present": access_key_present,
    "weak_password_policy": weak_password_policy,
    "cloudtrail_validation_disabled": bool_not_true("enable_log_file_validation"),
    "kms_rotation_disabled": bool_not_true("enable_key_rotation"),
    "ebs_unencrypted": bool_false("encrypted"),
    "alb_deletion_protection": bool_not_true("enable_deletion_protection"),
    "ec2_public_ip": lambda resource, _: {"associate_public_ip_address": True} if _config(resource).get("associate_public_ip_address") is True else None,
    "lambda_env_secrets": lambda_env_secrets,
    "secret_recovery_zero": secret_recovery_zero,
    "eks_public_endpoint": lambda resource, _: {"endpoint_public_access": True} if _config(resource).get("endpoint_public_access") is True else None,
    "privileged_container": privileged_container,
    "sqs_unencrypted": missing_or_empty("kms_master_key_id"),
    "sns_unencrypted": missing_or_empty("kms_master_key_id"),
    "dynamodb_pitr_missing": bool_not_true("point_in_time_recovery.0.enabled"),
    "default_sg_rules": default_sg_rules,
    "log_retention_short": numeric_less("retention_in_days", 30),
    "api_gateway_logging_missing": api_gateway_logging_missing,
    "missing_cloudtrail": missing_resource_type_factory("aws_cloudtrail"),
    "missing_vpc_flow_logs": missing_resource_type_factory("aws_flow_log"),
    "missing_config_recorder": missing_resource_type_factory("aws_config_configuration_recorder"),
    "missing_guardduty": missing_resource_type_factory("aws_guardduty_detector"),
    "missing_securityhub": missing_resource_type_factory("aws_securityhub_account"),
    "azure_storage_public": lambda resource, _: {"allow_nested_items_to_be_public": True} if _config(resource).get("allow_nested_items_to_be_public") is True else None,
    "gcp_bucket_public": lambda resource, _: {"public_access_prevention": _config(resource).get("public_access_prevention")} if _config(resource).get("public_access_prevention") not in {"enforced", True} else None,
}


def load_policy_file(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Policy {path.name} must contain a mapping")
    required = {"id", "title", "severity", "category", "check", "remediation"}
    missing = required - set(data)
    if missing:
        raise ValueError(f"Policy {path.name} missing: {', '.join(sorted(missing))}")
    if data["check"] not in CHECKS:
        raise ValueError(f"Unknown check {data['check']} in {path.name}")
    return data


def import_policies(db: Session) -> tuple[int, int]:
    created = updated = 0
    for path in sorted(settings.policy_dir.rglob("*.yml")):
        data = load_policy_file(path)
        policy = db.scalar(select(Policy).where(Policy.policy_key == data["id"]))
        values = {
            "title": data["title"],
            "description": data.get("description", ""),
            "severity": data["severity"],
            "category": data["category"],
            "provider": data.get("provider", "aws"),
            "framework": data.get("framework", "CloudSentinel Baseline"),
            "control_id": data.get("control_id"),
            "scope": data.get("scope", "resource"),
            "resource_types": json.dumps(data.get("resource_types", [])),
            "check_name": data["check"],
            "remediation": data["remediation"],
            "yaml_content": path.read_text(encoding="utf-8"),
            "enabled": data.get("enabled", True),
            "version": int(data.get("version", 1)),
        }
        if policy:
            for key, value in values.items():
                setattr(policy, key, value)
            updated += 1
        else:
            db.add(Policy(policy_key=data["id"], **values))
            created += 1
    db.commit()
    return created, updated


def policy_resource_types(policy: Policy) -> list[str]:
    try:
        return json.loads(policy.resource_types or "[]")
    except json.JSONDecodeError:
        return []


def evaluate(policy: Policy, resource, all_resources):
    return CHECKS[policy.check_name](resource, all_resources)
