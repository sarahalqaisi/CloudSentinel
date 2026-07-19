from __future__ import annotations

import json
from collections import Counter, defaultdict

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models import CloudResource, Finding, Policy, Scan


def dashboard_stats(db: Session) -> dict:
    latest = db.scalar(select(Scan).order_by(desc(Scan.id)).limit(1))
    return {
        "security_score": latest.security_score if latest else 100,
        "grade": latest.grade if latest else "A",
        "critical": db.scalar(select(func.count()).select_from(Finding).where(Finding.severity == "critical", Finding.status == "open")) or 0,
        "open_findings": db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0,
        "resources": latest.resource_count if latest else 0,
        "scans": db.scalar(select(func.count()).select_from(Scan)) or 0,
        "policies": db.scalar(select(func.count()).select_from(Policy).where(Policy.enabled.is_(True))) or 0,
        "latest": latest,
    }


def chart_data(db: Session) -> dict:
    scans = list(db.scalars(select(Scan).order_by(Scan.id).limit(12)).all())
    severity = Counter(finding.severity for finding in db.scalars(select(Finding)).all())
    category = Counter(finding.category for finding in db.scalars(select(Finding)).all())
    provider = Counter(resource.provider for resource in db.scalars(select(CloudResource)).all())
    return {
        "scores": {"labels": [scan.name[:18] for scan in scans], "values": [scan.security_score for scan in scans]},
        "severity": {"labels": ["critical", "high", "medium", "low", "info"], "values": [severity.get(key, 0) for key in ["critical", "high", "medium", "low", "info"]]},
        "categories": {"labels": [key for key, _ in category.most_common(8)], "values": [value for _, value in category.most_common(8)]},
        "providers": {"labels": [key.upper() for key, _ in provider.most_common(6)], "values": [value for _, value in provider.most_common(6)]},
    }


def compliance_matrix(db: Session, scan_id: int | None = None) -> list[dict]:
    policies = list(db.scalars(select(Policy).where(Policy.enabled.is_(True)).order_by(Policy.framework, Policy.control_id)).all())
    query = select(Finding)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    failed = Counter(finding.policy_id for finding in db.scalars(query).all())
    groups = defaultdict(lambda: {"controls": 0, "passed": 0, "failed": 0, "critical": 0, "score": 100})
    for policy in policies:
        group = groups[policy.framework]
        group["controls"] += 1
        if failed[policy.id]:
            group["failed"] += 1
            if policy.severity == "critical":
                group["critical"] += 1
        else:
            group["passed"] += 1
    result = []
    for framework, data in groups.items():
        data["framework"] = framework
        data["score"] = round(data["passed"] / max(1, data["controls"]) * 100, 1)
        result.append(data)
    return sorted(result, key=lambda item: item["framework"])


def iam_graph(db: Session, scan_id: int | None = None) -> dict:
    if scan_id is None:
        scan_id = db.scalar(select(Scan.id).order_by(desc(Scan.id)).limit(1))
    if not scan_id:
        return {"nodes": [], "edges": []}
    resources = list(db.scalars(select(CloudResource).where(CloudResource.scan_id == scan_id, CloudResource.resource_type.like("aws_iam_%"))).all())
    nodes, edges, seen = [], [], set()

    def add_node(identifier: str, label: str, kind: str, risk: float = 0):
        if identifier in seen:
            return
        seen.add(identifier)
        nodes.append({"id": identifier, "label": label, "type": kind, "risk": risk, "risky": risk >= 70})

    for resource in resources:
        add_node(resource.address, resource.name, resource.resource_type.replace("aws_iam_", ""), resource.risk_score)
        try:
            config = json.loads(resource.configuration)
        except json.JSONDecodeError:
            config = {}
        for key in ("user", "role", "group", "policy_arn"):
            value = config.get(key)
            if isinstance(value, str):
                reference = value.replace("${", "").replace("}", "")
                add_node(reference, reference.rsplit(".", 1)[-1], key)
                edges.append({"source": reference, "target": resource.address, "label": key})
    return {"nodes": nodes, "edges": edges}


def repository_score(values: dict) -> float:
    weights = {"branch_protection": 18, "secret_scanning": 16, "code_scanning": 16, "dependabot": 12, "dependency_review": 12, "security_policy": 8, "actions_pinning": 8}
    score = sum(weight for key, weight in weights.items() if values.get(key))
    score += min(10, max(0, float(values.get("openssf_score") or 0)))
    return round(score, 1)
