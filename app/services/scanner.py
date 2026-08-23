from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, CloudResource, Finding, Policy, Scan
from app.services.parser import ParsedResource, parse_path
from app.services.policies import DeterministicPolicyEvaluator, PolicyEvaluator, policy_resource_types
from app.services.risk import finding_risk, infer_factors

WEIGHTS = {"critical": 20, "high": 12, "medium": 6, "low": 2, "info": 0.5}


def grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _fingerprint(policy_key: str, address: str, file_path: str | None = None) -> str:
    raw = json.dumps([policy_key, address, file_path or ""], sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _run_scan(db: Session, *, name: str, source_name: str, resources: list[ParsedResource], actor: str = "analyst", evaluator: PolicyEvaluator | None = None) -> Scan:
    evaluator = evaluator or DeterministicPolicyEvaluator()
    scan = Scan(name=name, source_name=source_name, status="running", started_at=datetime.now(timezone.utc))
    db.add(scan)
    db.flush()

    stored: list[CloudResource] = []
    for item in resources:
        resource = CloudResource(
            scan_id=scan.id,
            address=item.address,
            resource_type=item.resource_type,
            name=item.name,
            provider=item.provider,
            region=item.region,
            file_path=item.file_path,
            line_number=item.line_number,
            configuration=json.dumps(item.configuration, default=str),
        )
        db.add(resource)
        stored.append(resource)
    db.flush()

    policies = list(db.scalars(select(Policy).where(Policy.enabled.is_(True))).all())
    findings: list[Finding] = []
    for policy in policies:
        resource_types = policy_resource_types(policy)
        if policy.scope == "scan":
            result = evaluator.evaluate(policy, stored[0] if stored else {"configuration": {}}, stored)
            if result:
                address = "scan.configuration"
                findings.append(
                    Finding(
                        scan_id=scan.id,
                        policy_id=policy.id,
                        title=policy.title,
                        severity=policy.severity,
                        category=policy.category,
                        provider=policy.provider,
                        framework=policy.framework,
                        control_id=policy.control_id,
                        resource_address=address,
                        evidence=json.dumps(result, default=str),
                        remediation=policy.remediation,
                        fingerprint=_fingerprint(policy.policy_key, address),
                        risk_score=finding_risk(policy.severity, infer_factors(result, scope=policy.scope)),
                    )
                )
            continue

        for resource in stored:
            if resource_types and resource.resource_type not in resource_types:
                continue
            result = evaluator.evaluate(policy, resource, stored)
            if not result:
                continue
            finding = Finding(
                scan_id=scan.id,
                resource_id=resource.id,
                policy_id=policy.id,
                title=policy.title,
                severity=policy.severity,
                category=policy.category,
                provider=resource.provider,
                framework=policy.framework,
                control_id=policy.control_id,
                resource_address=resource.address,
                evidence=json.dumps(result, default=str),
                remediation=policy.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number,
                fingerprint=_fingerprint(policy.policy_key, resource.address, resource.file_path),
                risk_score=finding_risk(policy.severity, infer_factors(result, scope=policy.scope)),
            )
            findings.append(finding)
            resource.risk_score = max(resource.risk_score, finding.risk_score)

    db.add_all(findings)
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in WEIGHTS}
    penalty = sum(WEIGHTS[severity] * counts[severity] for severity in WEIGHTS)
    score = max(0.0, round(100 - (penalty / max(1, len(stored))) * 2.2, 1))
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.resource_count = len(stored)
    scan.finding_count = len(findings)
    scan.critical_count = counts["critical"]
    scan.high_count = counts["high"]
    scan.medium_count = counts["medium"]
    scan.low_count = counts["low"]
    scan.info_count = counts["info"]
    scan.security_score = score
    scan.grade = grade(score)
    scan.summary = f"Analyzed {len(stored)} resources against {len(policies)} enabled policies and generated {len(findings)} findings."
    db.add(
        AuditLog(
            action="scan_completed",
            entity_type="scan",
            entity_id=str(scan.id),
            actor=actor,
            details=json.dumps({"name": name, "resources": len(stored), "findings": len(findings), "score": score}),
        )
    )
    db.commit()
    db.refresh(scan)
    return scan


def run_scan(db: Session, *, name: str, source_name: str, resources: list[ParsedResource], actor: str = "analyst", evaluator: PolicyEvaluator | None = None) -> Scan:
    """Persist a scan atomically; discard all partial records on failure."""
    try:
        return _run_scan(db, name=name, source_name=source_name, resources=resources, actor=actor, evaluator=evaluator)
    except Exception:
        db.rollback()
        raise


def scan_file(db: Session, path: Path, name: str, actor: str = "analyst") -> Scan:
    with tempfile.TemporaryDirectory(prefix="cloudsentinel-") as temp_dir:
        resources = parse_path(path, Path(temp_dir))
    if not resources:
        raise ValueError("No Terraform resources were found in the uploaded file.")
    return run_scan(db, name=name, source_name=path.name, resources=resources, actor=actor)


def compare_scans(db: Session, scan: Scan) -> dict:
    previous = db.scalar(select(Scan).where(Scan.id < scan.id).order_by(Scan.id.desc()).limit(1))
    if not previous:
        return {"previous": None, "new": scan.finding_count, "resolved": 0, "persistent": 0, "score_delta": 0}
    current = {finding.fingerprint for finding in scan.findings}
    old = {finding.fingerprint for finding in previous.findings}
    return {
        "previous": previous,
        "new": len(current - old),
        "resolved": len(old - current),
        "persistent": len(current & old),
        "score_delta": round(scan.security_score - previous.security_score, 1),
    }
