from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import BASE_DIR
from app.database import Base
from app.models import AuditLog, Finding, Policy
from app.services.parser import parse_file
from app.services.policies import import_policies
from app.services.reporting import scan_csv, scan_json, scan_pdf
from app.services.scanner import compare_scans, run_scan


def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_insecure_demo_generates_findings_and_reports():
    db = session()
    created, _ = import_policies(db)
    assert created == 35
    resources = parse_file(BASE_DIR / "sample-data" / "insecure-aws" / "main.tf")
    scan = run_scan(db, name="Demo", source_name="main.tf", resources=resources)
    assert scan.resource_count >= 15
    assert scan.finding_count >= 15
    assert scan.critical_count >= 4
    assert scan.security_score < 80
    assert db.scalar(select(Finding).where(Finding.scan_id == scan.id))
    assert db.scalar(select(AuditLog).where(AuditLog.entity_id == str(scan.id)))
    assert scan_pdf(scan).startswith(b"%PDF")
    assert b"Resource" in scan_csv(scan)
    assert b'"score"' in scan_json(scan)


def test_scan_comparison_reports_improvement():
    db = session(); import_policies(db)
    bad = run_scan(db, name="Bad", source_name="bad.tf", resources=parse_file(BASE_DIR / "sample-data" / "insecure-aws" / "main.tf"))
    good = run_scan(db, name="Good", source_name="good.tf", resources=parse_file(BASE_DIR / "sample-data" / "secure-baseline.tf"))
    good.findings  # relationship available
    result = compare_scans(db, good)
    assert result["previous"].id == bad.id
    assert result["score_delta"] > 0
    assert result["resolved"] > 0
