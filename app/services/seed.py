from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import BASE_DIR
from app.models import RepositoryAssessment, Scan
from app.services.analytics import repository_score
from app.services.scanner import scan_file


def seed_demo(db: Session) -> Scan:
    existing = db.scalar(select(Scan).where(Scan.name == "Demo AWS Environment"))
    if existing:
        return existing
    scan = scan_file(db, BASE_DIR / "sample-data" / "insecure-aws" / "main.tf", "Demo AWS Environment", "seed")
    values = {
        "repository": "sarah/cloudsentinel-demo",
        "visibility": "public",
        "default_branch": "main",
        "branch_protection": True,
        "secret_scanning": True,
        "code_scanning": True,
        "dependabot": True,
        "dependency_review": False,
        "security_policy": True,
        "actions_pinning": False,
        "openssf_score": 7.4,
    }
    values["security_score"] = repository_score(values)
    db.add(RepositoryAssessment(**values))
    db.commit()
    return scan
