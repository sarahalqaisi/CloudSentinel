#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.services.parser import parse_file, parse_path
from app.services.policies import import_policies
from app.services.sarif import scan_sarif
from app.services.scanner import run_scan


def resources_from(path: Path):
    if path.is_file():
        with tempfile.TemporaryDirectory(prefix="cloudsentinel-ci-") as temp:
            return parse_path(path, Path(temp))
    resources = []
    for item in sorted(path.rglob("*")):
        if item.is_file() and (item.suffix == ".tf" or item.suffix == ".json"):
            resources.extend(parse_file(item, item.relative_to(path).as_posix()))
    return resources


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan Terraform and emit SARIF 2.1.0")
    parser.add_argument("path", type=Path)
    parser.add_argument("--sarif", type=Path, default=Path("cloudsentinel.sarif"))
    parser.add_argument("--fail-on", choices=("none", "critical", "high"), default="none")
    args = parser.parse_args()
    if not args.path.exists():
        parser.error(f"path does not exist: {args.path}")
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, expire_on_commit=False)() as db:
        import_policies(db)
        resources = resources_from(args.path)
        if not resources:
            parser.error("no Terraform resources found")
        scan = run_scan(db, name="CI scan", source_name=str(args.path), resources=resources, actor="ci")
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_bytes(scan_sarif(scan))
        print(f"CloudSentinel: {scan.finding_count} findings, score {scan.security_score}, SARIF {args.sarif}")
        if args.fail_on == "critical" and scan.critical_count:
            return 2
        if args.fail_on == "high" and (scan.critical_count or scan.high_count):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
