from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="completed", index=True)
    security_score: Mapped[float] = mapped_column(Float, default=100.0, index=True)
    grade: Mapped[str] = mapped_column(String(4), default="A", index=True)
    resource_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resources: Mapped[list["CloudResource"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class CloudResource(Base):
    __tablename__ = "cloud_resources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    address: Mapped[str] = mapped_column(String(500), index=True)
    resource_type: Mapped[str] = mapped_column(String(180), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(30), default="aws", index=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    configuration: Mapped[str] = mapped_column(Text, default="{}")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    scan: Mapped[Scan] = relationship(back_populates="resources")
    findings: Mapped[list["Finding"]] = relationship(back_populates="resource")


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_key: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    category: Mapped[str] = mapped_column(String(80), index=True)
    provider: Mapped[str] = mapped_column(String(30), default="aws", index=True)
    framework: Mapped[str] = mapped_column(String(80), default="CloudSentinel", index=True)
    control_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    scope: Mapped[str] = mapped_column(String(20), default="resource")
    resource_types: Mapped[str] = mapped_column(Text, default="[]")
    check_name: Mapped[str] = mapped_column(String(100), index=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    yaml_content: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    findings: Mapped[list["Finding"]] = relationship(back_populates="policy")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("cloud_resources.id"), nullable=True, index=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id"), index=True)
    title: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    category: Mapped[str] = mapped_column(String(80), index=True)
    provider: Mapped[str] = mapped_column(String(30), default="aws", index=True)
    framework: Mapped[str] = mapped_column(String(80), index=True)
    control_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    resource_address: Mapped[str] = mapped_column(String(500), index=True)
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    remediation: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scan: Mapped[Scan] = relationship(back_populates="findings")
    resource: Mapped[CloudResource | None] = relationship(back_populates="findings")
    policy: Mapped[Policy] = relationship(back_populates="findings")
    notes: Mapped[list["FindingNote"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class FindingNote(Base):
    __tablename__ = "finding_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    author: Mapped[str] = mapped_column(String(100), default="Analyst")
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finding: Mapped[Finding] = relationship(back_populates="notes")


class RepositoryAssessment(Base):
    __tablename__ = "repository_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository: Mapped[str] = mapped_column(String(255), index=True)
    visibility: Mapped[str] = mapped_column(String(20), default="public")
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    branch_protection: Mapped[bool] = mapped_column(Boolean, default=False)
    secret_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    code_scanning: Mapped[bool] = mapped_column(Boolean, default=False)
    dependabot: Mapped[bool] = mapped_column(Boolean, default=False)
    dependency_review: Mapped[bool] = mapped_column(Boolean, default=False)
    security_policy: Mapped[bool] = mapped_column(Boolean, default=False)
    actions_pinning: Mapped[bool] = mapped_column(Boolean, default=False)
    openssf_score: Mapped[float] = mapped_column(Float, default=0.0)
    security_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(50), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    details: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
