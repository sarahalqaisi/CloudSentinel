from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _database_url() -> str:
    return os.getenv("DATABASE_URL", "").strip() or f"sqlite:///{BASE_DIR / 'cloudsentinel.db'}"


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "CloudSentinel")
    app_env: str = os.getenv("APP_ENV", "development")
    secret_key: str = os.getenv("SECRET_KEY", "change-me-in-production")
    database_url: str = _database_url()
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", str(12 * 1024 * 1024)))
    max_archive_members: int = int(os.getenv("MAX_ARCHIVE_MEMBERS", "250"))
    max_archive_bytes: int = int(os.getenv("MAX_ARCHIVE_BYTES", str(32 * 1024 * 1024)))
    max_archive_ratio: float = float(os.getenv("MAX_ARCHIVE_RATIO", "100"))
    risk_severity_weight: float = float(os.getenv("RISK_SEVERITY_WEIGHT", "0.50"))
    risk_exposure_weight: float = float(os.getenv("RISK_EXPOSURE_WEIGHT", "0.20"))
    risk_confidence_weight: float = float(os.getenv("RISK_CONFIDENCE_WEIGHT", "0.10"))
    risk_blast_radius_weight: float = float(os.getenv("RISK_BLAST_RADIUS_WEIGHT", "0.10"))
    risk_exploitability_weight: float = float(os.getenv("RISK_EXPLOITABILITY_WEIGHT", "0.10"))
    upload_dir: Path = BASE_DIR / "uploads"
    policy_dir: Path = BASE_DIR / "policies"
    report_dir: Path = BASE_DIR / "reports"


settings = Settings()
for directory in (settings.upload_dir, settings.report_dir):
    directory.mkdir(parents=True, exist_ok=True)
