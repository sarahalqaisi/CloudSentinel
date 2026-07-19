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
    upload_dir: Path = BASE_DIR / "uploads"
    policy_dir: Path = BASE_DIR / "policies"
    report_dir: Path = BASE_DIR / "reports"


settings = Settings()
for directory in (settings.upload_dir, settings.report_dir):
    directory.mkdir(parents=True, exist_ok=True)
