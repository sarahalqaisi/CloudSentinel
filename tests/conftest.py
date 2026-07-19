from __future__ import annotations

import os
from pathlib import Path

TEST_DB = Path(__file__).resolve().parent / "cloudsentinel-test.db"
TEST_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["SECRET_KEY"] = "test-secret-key"
