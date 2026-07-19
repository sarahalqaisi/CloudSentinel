from __future__ import annotations

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import settings
from app.database import Base, engine

if __name__ == "__main__":
    if settings.database_url.startswith("sqlite"):
        db_file = Path(settings.database_url.replace("sqlite:///", "", 1))
        db_file.unlink(missing_ok=True)
    else:
        Base.metadata.drop_all(bind=engine)
    print("Database reset. Run scripts/init_db.py next.")
