from __future__ import annotations

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.database import SessionLocal, init_db
from app.services.policies import import_policies
from app.services.seed import seed_demo

if __name__ == "__main__":
    init_db()
    with SessionLocal() as db:
        import_policies(db)
        scan = seed_demo(db)
    print(f"Demo scan #{scan.id}: score={scan.security_score}, findings={scan.finding_count}.")
