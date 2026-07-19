#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "Python 3.11+ is required." >&2; exit 1; }
if [ ! -d .venv ]; then "$PYTHON_BIN" -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
if [ ! -f .env ]; then
  cp .env.example .env
  SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed -i "s|SECRET_KEY=change-this-before-production|SECRET_KEY=$SECRET|" .env
fi
python scripts/init_db.py
python scripts/seed_demo.py
printf '\nCloudSentinel is ready.\nRun: source .venv/bin/activate && python run.py\nOpen: http://127.0.0.1:8000\n'
