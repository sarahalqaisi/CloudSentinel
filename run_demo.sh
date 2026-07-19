#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
[ -d .venv ] || ./setup_kali.sh
# shellcheck disable=SC1091
source .venv/bin/activate
exec python run.py
