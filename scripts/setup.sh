#!/usr/bin/env bash
# One-shot installer: venv + deps + daily crontab.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[setup] venv"
python3 -m venv .venv
. .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "[setup] smoke test"
.venv/bin/python run_pipeline.py --dry-run | tail -4

# install daily cron (idempotent for this exact line)
LINE="0 7 * * * cd $ROOT && .venv/bin/python run_pipeline.py >> data/run.log 2>&1"
( crontab -l 2>/dev/null | grep -Fv "run_pipeline.py" ; echo "$LINE" ) | crontab -
echo "[setup] crontab installed:"
crontab -l | grep run_pipeline
echo "[done] edit config/sources.yml to tune topics/sources."