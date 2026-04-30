#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_ACTIVATE="${PROJECT_ROOT}/.venv/Scripts/activate"

if [[ ! -f "${VENV_ACTIVATE}" ]]; then
  echo "Virtual environment not found at: ${VENV_ACTIVATE}"
  echo "Create it first with: python -m venv .venv"
  exit 1
fi

# shellcheck disable=SC1090
source "${VENV_ACTIVATE}"

echo "Virtual environment activated."
cd "${PROJECT_ROOT}"

if ! python -c "import flask, flask_bcrypt, flask_jwt_extended, flask_limiter, flask_wtf, pyotp, qrcode, dotenv, email_validator, cryptography" >/dev/null 2>&1; then
  echo "Dependencies missing. Installing from backend/requirements.txt..."
  python -m pip install -r backend/requirements.txt
else
  echo "Dependencies already installed."
fi

if python - <<'PY'
import sqlite3
from pathlib import Path
db_path = Path("backend/login.db")
if not db_path.exists():
    raise SystemExit(1)
connection = sqlite3.connect(db_path)
try:
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if cursor.fetchone() is None:
        raise SystemExit(1)
finally:
    connection.close()
PY
then
  echo "Database already initialized. Skipping init_db.py."
else
  echo "Database not initialized. Running init_db.py..."
  python init_db.py
fi

echo "Starting Flask app..."
python -m backend.app
