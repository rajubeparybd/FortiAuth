#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_ACTIVATE="${PROJECT_ROOT}/.venv/Scripts/activate"
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE_FILE="${PROJECT_ROOT}/.env.example"

cd "${PROJECT_ROOT}"

if [[ ! -f "${VENV_ACTIVATE}" ]]; then
  echo "Virtual environment not found. Creating .venv..."
  python -m venv .venv
fi

# shellcheck disable=SC1090
source "${VENV_ACTIVATE}"

echo "Virtual environment activated."

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${ENV_EXAMPLE_FILE}" ]]; then
    echo ".env not found. Creating from .env.example..."
    cp "${ENV_EXAMPLE_FILE}" "${ENV_FILE}"
  else
    echo ".env and .env.example not found. Creating default .env..."
    cat > "${ENV_FILE}" <<'EOF'
SECRET_KEY=change-me-secret
JWT_SECRET_KEY=change-me-jwt-secret
DATABASE_PATH=backend/login.db
FLASK_ENV=production
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Strict
JWT_ACCESS_TOKEN_MINUTES=15
JWT_REFRESH_TOKEN_DAYS=7
LOCKOUT_MINUTES=10
MAX_FAILED_ATTEMPTS=3
EOF
  fi
else
  echo ".env already exists."
fi

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
