#!/usr/bin/env bash
set -euo pipefail

# Safe bootstrap:
# - installs dependencies into .venv (best-effort)
# - creates the runtime DB from data/schemas/iam_datastore.sql if missing
# - does NOT overwrite iam/schema.sql
# - does NOT commit the DB

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Create venv if missing, install requirements if present
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip >/dev/null || true
if [ -f requirements.txt ]; then
  python -m pip install -r requirements.txt || true
fi

DB_URL="${DATABASE_URL:-sqlite:///./data/schemas/iam_datastore.db}"
DB_PATH="${DB_URL#sqlite:///}"

if [ ! -f "$DB_PATH" ]; then
  echo "Runtime DB not found at $DB_PATH. Creating from data/schemas/iam_datastore.sql..."
  if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "SQLite (sqlite3) is required to apply the SQL seed. Please install sqlite3 or use scripts/apply_datastore_sql.py" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$DB_PATH")"
  sqlite3 "$DB_PATH" ".read data/schemas/iam_datastore.sql"
  echo "Database created at $DB_PATH"
else
  echo "Runtime DB already exists at $DB_PATH (not modifying)."
fi

# quick verification using the repository layer
python - <<'PY'
from iam.repository import Repository
repo = Repository()
print("DATABASE_URL:", repo.database_url)
print("DB path:", repo.path)
try:
    print("identities:", repo.one("SELECT COUNT(*) AS c FROM identities")["c"])
except Exception as e:
    print("Check failed:", e)
PY

echo "Bootstrap complete. Start the API with:"
echo "  python -m uvicorn iam.api:app --host 0.0.0.0 --port 8000"