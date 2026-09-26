#!/usr/bin/env bash
set -euo pipefail

# Safe bootstrap:
# - installs dependencies into .venv
# - creates the runtime database only if it is missing
# - uses the canonical datastore SQL
# - never overwrites iam/schema.sql
# - does not modify an existing database

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

python -m pip install --upgrade pip

if [[ -f "requirements.txt" ]]; then
  python -m pip install -r requirements.txt
else
  python -m pip install -e ".[dev]"
fi

export DATABASE_URL="${DATABASE_URL:-sqlite:///./data/schemas/iam_datastore.db}"
DB_PATH="${DATABASE_URL#sqlite:///}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Runtime database not found: $DB_PATH"

  if [[ ! -f "data/schemas/iam_datastore.sql" ]]; then
    echo "Missing canonical SQL file: data/schemas/iam_datastore.sql" >&2
    exit 1
  fi

  if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "sqlite3 is required to create the database." >&2
    echo "Install SQLite or use a Python SQL-apply helper." >&2
    exit 1
  fi

  mkdir -p "$(dirname "$DB_PATH")"

  echo "Creating database from data/schemas/iam_datastore.sql..."
  sqlite3 "$DB_PATH" ".read data/schemas/iam_datastore.sql"
else
  echo "Existing database preserved: $DB_PATH"
fi

python - <<'PY'
from iam.repository import Repository

repo = Repository()
identity_count = repo.one(
    "SELECT COUNT(*) AS count FROM identities"
)["count"]

print(f"DATABASE_URL={repo.database_url}")
print(f"Database path={repo.path}")
print(f"Identities={identity_count}")
print("Canonical IAM datastore verified.")
PY

echo
echo "Bootstrap complete."
echo "Start the API with:"
echo "  python -m uvicorn iam.api:app --host 0.0.0.0 --port 8000"
