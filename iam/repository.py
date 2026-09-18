from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./data/iam.db")


def _sqlite_path() -> str:
    path = DB_URL.removeprefix("sqlite:///")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


class Repository:
    """Small persistence boundary; keeps the demo portable and keeps agents off raw SQL."""

    def __init__(self) -> None:
        self.path = _sqlite_path()
        with self.connection() as db:
            db.executescript(Path(__file__).with_name("schema.sql").read_text())

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"))

    def insert(self, table: str, values: dict[str, Any]) -> str:
        item_id = values.setdefault("id", str(uuid.uuid4()))
        columns = ",".join(values)
        placeholders = ",".join("?" for _ in values)
        with self.connection() as db:
            db.execute(f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})", list(values.values()))
        return item_id

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def user(self, user_id: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM users WHERE id=?", (user_id,))

    def policies(self, stage: str | None = None) -> list[dict[str, Any]]:
        if stage:
            return self.execute("SELECT * FROM policies WHERE enabled=1 AND stage=?", (stage,))
        return self.execute("SELECT * FROM policies WHERE enabled=1")

    def playbooks(self) -> list[dict[str, Any]]:
        return self.execute("SELECT * FROM playbooks WHERE enabled=1 ORDER BY priority DESC")

    def events_for_user(self, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
        return self.execute("SELECT * FROM access_events WHERE user_id=? ORDER BY occurred_at DESC LIMIT ?", (user_id, limit))
