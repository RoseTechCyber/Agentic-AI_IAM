from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class Repository:
    """Database boundary used by the IAM agents."""

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "sqlite:///./data/iam.db",
        )

        if not self.database_url.startswith("sqlite:///"):
            raise ValueError(
                "This POC currently supports sqlite:/// DATABASE_URL values."
            )

        self.path = self.database_url.removeprefix("sqlite:///")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        with self.connection() as db:
            schema = Path(__file__).with_name("schema.sql").read_text()
            db.executescript(schema)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def insert(self, table: str, values: dict[str, Any]) -> str:
        values = dict(values)
        item_id = values.setdefault("id", str(uuid.uuid4()))

        columns = ",".join(values.keys())
        placeholders = ",".join("?" for _ in values)

        with self.connection() as db:
            db.execute(
                f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})",
                tuple(values.values()),
            )
        return str(item_id)

    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def one(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> dict[str, Any] | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def user(self, user_id: str) -> dict[str, Any] | None:
        return self.one(
            """
            SELECT
                id,
                username,
                display_name,
                department,
                timezone,
                status,
                CASE WHEN status = 'active' THEN 1 ELSE 0 END AS active,
                created_at
            FROM identities
            WHERE id=?
            """,
            (user_id,),
        )

    def policies(self, stage: str | None = None) -> list[dict[str, Any]]:
        if stage:
            return self.execute(
                """
                SELECT * FROM policies
                WHERE enabled=1 AND stage=?
                ORDER BY priority DESC
                """,
                (stage,),
            )

        return self.execute(
            """
            SELECT * FROM policies
            WHERE enabled=1
            ORDER BY priority DESC
            """
        )

    def playbooks(self, stage: str | None = None) -> list[dict[str, Any]]:
        if stage:
            return self.execute(
                """
                SELECT * FROM playbooks
                WHERE enabled=1 AND (stage=? OR stage='any')
                ORDER BY priority DESC
                """,
                (stage,),
            )

        return self.execute(
            """
            SELECT * FROM playbooks
            WHERE enabled=1
            ORDER BY priority DESC
            """
        )

    def events_for_user(
        self,
        user_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return self.execute(
            """
            SELECT * FROM access_events
            WHERE identity_id=?
            ORDER BY occurred_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        )

    def access_matrix(self, user_id: str) -> list[dict[str, Any]]:
        return self.execute(
            """
            SELECT
                ir.role_id,
                r.name AS role_name,
                p.id AS entitlement_id,
                p.resource,
                p.action,
                p.sensitivity
            FROM identity_roles ir
            JOIN roles r ON r.id = ir.role_id
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE ir.identity_id=?
            ORDER BY p.resource, p.action
            """,
            (user_id,),
        )
