#!/usr/bin/env bash
set -euo pipefail

mkdir -p iam tests .github/workflows data

cat > iam/__init__.py <<'PY'
"""Agentic IAM package."""
PY

cat > iam/schema.sql <<'SQL'
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    department TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS entitlements (
    id TEXT PRIMARY KEY,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    sensitivity INTEGER NOT NULL DEFAULT 50
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_entitlements (
    role_id TEXT NOT NULL,
    entitlement_id TEXT NOT NULL,
    PRIMARY KEY (role_id, entitlement_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    text TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'any',
    trigger_json TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    device_trust REAL NOT NULL DEFAULT 0,
    mfa_satisfied INTEGER NOT NULL DEFAULT 0,
    requested_resource TEXT,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS anomaly_cases (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    playbook_id TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_user_time
    ON access_events(user_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_cases_status
    ON anomaly_cases(status);
SQL

cat > iam/repository.py <<'PY'
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
                f"INSERT OR REPLACE INTO {table} "
                f"({columns}) VALUES ({placeholders})",
                tuple(values.values()),
            )

        return str(item_id)

    def execute(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(sql, params).fetchall()
            ]

    def one(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> dict[str, Any] | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def user(self, user_id: str) -> dict[str, Any] | None:
        return self.one(
            "SELECT * FROM users WHERE id=?",
            (user_id,),
        )

    def policies(
        self,
        stage: str | None = None,
    ) -> list[dict[str, Any]]:
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

    def playbooks(
        self,
        stage: str | None = None,
    ) -> list[dict[str, Any]]:
        if stage:
            return self.execute(
                """
                SELECT * FROM playbooks
                WHERE enabled=1
                  AND (stage=? OR stage='any')
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
            WHERE user_id=?
            ORDER BY occurred_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        )

    def access_matrix(self, user_id: str) -> list[dict[str, Any]]:
        return self.execute(
            """
            SELECT
                r.id AS role_id,
                r.name AS role_name,
                e.id AS entitlement_id,
                e.resource,
                e.action,
                e.sensitivity
            FROM user_roles ur
            JOIN roles r ON r.id=ur.role_id
            JOIN role_entitlements re ON re.role_id=r.id
            JOIN entitlements e ON e.id=re.entitlement_id
            WHERE ur.user_id=?
            ORDER BY e.resource, e.action
            """,
            (user_id,),
        )
PY

cat > iam/agents.py <<'PY'
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .repository import Repository


class DatabaseIQ:
    """Reads user facts, access matrices, and database playbooks."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def user_context(self, user_id: str) -> dict[str, Any]:
        user = self.repo.user(user_id)

        if not user:
            raise ValueError(f"Unknown identity: {user_id}")

        roles = self.repo.execute(
            """
            SELECT r.*
            FROM roles r
            JOIN user_roles ur ON ur.role_id=r.id
            WHERE ur.user_id=?
            """,
            (user_id,),
        )

        return {
            "user": user,
            "roles": roles,
            "entitlements": self.repo.access_matrix(user_id),
            "recent_events": self.repo.events_for_user(user_id),
        }

    def playbooks(self, stage: str) -> list[dict[str, Any]]:
        result = []

        for row in self.repo.playbooks(stage):
            result.append(
                {
                    **row,
                    "trigger": json.loads(row["trigger_json"]),
                    "steps": json.loads(row["steps_json"]),
                }
            )

        return result


class WorkIQ:
    """Policy and governance reasoning boundary."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def policy_context(self, stage: str) -> list[dict[str, Any]]:
        return [
            {
                **policy,
                "rule": json.loads(policy["rule_json"]),
            }
            for policy in self.repo.policies(stage)
        ]


class WebIQ:
    """Optional external enrichment boundary."""

    def enrich(self, source_ip: str | None) -> dict[str, Any]:
        # Deliberately disabled by default.
        return {
            "source_ip": source_ip,
            "reputation": "unknown",
            "external_lookup": False,
        }


class FoundryIQ:
    """
    Foundry-compatible reasoning adapter.

    The adapter expects an OpenAI-compatible endpoint, such as Ollama,
    vLLM, or LocalAI. It falls back to a deterministic recommendation.
    """

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "")

    def explain(
        self,
        incident: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> str:
        fallback = (
            "Contain access, require step-up MFA, review the identity, "
            "and preserve audit evidence."
        )

        if not self.base_url or not self.model:
            return fallback

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cautious IAM incident analyst. "
                        "Return one concise recommendation grounded only "
                        "in the supplied evidence."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "incident": incident,
                            "evidence": evidence,
                        }
                    ),
                },
            ],
            "temperature": 0,
        }

        try:
            response = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=20,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except (
            httpx.HTTPError,
            KeyError,
            IndexError,
            TypeError,
            ValueError,
        ):
            return fallback


class LocalRAG:
    """
    Dependency-free local retrieval over policy text.

    Replace this adapter with pgvector, Qdrant, or OpenSearch when needed.
    """

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {
            word.lower().strip(".,:;()[]{}")
            for word in text.split()
            if len(word) > 2
        }

    def search(
        self,
        query: str,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        query_tokens = self._tokens(query)
        scored: list[tuple[float, dict[str, Any]]] = []

        rows = self.repo.execute(
            """
            SELECT id, name, stage, text
            FROM policies
            WHERE enabled=1
            """
        )

        for row in rows:
            document_tokens = self._tokens(row["text"])
            score = len(query_tokens & document_tokens) / max(
                1,
                len(query_tokens | document_tokens),
            )
            scored.append((score, row))

        scored.sort(key=lambda item: item[0], reverse=True)

        return [
            {
                **row,
                "similarity": round(score, 4),
            }
            for score, row in scored[:limit]
        ]
PY

cat > iam/workflow.py <<'PY'
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .agents import (
    DatabaseIQ,
    FoundryIQ,
    LocalRAG,
    WebIQ,
    WorkIQ,
)
from .repository import Repository


def clamp(
    value: float,
    low: float = 0,
    high: float = 100,
) -> float:
    return max(low, min(high, value))


class IAMWorkflow:
    """Orchestrates policy, database, model, web, and anomaly agents."""

    def __init__(self, repo: Repository | None = None) -> None:
        self.repo = repo or Repository()
        self.db = DatabaseIQ(self.repo)
        self.work = WorkIQ(self.repo)
        self.foundry = FoundryIQ()
        self.web = WebIQ()
        self.rag = LocalRAG(self.repo)

        self.threshold = float(
            os.getenv("RISK_THRESHOLD", "70")
        )

    @staticmethod
    def stage_for(event_type: str) -> str:
        return {
            "identify": "identification",
            "provision": "identification",
            "login": "authentication",
            "mfa_challenge": "authentication",
            "checkin": "audit",
            "logout": "audit",
        }.get(event_type, "authorization")

    @staticmethod
    def local_time(
        occurred: datetime,
        timezone_name: str,
    ) -> tuple[int, int]:
        try:
            local = occurred.astimezone(
                ZoneInfo(timezone_name)
            )
        except (ZoneInfoNotFoundError, ValueError):
            local = occurred.astimezone(timezone.utc)

        return local.hour, local.minute

    def evaluate(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        context = self.db.user_context(event["user_id"])

        occurred = datetime.fromisoformat(
            event["occurred_at"].replace("Z", "+00:00")
        )

        if occurred.tzinfo is None:
            occurred = occurred.replace(tzinfo=timezone.utc)

        event_type = event.get("event_type", "login")
        stage = self.stage_for(event_type)

        score = 0.0
        reasons: list[str] = []

        if not context["user"]["active"]:
            score += 100
            reasons.append("inactive identity")

        if (
            stage == "authentication"
            and not event.get("mfa_satisfied", False)
        ):
            score += 25
            reasons.append("MFA not satisfied")

        if event.get("device_trust", 0) < 0.5:
            score += 20
            reasons.append("low device trust")

        resource = event.get("requested_resource")

        if resource and not any(
            row["resource"] == resource
            for row in context["entitlements"]
        ):
            score += 35
            reasons.append(
                "resource is outside effective authorization matrix"
            )

        metadata = event.get("metadata", {})
        shift = metadata.get(
            "shift",
            {
                "start": 7,
                "end": 19,
            },
        )

        local_hour, _ = self.local_time(
            occurred,
            context["user"].get("timezone", "UTC"),
        )

        outside_shift = (
            local_hour < shift["start"]
            or local_hour >= shift["end"]
        )

        if outside_shift:
            score += 30
            reasons.append(
                "wrong-time check-in outside "
                f"{shift['start']:02d}:00-"
                f"{shift['end']:02d}:00 local window"
            )

        score = clamp(score)

        event_id = self.repo.insert(
            "access_events",
            {
                "id": str(uuid.uuid4()),
                "user_id": event["user_id"],
                "event_type": event_type,
                "source_ip": event.get("source_ip"),
                "device_trust": event.get("device_trust", 0),
                "mfa_satisfied": int(
                    event.get("mfa_satisfied", False)
                ),
                "requested_resource": resource,
                "occurred_at": occurred.isoformat(),
                "metadata_json": json.dumps(metadata),
            },
        )

        is_anomaly = score >= self.threshold

        result: dict[str, Any] = {
            "event_id": event_id,
            "user_id": event["user_id"],
            "stage": stage,
            "risk_score": score,
            "threshold": self.threshold,
            "anomaly": is_anomaly,
            "reasons": reasons,
            "policy_context": self.work.policy_context(stage),
            "web_context": self.web.enrich(
                event.get("source_ip")
            ),
            "agents": [
                "WorkIQ",
                "FoundryIQ",
                "DatabaseIQ",
                "WebIQ",
            ],
            "case": None,
        }

        if not is_anomaly:
            return result

        severity = (
            "critical"
            if score >= 90
            else "high"
            if score >= 75
            else "medium"
        )

        evidence = self.rag.search(" ".join(reasons))

        recommendation = self.foundry.explain(
            {
                "score": score,
                "stage": stage,
                "reasons": reasons,
            },
            evidence,
        )

        playbooks = self.db.playbooks(stage)
        selected = playbooks[0] if playbooks else None

        case_id = self.repo.insert(
            "anomaly_cases",
            {
                "id": str(uuid.uuid4()),
                "event_id": event_id,
                "user_id": event["user_id"],
                "stage": stage,
                "score": score,
                "severity": severity,
                "reasons_json": json.dumps(reasons),
                "recommendation": recommendation,
                "playbook_id": (
                    selected["id"] if selected else None
                ),
                "status": "open",
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
        )

        result["case"] = {
            "id": case_id,
            "severity": severity,
            "recommendation": recommendation,
            "playbook": selected,
            "retrieved_policies": evidence,
        }

        return result
PY

cat > iam/seed.py <<'PY'
from __future__ import annotations

import json
from datetime import datetime, timezone

from .repository import Repository


def seed() -> None:
    repo = Repository()
    now = datetime.now(timezone.utc).isoformat()

    repo.insert(
        "users",
        {
            "id": "u-100",
            "display_name": "Avery Analyst",
            "department": "Finance",
            "timezone": "UTC",
            "active": 1,
            "created_at": now,
        },
    )

    repo.insert(
        "users",
        {
            "id": "u-200",
            "display_name": "Morgan Contractor",
            "department": "Engineering",
            "timezone": "America/New_York",
            "active": 1,
            "created_at": now,
        },
    )

    repo.insert(
        "roles",
        {
            "id": "r-employee",
            "name": "employee",
            "description": "Standard workforce role",
        },
    )

    repo.insert(
        "roles",
        {
            "id": "r-finance",
            "name": "finance-approver",
            "description": "Finance approval role",
        },
    )

    repo.insert(
        "entitlements",
        {
            "id": "e-payroll-read",
            "resource": "finance/payroll",
            "action": "read",
            "sensitivity": 90,
        },
    )

    repo.insert(
        "entitlements",
        {
            "id": "e-hr-read",
            "resource": "hr/profile",
            "action": "read",
            "sensitivity": 70,
        },
    )

    with repo.connection() as db:
        db.execute(
            "INSERT OR IGNORE INTO user_roles VALUES (?, ?)",
            ("u-100", "r-employee"),
        )
        db.execute(
            "INSERT OR IGNORE INTO user_roles VALUES (?, ?)",
            ("u-100", "r-finance"),
        )
        db.execute(
            "INSERT OR IGNORE INTO user_roles VALUES (?, ?)",
            ("u-200", "r-employee"),
        )

        db.execute(
            "INSERT OR IGNORE INTO role_entitlements VALUES (?, ?)",
            ("r-finance", "e-payroll-read"),
        )
        db.execute(
            "INSERT OR IGNORE INTO role_entitlements VALUES (?, ?)",
            ("r-employee", "e-hr-read"),
        )

    policies = [
        (
            "p-identification",
            "Identity lifecycle governance",
            "identification",
            {"active_identity_required": True},
            (
                "Identification requires an active identity linked "
                "to an approved workforce record."
            ),
        ),
        (
            "p-auth",
            "Strong authentication",
            "authentication",
            {
                "mfa_required": True,
                "minimum_device_trust": 0.5,
            },
            (
                "Authentication requires MFA and a trusted device "
                "for sensitive resources."
            ),
        ),
        (
            "p-least",
            "Least privilege",
            "authorization",
            {
                "deny_unknown_resource": True,
                "risk_points": 35,
            },
            (
                "Authorization follows the effective role entitlement "
                "cross matrix and denies unknown resources."
            ),
        ),
        (
            "p-time",
            "Work-hour access",
            "audit",
            {
                "allowed_start": 7,
                "allowed_end": 19,
                "risk_points": 30,
            },
            (
                "Check-ins outside the user's approved local shift "
                "are anomalous and require review."
            ),
        ),
    ]

    for policy_id, name, stage, rule, text in policies:
        repo.insert(
            "policies",
            {
                "id": policy_id,
                "name": name,
                "stage": stage,
                "rule_json": json.dumps(rule),
                "text": text,
                "priority": 100,
            },
        )

    repo.insert(
        "playbooks",
        {
            "id": "pb-contain",
            "name": "High risk identity containment",
            "stage": "any",
            "trigger_json": json.dumps(
                {"risk_score_gte": 70}
            ),
            "steps_json": json.dumps(
                [
                    "revoke active sessions",
                    "require step-up MFA",
                    "notify IAM owner",
                    "preserve audit evidence",
                ]
            ),
            "priority": 100,
        },
    )

    repo.insert(
        "playbooks",
        {
            "id": "pb-time",
            "name": "Wrong-time check-in",
            "stage": "audit",
            "trigger_json": json.dumps(
                {"outside_local_hours": True}
            ),
            "steps_json": json.dumps(
                [
                    "verify shift or exception",
                    "compare device and IP history",
                    "open review case",
                ]
            ),
            "priority": 110,
        },
    )


if __name__ == "__main__":
    seed()
    print("Seeded IAM demo data")
PY

cat > iam/api.py <<'PY'
from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .repository import Repository
from .workflow import IAMWorkflow


app = FastAPI(
    title="Agentic AI IAM",
    version="0.2.0",
    description=(
        "Database-driven multi-agent IAM governance "
        "and anomaly detection POC"
    ),
)

repo = Repository()
workflow = IAMWorkflow(repo)


class AccessEvent(BaseModel):
    user_id: str
    event_type: str = "login"
    source_ip: str | None = None
    device_trust: float = Field(0, ge=0, le=1)
    mfa_satisfied: bool = False
    requested_resource: str | None = None
    occurred_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/policies")
def policies(stage: str | None = None):
    return repo.policies(stage)


@app.get("/playbooks")
def playbooks(stage: str | None = None):
    return [
        {
            **row,
            "trigger": json.loads(row["trigger_json"]),
            "steps": json.loads(row["steps_json"]),
        }
        for row in repo.playbooks(stage)
    ]


@app.get("/users/{user_id}/access-matrix")
def access_matrix(user_id: str):
    try:
        context = workflow.db.user_context(user_id)
        return {
            **context,
            "matrix": repo.access_matrix(user_id),
        }
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/evaluate")
def evaluate(event: AccessEvent):
    try:
        return workflow.evaluate(event.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/cases")
def cases(
    status: str | None = Query(default=None),
):
    sql = "SELECT * FROM anomaly_cases"

    if status:
        sql += " WHERE status=?"

    sql += " ORDER BY created_at DESC"

    rows = repo.execute(
        sql,
        (status,) if status else (),
    )

    for row in rows:
        row["reasons"] = json.loads(
            row.pop("reasons_json")
        )

    return rows


@app.post("/rag/search")
def rag_search(
    query: str,
    limit: int = Query(default=3, ge=1, le=20),
):
    return workflow.rag.search(query, limit)


@app.post("/demo/run")
def demo_run():
    return workflow.evaluate(
        {
            "user_id": "u-100",
            "event_type": "login",
            "source_ip": "203.0.113.10",
            "device_trust": 0.2,
            "mfa_satisfied": False,
            "requested_resource": "finance/payroll",
            "occurred_at": "2026-01-15T02:30:00Z",
            "metadata": {"demo": True},
        }
    )
PY

cat > tests/test_workflow.py <<'PY'
from iam.repository import Repository
from iam.workflow import IAMWorkflow


def test_low_risk_event_does_not_create_case(tmp_path):
    repo = Repository(f"sqlite:///{tmp_path}/test.db")

    repo.insert(
        "users",
        {
            "id": "u1",
            "display_name": "Test",
            "department": "IT",
            "timezone": "UTC",
            "active": 1,
            "created_at": "2026-01-01T00:00:00Z",
        },
    )

    repo.insert(
        "entitlements",
        {
            "id": "e1",
            "resource": "app",
            "action": "read",
            "sensitivity": 10,
        },
    )

    repo.insert(
        "roles",
        {
            "id": "r1",
            "name": "user",
            "description": "",
        },
    )

    with repo.connection() as db:
        db.execute(
            "INSERT INTO user_roles VALUES ('u1', 'r1')"
        )
        db.execute(
            "INSERT INTO role_entitlements VALUES ('r1', 'e1')"
        )

    result = IAMWorkflow(repo).evaluate(
        {
            "user_id": "u1",
            "event_type": "login",
            "device_trust": 1,
            "mfa_satisfied": True,
            "requested_resource": "app",
            "occurred_at": "2026-01-15T10:00:00Z",
        }
    )

    assert result["anomaly"] is False


def test_wrong_time_and_unknown_resource_create_case(tmp_path):
    repo = Repository(f"sqlite:///{tmp_path}/test.db")

    repo.insert(
        "users",
        {
            "id": "u1",
            "display_name": "Test",
            "department": "IT",
            "timezone": "UTC",
            "active": 1,
            "created_at": "2026-01-01T00:00:00Z",
        },
    )

    result = IAMWorkflow(repo).evaluate(
        {
            "user_id": "u1",
            "event_type": "checkin",
            "device_trust": 0,
            "mfa_satisfied": False,
            "requested_resource": "secret",
            "occurred_at": "2026-01-15T02:30:00Z",
        }
    )

    assert result["anomaly"] is True
    assert "wrong-time check-in" in " ".join(
        result["reasons"]
    )
PY

cat > pyproject.toml <<'TOML'
[project]
name = "agentic-ai-iam"
version = "0.2.0"
description = "Self-hosted multi-agent IAM anomaly detection POC"
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.115.0,<1",
  "uvicorn[standard]>=0.30.0,<1",
  "pydantic>=2.8.0,<3",
  "httpx>=0.27.0,<1",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0,<9",
]

[tool.pytest.ini_options]
pythonpath = ["."]
TOML

cat > .env.example <<'ENV'
DATABASE_URL=sqlite:///./data/iam.db
RISK_THRESHOLD=70

# Optional self-hosted OpenAI-compatible model:
# LLM_BASE_URL=http://localhost:11434
# LLM_MODEL=llama3.1
ENV

cat > Dockerfile <<'DOCKER'
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY iam ./iam

RUN pip install --no-cache-dir .

ENV DATABASE_URL=sqlite:///./data/iam.db

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "python -m iam.seed && uvicorn iam.api:app --host 0.0.0.0 --port 8000"]
DOCKER

cat > docker-compose.yml <<'YAML'
services:
  iam-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: sqlite:///./data/iam.db
      RISK_THRESHOLD: "70"
      LLM_BASE_URL: ""
      LLM_MODEL: ""
    volumes:
      - iam-data:/app/data

volumes:
  iam-data:
YAML

cat > .github/workflows/test.yml <<'YAML'
name: tests

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install -e '.[dev]'
      - run: pytest -q
YAML

cat > README.md <<'MD'
# Agentic AI IAM

Self-hostable proof of concept for identity lifecycle governance,
authentication, authorization, audit analysis, and anomaly response.

## Included

- FastAPI API and Swagger UI
- WorkIQ, DatabaseIQ, FoundryIQ, and WebIQ boundaries
- Database-backed users, roles, entitlements, policies, and playbooks
- Identification, authentication, authorization, and audit stages
- Threshold-based risk scoring
- Wrong-time check-in detection
- Access-matrix evaluation
- Local policy retrieval/RAG
- Optional self-hosted OpenAI-compatible LLM adapter
- Docker and GitHub Actions test configuration

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m iam.seed
pytest -q
uvicorn iam.api:app --reload