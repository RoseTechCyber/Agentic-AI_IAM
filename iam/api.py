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
