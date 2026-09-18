from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .repository import Repository
from .workflow import IAMWorkflow

app = FastAPI(title="Agentic AI IAM", version="0.1.0", description="Multi-agent IAM governance and anomaly detection POC")
repo = Repository(); workflow = IAMWorkflow(repo)

class AccessEvent(BaseModel):
    user_id: str
    event_type: str = "login"
    source_ip: str | None = None
    device_trust: float = Field(0, ge=0, le=1)
    mfa_satisfied: bool = False
    requested_resource: str | None = None
    occurred_at: str
    metadata: dict[str, Any] = {}

@app.get("/health")
def health() -> dict[str, str]: return {"status": "ok"}

@app.get("/policies")
def policies(stage: str | None = None): return repo.policies(stage)

@app.get("/playbooks")
def playbooks(): return [{**x, "trigger": json.loads(x["trigger_json"]), "steps": json.loads(x["steps_json"])} for x in repo.playbooks()]

@app.get("/users/{user_id}/access-matrix")
def access_matrix(user_id: str):
    try: return workflow.db.user_context(user_id)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc

@app.post("/evaluate")
def evaluate(event: AccessEvent): return workflow.evaluate(event.model_dump())

@app.get("/cases")
def cases(status: str | None = None):
    rows = repo.execute("SELECT * FROM anomaly_cases" + (" WHERE status=?" if status else "") + " ORDER BY created_at DESC", (status,) if status else ())
    for row in rows: row["reasons"] = json.loads(row.pop("reasons_json"))
    return rows

@app.post("/rag/search")
def rag_search(query: str): return workflow.rag.search(query)

@app.post("/demo/run")
def demo_run():
    return workflow.evaluate({"user_id": "u-100", "event_type": "login", "source_ip": "203.0.113.10", "device_trust": 0.2, "mfa_satisfied": False, "requested_resource": "finance/payroll", "occurred_at": "2026-01-15T02:30:00Z", "metadata": {"demo": True}})
