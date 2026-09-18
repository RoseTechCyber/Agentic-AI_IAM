from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from .agents import DatabaseIQ, FoundryIQ, LocalRAG, WebIQ, WorkIQ
from .repository import Repository


def clamp(value: float, low: float = 0, high: float = 100) -> float: return max(low, min(high, value))


class IAMWorkflow:
    def __init__(self, repo: Repository | None = None) -> None:
        self.repo = repo or Repository(); self.db = DatabaseIQ(self.repo); self.work = WorkIQ(self.repo); self.foundry = FoundryIQ(); self.web = WebIQ(); self.rag = LocalRAG(self.repo)
        self.threshold = float(os.getenv("RISK_THRESHOLD", "70")); self.grace = int(os.getenv("WRONG_TIME_GRACE_MINUTES", "30"))

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        user = self.db.user_context(event["user_id"])
        occurred = datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00"))
        score, reasons = 0.0, []
        if not user["user"]["active"]: score += 100; reasons.append("inactive identity")
        if not event.get("mfa_satisfied", False): score += 25; reasons.append("MFA not satisfied")
        if event.get("device_trust", 0) < 0.5: score += 20; reasons.append("low device trust")
        entitlements = {(x["resource"], x["action"]) for x in user["entitlements"]}
        resource = event.get("requested_resource")
        if resource and not any(x[0] == resource for x in entitlements): score += 35; reasons.append("resource is outside effective authorization matrix")
        if occurred.hour < 7 or occurred.hour >= 19:
            score += 30; reasons.append("wrong-time check-in outside 07:00-19:00 UTC")
        score = clamp(score)
        stage = "authentication" if event.get("event_type") in {"login", "mfa_challenge"} else "authorization"
        event_id = self.repo.insert("access_events", {"id": str(uuid.uuid4()), **event, "source_ip": event.get("source_ip"), "device_trust": event.get("device_trust", 0), "mfa_satisfied": int(event.get("mfa_satisfied", False)), "metadata_json": json.dumps(event.get("metadata", {}))})
        incident = {"score": score, "threshold": self.threshold, "stage": stage, "reasons": reasons}
        case = None
        if score >= self.threshold:
            severity = "critical" if score >= 90 else "high" if score >= 75 else "medium"
            recommendation = self.foundry.explain(incident, self.rag.search(" ".join(reasons)))
            case_id = self.repo.insert("anomaly_cases", {"id": str(uuid.uuid4()), "event_id": event_id, "user_id": event["user_id"], "stage": stage, "score": score, "severity": severity, "reasons_json": json.dumps(reasons), "recommendation": recommendation, "status": "open", "created_at": datetime.now(timezone.utc).isoformat()})
            case = {"id": case_id, **incident, "severity": severity, "recommendation": recommendation}
        return {"event_id": event_id, "user_id": event["user_id"], "risk_score": score, "threshold": self.threshold, "anomaly": case is not None, "reasons": reasons, "case": case, "agents": ["WorkIQ", "FoundryIQ", "DatabaseIQ", "WebIQ"]}
