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
        self.threshold = float(os.getenv("RISK_THRESHOLD", "70"))

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
            local = occurred.astimezone(ZoneInfo(timezone_name))
        except (ZoneInfoNotFoundError, ValueError):
            local = occurred.astimezone(timezone.utc)
        return local.hour, local.minute

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        context = self.db.user_context(event["user_id"])

        occurred = datetime.fromisoformat(
            event["occurred_at"].replace("Z", "+00:00")
        )
        if occurred.tzinfo is None:
            occurred = occurred.replace(tzinfo=timezone.utc)

        event_type = event.get("event_type", "login")
        stage = self.stage_for(event_type)
        metadata = event.get("metadata", {})
        resource = event.get("requested_resource")
        action = event.get("action") or metadata.get("action") or event_type

        score = 0.0
        reasons: list[str] = []

        if context["user"]["status"] != "active":
            score += 100
            reasons.append("inactive identity")

        if stage == "authentication" and not event.get("mfa_satisfied", False):
            score += 25
            reasons.append("MFA not satisfied")

        if event.get("device_trust", 0) < 0.5:
            score += 20
            reasons.append("low device trust")

        if resource and not any(
            row["resource"] == resource for row in context["entitlements"]
        ):
            score += 35
            reasons.append("resource is outside effective authorization matrix")

        shift = metadata.get("shift", {"start": 7, "end": 19})
        local_hour, _ = self.local_time(
            occurred,
            context["user"].get("timezone", "UTC"),
        )

        if local_hour < shift["start"] or local_hour >= shift["end"]:
            score += 30
            reasons.append(
                "wrong-time check-in outside "
                f"{shift['start']:02d}:00-{shift['end']:02d}:00 local window"
            )

        score = clamp(score)
        is_anomaly = score >= self.threshold
        decision = "deny" if is_anomaly else "allow"

        event_id = self.repo.insert(
            "access_events",
            {
                "id": str(uuid.uuid4()),
                "identity_id": event["user_id"],
                "event_type": event_type,
                "stage": stage,
                "action": action,
                "decision": decision,
                "source_ip": event.get("source_ip"),
                "device_id": event.get("device_id"),
                "requested_resource": resource,
                "device_trust": event.get("device_trust", 0),
                "mfa_satisfied": int(event.get("mfa_satisfied", False)),
                "occurred_at": occurred.isoformat(),
                "metadata_json": json.dumps(metadata),
            },
        )

        result: dict[str, Any] = {
            "event_id": event_id,
            "user_id": event["user_id"],
            "stage": stage,
            "decision": decision,
            "risk_score": score,
            "threshold": self.threshold,
            "anomaly": is_anomaly,
            "reasons": reasons,
            "policy_context": self.work.policy_context(stage),
            "web_context": self.web.enrich(event.get("source_ip")),
            "agents": ["WorkIQ", "FoundryIQ", "DatabaseIQ", "WebIQ"],
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
            {"score": score, "stage": stage, "reasons": reasons},
            evidence,
        )

        playbooks = self.db.playbooks(stage)
        selected = playbooks[0] if playbooks else None

        case_id = self.repo.insert(
            "anomaly_cases",
            {
                "id": str(uuid.uuid4()),
                "event_id": event_id,
                "identity_id": event["user_id"],
                "stage": stage,
                "risk_score": score,
                "severity": severity,
                "reasons_json": json.dumps(reasons),
                "recommendation": recommendation,
                "playbook_id": selected["id"] if selected else None,
                "status": "open",
                "created_at": datetime.now(timezone.utc).isoformat(),
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
