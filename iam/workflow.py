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
    """Orchestrates policy, database, model, web, RAG, and anomaly agents."""

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

        self.rag_min_similarity = float(
            os.getenv("RAG_MIN_SIMILARITY", "0.05")
        )

        self.rag_limit = int(
            os.getenv("RAG_LIMIT", "3")
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

        except (
            ZoneInfoNotFoundError,
            ValueError,
        ):
            local = occurred.astimezone(timezone.utc)

        return local.hour, local.minute

    def retrieve_evidence(
        self,
        reasons: list[str],
        stage: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve RAG evidence independently for each
        anomaly reason, then deduplicate and rank it.
        """

        evidence_by_id: dict[str, dict[str, Any]] = {}

        for reason in reasons:

            if not reason:
                continue

            matches = self.rag.search(
                query=reason,
                limit=self.rag_limit,
                stage=stage,
                min_similarity=self.rag_min_similarity,
            )

            for match in matches:

                policy_id = match["id"]

                existing = evidence_by_id.get(policy_id)

                # Keep the strongest match if the same
                # policy was retrieved for multiple reasons.
                if (
                    existing is None
                    or match["similarity"]
                    > existing["similarity"]
                ):
                    evidence_by_id[policy_id] = match

        results = list(evidence_by_id.values())

        results.sort(
            key=lambda item: (
                item["similarity"],
                item.get("priority", 0),
            ),
            reverse=True,
        )

        return results[:self.rag_limit]

    @staticmethod
    def playbook_matches(
        playbook: dict[str, Any],
        *,
        context: dict[str, Any],
        stage: str,
        risk_score: float,
    ) -> bool:
        """
        Determine whether a playbook trigger matches
        the current lifecycle context.
        """

        if not playbook.get("enabled", 1):
            return False

        playbook_stage = playbook.get("stage", "any")

        if (
            playbook_stage != "any"
            and playbook_stage != stage
        ):
            return False

        trigger = playbook.get("trigger")

        if not trigger:
            trigger_json = playbook.get("trigger_json")

            if trigger_json:
                try:
                    trigger = json.loads(trigger_json)
                except (TypeError, json.JSONDecodeError):
                    trigger = {}

        trigger = trigger or {}

        # Identity status trigger
        if "identity_status" in trigger:

            actual_status = context["user"].get("status")

            if actual_status != trigger["identity_status"]:
                return False

        # Minimum risk score trigger
        if "min_risk_score" in trigger:

            if risk_score < float(
                trigger["min_risk_score"]
            ):
                return False

        # Maximum risk score trigger
        if "max_risk_score" in trigger:

            if risk_score > float(
                trigger["max_risk_score"]
            ):
                return False

        # Stage trigger
        if "stage" in trigger:

            if trigger["stage"] != stage:
                return False

        return True

    def select_playbook(
        self,
        *,
        stage: str,
        context: dict[str, Any],
        risk_score: float,
    ) -> dict[str, Any] | None:
        """
        Select the first applicable playbook based on
        stage, trigger conditions, and priority.
        """

        playbooks = self.db.playbooks(stage)

        if not playbooks:
            return None

        matching: list[dict[str, Any]] = []

        for playbook in playbooks:

            if self.playbook_matches(
                playbook,
                context=context,
                stage=stage,
                risk_score=risk_score,
            ):
                matching.append(playbook)

        if not matching:
            return None

        matching.sort(
            key=lambda item: item.get(
                "priority",
                0,
            ),
            reverse=True,
        )

        return matching[0]

    def evaluate(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:

        context = self.db.user_context(
            event["user_id"]
        )

        occurred = datetime.fromisoformat(
            event["occurred_at"].replace(
                "Z",
                "+00:00",
            )
        )

        if occurred.tzinfo is None:
            occurred = occurred.replace(
                tzinfo=timezone.utc
            )

        event_type = event.get(
            "event_type",
            "login",
        )

        stage = self.stage_for(
            event_type
        )

        metadata = event.get(
            "metadata",
            {},
        )

        resource = event.get(
            "requested_resource"
        )

        action = (
            event.get("action")
            or metadata.get("action")
            or event_type
        )

        score = 0.0
        reasons: list[str] = []

        # -------------------------------------------------
        # Identity status
        # -------------------------------------------------

        if context["user"]["status"] != "active":

            score += 100

            reasons.append(
                "inactive identity"
            )

        # -------------------------------------------------
        # MFA
        # -------------------------------------------------

        if (
            stage == "authentication"
            and not event.get(
                "mfa_satisfied",
                False,
            )
        ):

            score += 25

            reasons.append(
                "MFA not satisfied"
            )

        # -------------------------------------------------
        # Device trust
        # -------------------------------------------------

        if event.get(
            "device_trust",
            0,
        ) < 0.5:

            score += 20

            reasons.append(
                "low device trust"
            )

        # -------------------------------------------------
        # Authorization matrix
        # -------------------------------------------------

        if resource and not any(
            row["resource"] == resource
            for row in context["entitlements"]
        ):

            score += 35

            reasons.append(
                "resource is outside effective "
                "authorization matrix"
            )

        # -------------------------------------------------
        # Time / shift
        # -------------------------------------------------

        shift = metadata.get(
            "shift",
            {
                "start": 7,
                "end": 19,
            },
        )

        local_hour, _ = self.local_time(
            occurred,
            context["user"].get(
                "timezone",
                "UTC",
            ),
        )

        if (
            local_hour < shift["start"]
            or local_hour >= shift["end"]
        ):

            score += 30

            reasons.append(
                "wrong-time check-in outside "
                f"{shift['start']:02d}:00-"
                f"{shift['end']:02d}:00 local window"
            )

        # -------------------------------------------------
        # Final risk calculation
        # -------------------------------------------------

        score = clamp(score)

        is_anomaly = (
            score >= self.threshold
        )

        decision = (
            "deny"
            if is_anomaly
            else "allow"
        )

        # -------------------------------------------------
        # Persist access event
        # -------------------------------------------------

        event_id = self.repo.insert(
            "access_events",
            {
                "id": str(uuid.uuid4()),
                "identity_id": event["user_id"],
                "event_type": event_type,
                "stage": stage,
                "action": action,
                "decision": decision,
                "source_ip": event.get(
                    "source_ip"
                ),
                "device_id": event.get(
                    "device_id"
                ),
                "requested_resource": resource,
                "device_trust": event.get(
                    "device_trust",
                    0,
                ),
                "mfa_satisfied": int(
                    event.get(
                        "mfa_satisfied",
                        False,
                    )
                ),
                "occurred_at": occurred.isoformat(),
                "metadata_json": json.dumps(
                    metadata
                ),
            },
        )

        # -------------------------------------------------
        # Base result
        # -------------------------------------------------

        result: dict[str, Any] = {
            "event_id": event_id,
            "user_id": event["user_id"],
            "stage": stage,
            "decision": decision,
            "risk_score": score,
            "threshold": self.threshold,
            "anomaly": is_anomaly,
            "reasons": reasons,
            "policy_context": (
                self.work.policy_context(stage)
            ),
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

        # -------------------------------------------------
        # No anomaly
        # -------------------------------------------------

        if not is_anomaly:
            return result

        # -------------------------------------------------
        # Severity
        # -------------------------------------------------

        severity = (
            "critical"
            if score >= 90
            else "high"
            if score >= 75
            else "medium"
        )

        # -------------------------------------------------
        # Agent-specific RAG retrieval
        # -------------------------------------------------

        evidence = self.retrieve_evidence(
            reasons=reasons,
            stage=stage,
        )

        # -------------------------------------------------
        # Foundry explanation
        # -------------------------------------------------

        recommendation = self.foundry.explain(
            {
                "score": score,
                "stage": stage,
                "reasons": reasons,
            },
            evidence,
        )

        # -------------------------------------------------
        # Trigger-based playbook selection
        # -------------------------------------------------

        selected = self.select_playbook(
            stage=stage,
            context=context,
            risk_score=score,
        )

        # -------------------------------------------------
        # Persist anomaly case
        # -------------------------------------------------

        case_id = self.repo.insert(
            "anomaly_cases",
            {
                "id": str(uuid.uuid4()),
                "event_id": event_id,
                "identity_id": event["user_id"],
                "stage": stage,
                "risk_score": score,
                "severity": severity,
                "reasons_json": json.dumps(
                    reasons
                ),
                "recommendation": recommendation,
                "playbook_id": (
                    selected["id"]
                    if selected
                    else None
                ),
                "status": "open",
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
        )

        # -------------------------------------------------
        # Return complete case
        # -------------------------------------------------

        result["case"] = {
            "id": case_id,
            "severity": severity,
            "recommendation": recommendation,
            "playbook": selected,
            "retrieved_policies": evidence,
        }

        return result
