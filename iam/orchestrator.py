from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .repository import Repository


@dataclass
class WorkflowContext:
    user_id: str
    event: dict[str, Any]
    user: dict[str, Any] | None = None
    roles: list[dict[str, Any]] = field(default_factory=list)
    entitlements: list[dict[str, Any]] = field(default_factory=list)
    policies: list[dict[str, Any]] = field(default_factory=list)
    decision: str = "pending"
    stage: str = "enrollment"
    risk_score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    anomaly: bool = False
    case: dict[str, Any] | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)


class WorkIQAgent:
    """Loads policy and governance context."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def run(self, context: WorkflowContext) -> WorkflowContext:
        event_type = context.event.get("event_type", "login")

        context.stage = {
            "identify": "identification",
            "provision": "enrollment",
            "login": "authentication",
            "mfa_challenge": "authentication",
            "checkin": "audit",
            "logout": "audit",
        }.get(event_type, "authorization")

        context.policies = self.repo.policies(context.stage)

        context.audit.append(
            {
                "agent": "WorkIQ",
                "stage": context.stage,
                "status": "completed",
            }
        )

        return context


class EnrollmentAgent:
    """Confirms that the identity is enrolled and active."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def run(self, context: WorkflowContext) -> WorkflowContext:
        user = self.repo.user(context.user_id)

        if not user:
            context.decision = "deny"
            context.risk_score += 100
            context.reasons.append("identity is not enrolled")
        else:
            context.user = user
            context.audit.append(
                {
                    "agent": "EnrollmentAgent",
                    "status": "identity found",
                    "user_id": context.user_id,
                }
            )

        return context


class IdentificationAgent:
    """Validates identity lifecycle state."""

    def run(self, context: WorkflowContext) -> WorkflowContext:
        if not context.user:
            return context

        if not context.user.get("active", False):
            context.decision = "deny"
            context.risk_score += 100
            context.reasons.append("identity is inactive")

        context.audit.append(
            {
                "agent": "IdentificationAgent",
                "status": "completed",
                "active": bool(context.user.get("active")),
            }
        )

        return context


class AuthenticationAgent:
    """Checks MFA and device trust."""

    def run(self, context: WorkflowContext) -> WorkflowContext:
        event = context.event

        if context.stage != "authentication":
            return context

        if not event.get("mfa_satisfied", False):
            context.risk_score += 25
            context.reasons.append("MFA was not satisfied")

        device_trust = float(event.get("device_trust", 0))

        if device_trust < 0.5:
            context.risk_score += 20
            context.reasons.append("device trust is below the minimum")

        context.audit.append(
            {
                "agent": "AuthenticationAgent",
                "status": "completed",
                "mfa_satisfied": bool(event.get("mfa_satisfied")),
                "device_trust": device_trust,
            }
        )

        return context


class AuthorizationAgent:
    """Checks roles, entitlements, and requested resource."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def run(self, context: WorkflowContext) -> WorkflowContext:
        context.entitlements = self.repo.access_matrix(context.user_id)

        requested_resource = context.event.get("requested_resource")

        if requested_resource:
            permitted = any(
                row.get("resource") == requested_resource
                for row in context.entitlements
            )

            if not permitted:
                context.risk_score += 35
                context.reasons.append(
                    "requested resource is outside the authorization matrix"
                )

        context.audit.append(
            {
                "agent": "AuthorizationAgent",
                "status": "completed",
                "requested_resource": requested_resource,
                "entitlement_count": len(context.entitlements),
            }
        )

        return context


class AuditAgent:
    """Checks time-window and event-quality signals."""

    def run(self, context: WorkflowContext) -> WorkflowContext:
        occurred_at = context.event.get("occurred_at")

        if occurred_at and context.user:
            occurred = datetime.fromisoformat(
                occurred_at.replace("Z", "+00:00")
            )

            if occurred.tzinfo is None:
                occurred = occurred.replace(tzinfo=timezone.utc)

            local_hour = occurred.hour
            shift = context.event.get(
                "metadata",
                {},
            ).get(
                "shift",
                {
                    "start": 7,
                    "end": 19,
                },
            )

            if local_hour < shift["start"] or local_hour >= shift["end"]:
                context.risk_score += 30
                context.reasons.append(
                    "event occurred outside the approved work window"
                )

        context.audit.append(
            {
                "agent": "AuditAgent",
                "status": "completed",
            }
        )

        return context


class AnomalyAgent:
    """Converts accumulated risk signals into an anomaly decision."""

    def __init__(self, threshold: float = 70) -> None:
        self.threshold = threshold

    def run(self, context: WorkflowContext) -> WorkflowContext:
        context.risk_score = min(100, context.risk_score)
        context.anomaly = context.risk_score >= self.threshold

        if context.anomaly:
            context.decision = "review"
        elif context.decision != "deny":
            context.decision = "allow"

        context.audit.append(
            {
                "agent": "AnomalyAgent",
                "status": "completed",
                "risk_score": context.risk_score,
                "anomaly": context.anomaly,
            }
        )

        return context


class PlaybookAgent:
    """Selects an appropriate response for an anomaly."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def run(self, context: WorkflowContext) -> WorkflowContext:
        if not context.anomaly:
            return context

        playbooks = self.repo.playbooks(context.stage)

        selected = playbooks[0] if playbooks else None

        context.case = {
            "severity": (
                "critical"
                if context.risk_score >= 90
                else "high"
                if context.risk_score >= 75
                else "medium"
            ),
            "playbook": selected,
            "reasons": context.reasons,
            "recommendation": (
                "Require step-up MFA, review the identity, "
                "and preserve audit evidence."
            ),
        }

        context.audit.append(
            {
                "agent": "PlaybookAgent",
                "status": "response selected",
                "playbook": selected["id"] if selected else None,
            }
        )

        return context


class IAMOrchestrator:
    """Runs the IAM agents in a controlled sequence."""

    def __init__(
        self,
        repo: Repository | None = None,
        threshold: float = 70,
    ) -> None:
        self.repo = repo or Repository()

        self.agents = [
            WorkIQAgent(self.repo),
            EnrollmentAgent(self.repo),
            IdentificationAgent(),
            AuthenticationAgent(),
            AuthorizationAgent(self.repo),
            AuditAgent(),
            AnomalyAgent(threshold),
            PlaybookAgent(self.repo),
        ]

    def run(
        self,
        user_id: str,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        context = WorkflowContext(
            user_id=user_id,
            event=event,
        )

        for agent in self.agents:
            context = agent.run(context)

            # Stop safely if the identity is unknown or inactive.
            if context.decision == "deny":
                break

        return {
            "user_id": context.user_id,
            "decision": context.decision,
            "stage": context.stage,
            "risk_score": context.risk_score,
            "anomaly": context.anomaly,
            "reasons": context.reasons,
            "case": context.case,
            "audit": context.audit,
        }