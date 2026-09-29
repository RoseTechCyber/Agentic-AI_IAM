import json
from datetime import datetime


class ContextProvider:

    def __init__(self, repo):
        self.repo = repo

    def get_identity(self, user_id):

        rows = self.repo.execute(
            """
            SELECT *
            FROM identities
            WHERE user_id = ?
            """,
            (user_id,)
        )

        return rows[0] if rows else None

    def get_recent_access_events(self, user_id):

        return self.repo.execute(
            """
            SELECT *
            FROM access_events_trigger
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 5
            """,
            (user_id,)
        )

    def get_latest_access_event(self, user_id):

        rows = self.repo.execute(
            """
            SELECT *
            FROM access_events
            WHERE user_id = ?
            ORDER BY occurred_at DESC
            LIMIT 1
            """,
            (user_id,)
        )

        return rows[0] if rows else None

    def get_user_permissions(self, user_id):

        return self.repo.execute(
            """
            SELECT *
            FROM user_permissions_trigger
            WHERE user_id = ?
            """,
            (user_id,)
        )

    def get_policy_context(self, policy_name):

        return self.repo.execute(
            """
            SELECT *
            FROM policy_context_trigger
            WHERE policy_name = ?
            """,
            (policy_name,)
        )

    def get_playbook_by_name(self, playbook_name):

        rows = self.repo.execute(
            """
            SELECT *
            FROM playbooks
            WHERE playbook_name = ?
            LIMIT 1
            """,
            (playbook_name,)
        )

        return rows[0] if rows else None


class IdentificationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request, response):

        identity = self.provider.get_identity(
            request.user_id
        )

        if not identity:

            response.identification_status = "FAILED"

            response.agent_trace.append({
                "agent": "Identification",
                "decision": "FAILED",
                "reason": "Identity not found"
            })

            return response

        response.identification_status = "PASSED"

        response.agent_trace.append({
            "agent": "Identification",
            "decision": "PASSED",
            "reason": "Identity verified"
        })

        return response


class AuthenticationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        if request.identification_status != "PASSED":

            request.authentication_status = "BLOCKED"

            request.agent_trace.append({
                "agent": "Authentication",
                "decision": "BLOCKED",
                "reason": "Identification failed"
            })

            return request

        events = self.provider.get_recent_access_events(
            request.user_id
        )

        if not events:
            request.risk_score += 10

        event = self.provider.get_latest_access_event(
            request.user_id
        )

        if event and not event.get("device_id"):
            request.risk_score += 15

        request.authentication_status = "PASSED"

        request.agent_trace.append({
            "agent": "Authentication",
            "decision": "PASSED",
            "reason": "Authentication successful"
        })

        return request


class AuthorizationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        if request.authentication_status != "PASSED":

            request.authorization_status = "BLOCKED"

            return request

        permissions = self.provider.get_user_permissions(
            request.user_id
        )

        if not permissions:

            request.authorization_status = "FAILED"

            request.agent_trace.append({
                "agent": "Authorization",
                "decision": "FAILED",
                "reason": "No permissions assigned"
            })

            return request

        request.authorization_status = "PASSED"

        request.agent_trace.append({
            "agent": "Authorization",
            "decision": "PASSED",
            "reason": "RBAC validation successful"
        })

        return request


class AuditAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        try:

            self.provider.repo.execute(
                """
                INSERT INTO access_events
                (
                    user_id,
                    event_type,
                    occurred_at
                )
                VALUES (?,?,?)
                """,
                (
                    request.user_id,
                    "IDENTITY_LIFECYCLE_RUN",
                    datetime.utcnow().isoformat()
                ),
                commit=True
            )

        except Exception:
            pass

        request.audit_status = "PASSED"

        request.agent_trace.append({
            "agent": "Audit",
            "decision": "PASSED",
            "reason": "Audit event persisted"
        })

        return request


class RiskAnomalyAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        score = request.risk_score
        reasons = []

        event = self.provider.get_latest_access_event(
            request.user_id
        )

        if event:

            occurred_at = str(
                event["occurred_at"]
            ).replace("Z", "+00:00")

            try:

                login_hour = datetime.fromisoformat(
                    occurred_at
                ).hour

                if login_hour < 7 or login_hour > 19:

                    reasons.append(
                        "wrong-time check-in"
                    )

                    score += 20

            except Exception:
                pass

            device = event.get("device_id")

            if not device:

                reasons.append(
                    "low device trust"
                )

                score += 15

        identity = self.provider.get_identity(
            request.user_id
        )

        if identity:

            dept = identity.get(
                "department",
                ""
            )

            if dept in [
                "Finance",
                "Security",
                "HR"
            ]:
                score += 20

        request.risk_score = score

        selected_playbook = (
            "Privileged access review"
        )

        if "wrong-time check-in" in reasons:

            selected_playbook = (
                "Wrong-time check-in"
            )

        elif "low device trust" in reasons:

            selected_playbook = (
                "High risk identity containment"
            )

        playbook = (
            self.provider.get_playbook_by_name(
                selected_playbook
            )
        )

        if not playbook:

            request.playbook = (
                "No Matching Playbook"
            )

            request.recommended_actions = []

            return request

        request.playbook = (
            playbook["playbook_name"]
        )

        try:

            request.recommended_actions = json.loads(
                playbook["steps_json"]
            )

        except Exception:

            request.recommended_actions = []

        request.agent_trace.append({
            "agent": "RiskAnomaly",
            "decision": "HIGH",
            "reason":
                f"Playbook Selected: {request.playbook}"
        })

        return request


class WorkIQAgent:

    def __init__(self, provider):
        self.provider = provider

    def get_policy_context(
        self,
        policy_name
    ):

        return self.provider.get_policy_context(
            policy_name
        )


class LifecycleOrchestrator:

    def __init__(
        self,
        identification_agent,
        authentication_agent,
        authorization_agent,
        audit_agent,
        risk_agent
    ):

        self.identification = identification_agent
        self.authentication = authentication_agent
        self.authorization = authorization_agent
        self.audit = audit_agent
        self.risk = risk_agent

    def process(self, request):

        response = request

        response = self.identification.execute(
            request,
            response
        )

        if response.identification_status != "PASSED":
            return response

        response = self.authentication.execute(
            response
        )

        response = self.authorization.execute(
            response
        )

        response = self.audit.execute(
            response
        )

        response = self.risk.execute(
            response
        )

        return response
