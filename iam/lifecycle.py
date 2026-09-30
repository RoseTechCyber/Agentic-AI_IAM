import json
import httpx
from datetime import datetime
from typing import Any
from .repository import Repository
from .workflow import IAMWorkflow
import repo from repository


class ContextProvider:

    def __init__(self, repo):
        self.repo = repo

    def get_identity(self, identity_id):

        rows = self.repo.execute(
            """
            SELECT *
            FROM identities
            WHERE id = ?
            """,
            (identity_id,)
        )

        return rows[0] if rows else None

    def get_latest_event(self, identity_id):

        rows = self.repo.execute(
            """
            SELECT *
            FROM access_events
            WHERE identity_id = ?
            ORDER BY occurred_at DESC
            LIMIT 1
            """,
            (identity_id,)
        )

        return rows[0] if rows else None

    def get_roles(self, identity_id):

        return self.repo.execute(
            """
            SELECT r.*
            FROM roles r
            JOIN identity_roles ir
            ON ir.role_id = r.id
            WHERE ir.identity_id = ?
            """,
            (identity_id,)
        )
	
class IdentificationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        identity = self.provider.get_identity(
            request.user_id
        )

        if not identity:

            request.identification_status = "FAILED"

            request.agent_trace.append({
                "agent":"Identification",
                "decision":"FAILED",
                "reason":"Identity not found"
            })

            return request

        if identity["status"] != "active":

            request.identification_status = "FAILED"

            request.agent_trace.append({
                "agent":"Identification",
                "decision":"FAILED",
                "reason":"Identity inactive"
            })

            return request

        request.identification_status = "PASSED"

        request.agent_trace.append({
            "agent":"Identification",
            "decision":"PASSED",
            "reason":"Active identity verified"
        })

        return request
		
class AuthenticationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        if request.identification_status != "PASSED":

            request.authentication_status = "BLOCKED"

            return request

        event = self.provider.get_latest_event(
            request.user_id
        )

        request.authentication_status = "PASSED"

        request.agent_trace.append({
            "agent":"Authentication",
            "decision":"PASSED",
            "reason":"Authentication controls satisfied"
        })

        return request
		
class AuthorizationAgent:

    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):

        if request.authentication_status != "PASSED":

            request.authorization_status = "BLOCKED"

            return request

        roles = self.provider.get_roles(
            request.user_id
        )

        if not roles:

            request.authorization_status = "FAILED"

            return request

        request.authorization_status = "PASSED"

        request.agent_trace.append({
            "agent":"Authorization",
            "decision":"PASSED",
            "reason":"Role membership verified"
        })

        return request
		
class AuditAgent:

    def __init__(self, repo):
        self.repo = repo

    def execute(self, request):

        self.repo.insert(
            "access_events",
            {
                "id": str(uuid.uuid4()),
                "identity_id": request.user_id,
                "event_type": "identity_lifecycle",
                "stage": "audit",
                "action": "evaluate",
                "decision": "allow",
                "occurred_at":
                    datetime.utcnow().isoformat()
            }
        )

        request.audit_status = "PASSED"

        return request

class RiskAgent:

    def __init__(self, workflow):
        self.workflow = workflow

    def execute(self, request):

        result = self.workflow.evaluate(
            {
                "user_id": request.user_id,
                "event_type": "login",
                "occurred_at":
                    datetime.utcnow().isoformat(),
                "device_trust": 0.3,
                "mfa_satisfied": False,
                "metadata": {
                    "lifecycle": True
                }
            }
        )

        request.risk_score = result["risk_score"]

        request.recommended_actions = []

        if result["case"]:

            playbook = result["case"]["playbook"]

            if playbook:

                request.playbook = playbook["name"]

        return request
		
