import sqlite3
import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from datetime import datetime
from pydantic import Field

class ContextProvider:
    def __init__(self):

        self.conn = sqlite3.connect(
            "data/schemas/iam_datastore.db",
            check_same_thread=False
        )

        self.conn.row_factory = sqlite3.Row
        with self.conn() as db:
            schema = Path(__file__).with_name("iam_datastore.sql").read_text()
            db.executescript(schema)

    def get_identity(self, user_id):

        cur = self.conn.cursor()

        cur.execute(
            """
            SELECT *
            FROM identities
            WHERE user_id = ?
            """,
            (user_id,)
        )

        return cur.fetchone()
        
    def get_recent_access_events(self, user_id):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT *
            FROM access_events_trigger
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 5
            """, (user_id,))
        return cur.fetchall()
        
    def get_latest_access_event(self, user_id):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT *
            FROM access_events
            WHERE user_id = ?
            ORDER BY occurred_at DESC
            LIMIT 1
            """, (user_id,))
        return cur.fetchone()
        
    def get_user_permissions(self, user_id):

        cur = self.conn.cursor()

        cur.execute("""
            SELECT *
            FROM user_permissions_trigger
                WHERE user_id = ?
            """, (user_id,))

        return cur.fetchall()
        
      
    def get_policy_context(self, policy_name):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT *
        FROM policy_context_trigger
        WHERE policy_name = ?
        """, (policy_name,))

        return cur.fetchall()
        
    def get_playbook(self, playbook_id):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT *
        FROM playbooks
        WHERE playbook_id = ?
        """, (playbook_id,))

        return cur.fetchone()
        
    def get_playbook_by_name(self, playbook_name):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT *
        FROM playbooks
        WHERE playbook_name = ?
        LIMIT 1
        """, (playbook_name,))

        return cur.fetchone()
        
    def get_playbook_by_reason(self, reason):

        cur = self.conn.cursor()

        cur.execute("""
        SELECT *
        FROM playbooks
        WHERE lower(playbook_name) LIKE ?
        LIMIT 1
        """, (f"%{reason.lower()}%",))

        return cur.fetchone()

class LifecycleOrchestrator:

    def __init__(
        self,
        IdentificationAgent,
        AuthenticationAgent,
        AuthorizationAgent,
        AuditAgent,
        RiskAnomalyAgent,
        WorkIQAgent,
        EventAgent
    ):
        self.identification = IdentificationAgent
        self.authentication = AuthenticationAgent
        self.authorization = AuthorizationAgent
        self.audit = AuditAgent
        self.risk = RiskAnomalyAgent
        self.workiq =  WorkIQAgent
        self.events = EventAgent
        
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
            "agent":"Identification",
            "decision":"FAILED",
            "reason":"Identity not found"
        })
            return response
        response.identification_status = "PASSED"
        response.agent_trace.append({
                    "agent":"Identification",
                    "decision":"PASSED",
                    "reason":"Identity verified"
        })
        return response
   
class AuthenticationAgent:
    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):
        if request.identification_status != "PASSED":
            request.authentication_status = "BLOCKED"
            request.agent_trace.append({
                "agent":"Authentication",
                "decision":"BLOCKED",
                "reason":"Authentication Failed"
            )
            return request
       
        events = self.provider.get_recent_access_events(request.user_id)
        if not events:
            request.risk_score += 10
        if request.device == "UNKNOWN":
            request.risk_score += 15

        request.authentication_status = "PASSED"
        request.agent_trace.append({
                "agent":"Authentication",
                "decision":"PASSED",
                "reason":"Authentication successful"
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

        if len(permissions) == 0:
            request.authorization_status = "FAILED"
            request.agent_trace.append({
                "agent":"Authorization",
                "decision":"FAILED",
                "reason":"No permissions assigned"
            })
            return request

        request.authorization_status = "PASSED"
        request.agent_trace.append({
        "agent":"Authorization",
        "decision":"PASSED",
        "reason":"RBAC validation successful"
        })
        return request

class AuditAgent:
    def __init__(self, provider):
        self.provider = provider

    def execute(self, request):
        cur = self.provider.conn.cursor()
        cur.execute(
            """
            INSERT INTO access_events
            (
                user_id,
                event_type,
                source_ip,
                device_id,
                occurred_at
            )
            VALUES (?,?,?,?,?)
            """,
            (
                request.user_id,
                "IDENTITY_LIFECYCLE_RUN",
                None,
                None,
                datetime.utcnow()
            )
        )

        self.provider.conn.commit()

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
            occurred_at = (event["occurred_at"].replace("Z", "+00:00")
)
            login_hour = datetime.fromisoformat(occurred_at).hour

            if login_hour < 7 or login_hour > 19:

                reasons.append("wrong-time check-in")
                score += 20
        identity = self.provider.get_identity(
            request.user_id
        )
        if identity:
            dept = identity["department"]
            if dept in [
                "Finance",
                "Security",
                "HR"
            ]:
                score += 20

        event = self.provider.get_latest_access_event(request.user_id)
        device = None
        if event:
        device = event["device_id"]

        if not device:

                reasons.append("low device trust")

                score += 15


        request.risk_score = score

        selected_playbook = \
            "Privileged access review"

        if "wrong-time check-in" in reasons:

            selected_playbook = \
                "Wrong-time check-in"

        elif "low device trust" in reasons:

            selected_playbook = \
                "High risk identity containment"

        playbook = \
            self.provider.get_playbook_by_name(
                selected_playbook
            )

        if not playbook:

            request.playbook = \
                "No Matching Playbook"

            request.recommended_actions = []

            return request

        request.playbook = \
            playbook["playbook_name"]

        request.recommended_actions = \
            json.loads(
                playbook["steps_json"]
            )

        request.agent_trace.append({
            "agent":"RiskAnomaly",
            "decision":"HIGH",
            "reason":
                f"Playbook Selected: {request.playbook}"
        })

        return request
        
        
class WorkIQAgent:
    def __init__(self, provider):
        self.provider = provider
    def get_policy_context(self, policy_name):
        return self.provider.get_policy_context(policy_name)
       
        
class EventAgent:

    def __init__(self, provider):

        self.provider = provider

    def publish(
        self,
        event_type,
        payload
    ):

        cur = self.provider.conn.cursor()

        cur.execute(
            """
            INSERT INTO event_queue
            (
                event_type,
                payload_json,
                created_at
            )
            VALUES (?,?,?)
            """,
            (
                event_type,
                json.dumps(payload.dict(), default=str),
                datetime.utcnow()
            )
        )

        self.provider.conn.commit()
