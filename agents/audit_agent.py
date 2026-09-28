# agents/audit_agent.py

import sqlite3
from datetime import datetime


class AuditAgent:

    def execute(self, request):

        conn = sqlite3.connect("iam_datastore.db")

        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO audit_events
            (
                user_id,
                event_type,
                created_at
            )
            VALUES (?,?,?)
            """,
            (
                request.user_id,
                "IDENTITY_LIFECYCLE_RUN",
                datetime.utcnow()
            )
        )

        conn.commit()

        request.audit_status = "PASSED"

        request.agent_trace.append({
            "agent": "Audit",
            "decision": "PASSED",
            "reason": "Audit event persisted"
        })

        return request
``