import json
import os
from dataclasses import dataclass, field
from datetime import datetime



class DemoOrchestrator:

    def run(self, user_id: str):

        response = {
            "user_id": user_id,
            "agent_trace": []
        }

        #
        # Identification
        #

        response["agent_trace"].append({
            "agent": "IdentificationAgent",
            "decision": "PASSED",
            "reason": "Identity record confirmed"
        })

        #
        # Authentication
        #

        response["agent_trace"].append({
            "agent": "AuthenticationAgent",
            "decision": "PASSED",
            "reason": "Authentication controls satisfied"
        })

        #
        # Authorization
        #

        response["agent_trace"].append({
            "agent": "AuthorizationAgent",
            "decision": "PASSED",
            "reason": "Role and permission validation successful"
        })

        #
        # Audit
        #

        response["agent_trace"].append({
            "agent": "AuditAgent",
            "decision": "RECORDED",
            "reason": f"Audit event captured {datetime.utcnow().isoformat()}"
        })

        #
        # WorkIQ
        #

        workiq = {
            "risk_score": 82,
            "risk_level": "HIGH",
            "reasons": [
                "low device trust",
                "MFA not satisfied",
                "wrong-time check-in"
            ]
        }

        #
        # Playbook
        #

        playbook = {
            "playbook_name":
                "High risk identity containment",

            "actions": [
                "revoke active sessions",
                "require step-up MFA",
                "notify IAM owner"
            ]
        }

        response["workiq"] = workiq

        response["playbook"] = playbook

        response["agent_trace"].append({
            "agent": "WorkIQ",
            "decision": "HIGH RISK",
            "reason": "Risk score exceeded threshold"
        })

        response["agent_trace"].append({
            "agent": "PlaybookAgent",
            "decision": playbook["playbook_name"],
            "reason": "Playbook selected from policy context"
        })

        return response
