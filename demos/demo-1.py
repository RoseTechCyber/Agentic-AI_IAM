from fastapi import FastAPI

app = FastAPI()


@app.post("/demo/run-1")
def demo_run():

    return {
        "user_id": "EMP001",
        "identification_status": "PASSED",
        "authentication_status": "PASSED",
        "authorization_status": "PASSED",
        "audit_status": "PASSED",
        "risk_score": 60,
        "risk_level": "HIGH",
        "recommended_action": "STEP_UP_AUTHENTICATION",
        "playbook": "PB-RISK-003",
        "agent_trace": [
            {
                "agent": "Identification",
                "decision": "PASSED",
                "reason": "HR source verification successful"
            },
            {
                "agent": "Authentication",
                "decision": "PASSED",
                "reason": "Authentication successful"
            },
            {
                "agent": "Authorization",
                "decision": "PASSED",
                "reason": "RBAC validation successful"
            },
            {
                "agent": "Audit",
                "decision": "PASSED",
                "reason": "Audit event persisted"
            },
            {
                "agent": "RiskAnomaly",
                "decision": "HIGH",
                "reason": "Risk Score=60"
            }
        ]
    }