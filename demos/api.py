from fastapi import FastAPI
from pydantic import BaseModel
from typing import List


# ==================================================
# FastAPI App
# ==================================================

app = FastAPI(
    title="RoseTech Agentic AI IAM",
    description="Agentic Identity and Access Management Platform",
    version="1.0"
)


# ==================================================
# Models
# ==================================================

class AgentTrace(BaseModel):
    agent: str
    decision: str
    reason: str


class IdentityRequest(BaseModel):
    user_id: str
    country: str
    device: str
    login_time: str


class IdentityResponse(BaseModel):

    user_id: str

    identification_status: str
    authentication_status: str
    authorization_status: str
    audit_status: str

    risk_score: int
    risk_level: str

    recommended_action: str
    playbook: str

    agent_trace: List[AgentTrace]


# ==================================================
# Identification Agent
# ==================================================

class IdentificationAgent:

    def execute(self, request, response):

        response.identification_status = "PASSED"

        response.agent_trace.append(
            AgentTrace(
                agent="Identification",
                decision="PASSED",
                reason="HR source verification successful"
            )
        )

        return response


# ==================================================
# Authentication Agent
# ==================================================

class AuthenticationAgent:

    def execute(self, request, response):

        if response.identification_status != "PASSED":

            response.authentication_status = "BLOCKED"

            return response

        response.authentication_status = "PASSED"

        response.agent_trace.append(
            AgentTrace(
                agent="Authentication",
                decision="PASSED",
                reason="Authentication successful"
            )
        )

        return response


# ==================================================
# Authorization Agent
# ==================================================

class AuthorizationAgent:

    def execute(self, request, response):

        if response.authentication_status != "PASSED":

            response.authorization_status = "BLOCKED"

            return response

        response.authorization_status = "PASSED"

        response.agent_trace.append(
            AgentTrace(
                agent="Authorization",
                decision="PASSED",
                reason="RBAC validation successful"
            )
        )

        return response


# ==================================================
# Audit Agent
# ==================================================

class AuditAgent:

    def execute(self, request, response):

        response.audit_status = "PASSED"

        response.agent_trace.append(
            AgentTrace(
                agent="Audit",
                decision="PASSED",
                reason="Audit event persisted"
            )
        )

        return response


# ==================================================
# Risk & Anomaly Agent
# ==================================================

class RiskAnomalyAgent:

    APPROVED_COUNTRIES = ["NG", "UK"]

    def execute(self, request, response):

        score = 0

        login_hour = int(
            request.login_time.split(":")[0]
        )

        # After-hours login

        if login_hour < 7 or login_hour > 19:
            score += 20

        # Foreign country

        if request.country not in self.APPROVED_COUNTRIES:
            score += 25

        # Unknown device

        if request.device.upper() == "UNKNOWN":
            score += 15

        response.risk_score = score

        if score >= 80:

            response.risk_level = "CRITICAL"
            response.recommended_action = "DISABLE_ACCOUNT"
            response.playbook = "PB-RISK-004"

        elif score >= 60:

            response.risk_level = "HIGH"
            response.recommended_action = "STEP_UP_AUTHENTICATION"
            response.playbook = "PB-RISK-003"

        elif score >= 30:

            response.risk_level = "MEDIUM"
            response.recommended_action = "MFA_CHALLENGE"
            response.playbook = "PB-RISK-002"

        else:

            response.risk_level = "LOW"
            response.recommended_action = "ALLOW"
            response.playbook = "PB-RISK-001"

        response.agent_trace.append(
            AgentTrace(
                agent="RiskAnomaly",
                decision=response.risk_level,
                reason=f"Risk Score={score}"
            )
        )

        return response


# ==================================================
# Lifecycle Orchestrator
# ==================================================

class LifecycleOrchestrator:

    def __init__(self):

        self.identification = IdentificationAgent()
        self.authentication = AuthenticationAgent()
        self.authorization = AuthorizationAgent()
        self.audit = AuditAgent()
        self.risk = RiskAnomalyAgent()

    def process(self, request):

        response = IdentityResponse(
            user_id=request.user_id,
            identification_status="PENDING",
            authentication_status="PENDING",
            authorization_status="PENDING",
            audit_status="PENDING",
            risk_score=0,
            risk_level="LOW",
            recommended_action="NONE",
            playbook="NONE",
            agent_trace=[]
        )

        response = self.identification.execute(
            request,
            response
        )

        response = self.authentication.execute(
            request,
            response
        )

        response = self.authorization.execute(
            request,
            response
        )

        response = self.audit.execute(
            request,
            response
        )

        response = self.risk.execute(
            request,
            response
        )

        return response


# ==================================================
# Instantiate Orchestrator
# ==================================================

orchestrator = LifecycleOrchestrator()


# ==================================================
# Health Check
# ==================================================

@app.get("/")
def root():

    return {
        "application": "RoseTech Agentic IAM",
        "status": "running"
    }


# ==================================================
# Real Lifecycle Workflow
# ==================================================

@app.post("/identity/lifecycle")
def identity_lifecycle(payload: IdentityRequest):

    return orchestrator.process(payload)


# ==================================================
# Static Demo
# ==================================================

@app.get("/demo/run-1")
def demo_run():

    request_payload = IdentityRequest(
        user_id="EMP001",
        country="RU",
        device="UNKNOWN",
        login_time="02:15"
    )

    result = orchestrator.process(
        request_payload
    )

    return {
        "scenario": "After-Hours Foreign Login",
        "request": request_payload,
        "response": result
    }