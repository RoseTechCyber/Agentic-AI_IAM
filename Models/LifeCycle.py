# models/lifecycle.py

from pydantic import BaseModel, Field
from typing import List, Dict


class AgentTrace(BaseModel):
    agent: str
    decision: str
    reason: str


class IdentityRequest(BaseModel):

    user_id: str
    country: str
    device: str
    login_time: str

    identification_status: str = "PENDING"
    authentication_status: str = "PENDING"
    authorization_status: str = "PENDING"
    audit_status: str = "PENDING"

    risk_score: int = 0
    risk_level: str = "LOW"

    recommended_action: str = "NONE"
    playbook: str = "NONE"

    agent_trace: List[AgentTrace] = []
	

