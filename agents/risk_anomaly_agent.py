# agents/risk_anomaly_agent.py

from datetime import datetime


class RiskAnomalyAgent:

    RISK_VECTORS = {

        "after_hours_login": 20,
        "foreign_country": 25,
        "new_device": 15,
        "privileged_access": 30,
        "failed_mfa": 20
    }

    APPROVED_COUNTRIES = [
        "NG",
        "UK"
    ]

    def execute(self, request):

        score = request.risk_score

        login_hour = int(
            request.login_time.split(":")[0]
        )

        # After hours

        if login_hour < 7 or login_hour > 19:

            score += self.RISK_VECTORS[
                "after_hours_login"
            ]

        # Foreign Country

        if request.country not in self.APPROVED_COUNTRIES:

            score += self.RISK_VECTORS[
                "foreign_country"
            ]

        # New Device

        if request.device == "UNKNOWN":

            score += self.RISK_VECTORS[
                "new_device"
            ]

        request.risk_score = score

        if score >= 80:

            request.risk_level = "CRITICAL"
            request.playbook = "PB-RISK-004"
            request.recommended_action = "DISABLE_ACCOUNT"

        elif score >= 60:

            request.risk_level = "HIGH"
            request.playbook = "PB-RISK-003"
            request.recommended_action = "STEP_UP_AUTHENTICATION"

        elif score >= 30:

            request.risk_level = "MEDIUM"
            request.playbook = "PB-RISK-002"
            request.recommended_action = "MFA_CHALLENGE"

        else:

            request.risk_level = "LOW"
            request.playbook = "PB-RISK-001"
            request.recommended_action = "ALLOW"

        request.agent_trace.append({
            "agent": "RiskAnomaly",
            "decision": request.risk_level,
            "reason": f"Risk Score={score}"
        })

        return request
