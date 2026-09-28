# agents/authentication_agent.py

class AuthenticationAgent:

    def execute(self, request):

        if request.identification_status != "PASSED":

            request.authentication_status = "BLOCKED"

            return request

        if request.device == "UNKNOWN":

            request.risk_score += 15

        request.authentication_status = "PASSED"

        request.agent_trace.append({
            "agent": "Authentication",
            "decision": "PASSED",
            "reason": "Authentication successful"
        })

        return request
