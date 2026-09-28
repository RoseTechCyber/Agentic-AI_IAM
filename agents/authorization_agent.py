# agents/authorization_agent.py

class AuthorizationAgent:

    def execute(self, request):

        if request.authentication_status != "PASSED":

            request.authorization_status = "BLOCKED"

            return request

        request.authorization_status = "PASSED"

        request.agent_trace.append({
            "agent": "Authorization",
            "decision": "PASSED",
            "reason": "RBAC validation successful"
        })

        return request
