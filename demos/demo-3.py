@app.get("/demo/run-1")
def demo_run():

    request_payload = {
        "user_id": "EMP001",
        "country": "RU",
        "device": "UNKNOWN",
        "login_time": "02:15"
    }

    response_payload = orchestrator.process(
        IdentityRequest(**request_payload)
    )

    return {
        "request": request_payload,
        "response": response_payload
    }