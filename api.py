@app.post("/identity/lifecycle")
async def identity_lifecycle(
    payload: IdentityRequest
):

    result = orchestrator.process(
        payload
    )

    return result
``