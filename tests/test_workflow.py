from iam.repository import Repository
from iam.workflow import IAMWorkflow


def test_low_risk_event_does_not_create_case(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    repo = Repository()
    repo.insert("users", {"id":"u1","display_name":"Test","department":"IT","timezone":"UTC","active":1,"created_at":"2026-01-01T00:00:00Z"})
    repo.insert("entitlements", {"id":"e1","resource":"app","action":"read","sensitivity":10})
    repo.insert("roles", {"id":"r1","name":"user","description":""})
    with repo.connection() as db:
        db.execute("INSERT INTO user_roles VALUES ('u1','r1')")
        db.execute("INSERT INTO role_entitlements VALUES ('r1','e1')")
    result = IAMWorkflow(repo).evaluate({"user_id":"u1","event_type":"login","device_trust":1,"mfa_satisfied":True,"requested_resource":"app","occurred_at":"2026-01-15T10:00:00Z"})
    assert result["anomaly"] is False
