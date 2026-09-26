#!/usr/bin/env python3
"""
Generate demo access_events. Run from the repo root:

  python data/generate_events.py
"""
from datetime import datetime, timezone, timedelta
import random
import json
from iam.repository import Repository
import uuid

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()

def main():
    repo = Repository()
    now = datetime.now(timezone.utc)
    identities = [r["id"] for r in repo.execute("SELECT id FROM identities LIMIT 50")]

    if not identities:
        print("No identities found — run generate_users.py or seed the DB first.")
        return

    sample_resources = ["identity/profile", "finance/payroll", "engineering/repositories", "support/tickets"]
    event_types = ["login", "checkin", "logout", "mfa_challenge"]

    for i in range(20):
        identity = random.choice(identities)
        event_type = random.choice(event_types)
        occurred = now - timedelta(hours=random.randint(0, 72), minutes=random.randint(0, 59))
        device_trust = round(random.random(), 2)
        mfa = random.choice([True, False])
        requested_resource = random.choice(sample_resources)
        payload = {
            "id": str(uuid.uuid4()),
            "identity_id": identity,
            "event_type": event_type,
            "stage": "authentication" if event_type in ("login", "mfa_challenge") else "audit",
            "action": event_type,
            "decision": "allow",
            "source_ip": f"203.0.113.{random.randint(2,250)}",
            "device_id": f"device-{random.randint(1,20)}",
            "requested_resource": requested_resource,
            "device_trust": device_trust,
            "mfa_satisfied": int(mfa),
            "occurred_at": iso(occurred),
            "metadata_json": json.dumps({"demo": True}),
        }
        repo.insert("access_events", payload)

    print("generate_events: created 20 events")

if __name__ == "__main__":
    main()