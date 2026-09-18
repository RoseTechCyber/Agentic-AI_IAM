from __future__ import annotations

import json
from datetime import datetime, timezone

from .repository import Repository


def seed() -> None:
    repo = Repository(); now = datetime.now(timezone.utc).isoformat()
    repo.insert("users", {"id": "u-100", "display_name": "Avery Analyst", "department": "Finance", "timezone": "UTC", "active": 1, "created_at": now})
    repo.insert("users", {"id": "u-200", "display_name": "Morgan Contractor", "department": "Engineering", "timezone": "UTC", "active": 1, "created_at": now})
    repo.insert("roles", {"id": "r-employee", "name": "employee", "description": "Standard workforce role"})
    repo.insert("roles", {"id": "r-finance", "name": "finance-approver", "description": "Finance approval role"})
    repo.insert("entitlements", {"id": "e-payroll-read", "resource": "finance/payroll", "action": "read", "sensitivity": 90})
    repo.insert("entitlements", {"id": "e-hr-read", "resource": "hr/profile", "action": "read", "sensitivity": 70})
    with repo.connection() as db:
        db.execute("INSERT OR IGNORE INTO user_roles VALUES (?,?)", ("u-100", "r-employee")); db.execute("INSERT OR IGNORE INTO user_roles VALUES (?,?)", ("u-100", "r-finance")); db.execute("INSERT OR IGNORE INTO user_roles VALUES (?,?)", ("u-200", "r-employee"))
        db.execute("INSERT OR IGNORE INTO role_entitlements VALUES (?,?)", ("r-finance", "e-payroll-read")); db.execute("INSERT OR IGNORE INTO role_entitlements VALUES (?,?)", ("r-employee", "e-hr-read"))
    repo.insert("policies", {"id": "p-auth", "name": "Strong authentication", "stage": "authentication", "rule_json": json.dumps({"mfa_required": True, "minimum_device_trust": 0.5}), "text": "Authentication requires MFA and a trusted device for sensitive resources."})
    repo.insert("policies", {"id": "p-time", "name": "Work-hour access", "stage": "audit", "rule_json": json.dumps({"allowed_start": 7, "allowed_end": 19, "risk_points": 30}), "text": "Check-ins outside 07:00 to 19:00 UTC are anomalous and require review."})
    repo.insert("policies", {"id": "p-least", "name": "Least privilege", "stage": "authorization", "rule_json": json.dumps({"deny_unknown_resource": True, "risk_points": 35}), "text": "Authorization follows the effective role entitlement cross matrix and denies unknown resources."})
    repo.insert("playbooks", {"id": "pb-contain", "name": "High risk identity containment", "trigger_json": json.dumps({"risk_score_gte": 70}), "steps_json": json.dumps(["revoke active sessions", "require step-up MFA", "notify IAM owner", "preserve audit evidence"]), "priority": 100})
    repo.insert("playbooks", {"id": "pb-time", "name": "Wrong-time check-in", "trigger_json": json.dumps({"outside_utc_hours": [7, 19]}), "steps_json": json.dumps(["verify shift or exception", "compare device and IP history", "open review case"]), "priority": 80})

if __name__ == "__main__": seed(); print("Seeded IAM demo data")
