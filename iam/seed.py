#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from iam.repository import Repository

def seed() -> None:
    repo = Repository()
    now = datetime.now(timezone.utc).isoformat()

    # identities (was users)
    repo.insert(
        "identities",
        {
            "id": "u-100",
            "username": "avery.analyst@example.test",
            "display_name": "Avery Analyst",
            "department": "Finance",
            "timezone": "UTC",
            "status": "active",
            "created_at": now,
        },
    )

    repo.insert(
        "identities",
        {
            "id": "u-200",
            "username": "morgan.contractor@example.test",
            "display_name": "Morgan Contractor",
            "department": "Engineering",
            "timezone": "America/New_York",
            "status": "active",
            "created_at": now,
        },
    )

    # roles (unchanged)
    repo.insert(
        "roles",
        {
            "id": "r-employee",
            "name": "employee",
            "description": "Standard workforce role",
        },
    )

    repo.insert(
        "roles",
        {
            "id": "r-finance",
            "name": "finance-approver",
            "description": "Finance approval role",
        },
    )

    # permissions (was entitlements)
    repo.insert(
        "permissions",
        {
            "id": "e-payroll-read",
            "resource": "finance/payroll",
            "action": "read",
            "sensitivity": 90,
        },
    )

    repo.insert(
        "permissions",
        {
            "id": "e-hr-read",
            "resource": "hr/profile",
            "action": "read",
            "sensitivity": 70,
        },
    )

    # association tables: use a single connection context
    with repo.connection() as db:
        # identity_roles (was user_roles)
        db.execute(
            "INSERT OR IGNORE INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES (?, ?, ?, ?, ?)",
            ("u-100", "r-employee", now, "seed", 1),
        )
        db.execute(
            "INSERT OR IGNORE INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES (?, ?, ?, ?, ?)",
            ("u-100", "r-finance", now, "seed", 0),
        )
        db.execute(
            "INSERT OR IGNORE INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES (?, ?, ?, ?, ?)",
            ("u-200", "r-employee", now, "seed", 1),
        )

        # role_permissions (was role_entitlements)
        db.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, granted_at) VALUES (?, ?, ?)",
            ("r-finance", "e-payroll-read", now),
        )
        db.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, granted_at) VALUES (?, ?, ?)",
            ("r-employee", "e-hr-read", now),
        )

    # policies (keep existing IDs and text)
    policies = [
        (
            "p-identification",
            "Identity lifecycle governance",
            "identification",
            '{"active_identity_required": true}',
            "Identification requires an active identity linked to an approved workforce record.",
            100,
        ),
        (
            "p-auth",
            "Strong authentication",
            "authentication",
            '{"mfa_required": true, "minimum_device_trust": 0.5}',
            "Authentication requires MFA and a trusted device for sensitive resources.",
            110,
        ),
        (
            "p-least",
            "Least privilege",
            "authorization",
            '{"deny_unknown_resource": true, "risk_points": 35}',
            "Authorization follows the effective role entitlement cross matrix and denies unknown resources.",
            90,
        ),
        (
            "p-time",
            "Work-hour access",
            "audit",
            '{"allowed_start": 7, "allowed_end": 19, "risk_points": 30}',
            "Check-ins outside the user's approved local shift are anomalous and require review.",
            80,
        ),
    ]

    for pid, name, stage, rule_json, text, priority in policies:
        repo.insert(
            "policies",
            {
                "id": pid,
                "name": name,
                "stage": stage,
                "rule_json": rule_json,
                "text": text,
                "priority": priority,
                "enabled": 1,
            },
        )

if __name__ == "__main__":
    seed()
