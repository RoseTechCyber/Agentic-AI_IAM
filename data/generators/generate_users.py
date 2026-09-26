#!/usr/bin/env python3
"""
Generate a small set of demo identities, roles, permissions, and mappings.
Run from the repo root:

  python data/generate_users.py
"""
from pathlib import Path
from datetime import datetime, timezone
import json
from iam.repository import Repository

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def main():
    repo = Repository()
    now = now_iso()

    # roles
    roles = [
        ("role-employee", "Employee", "Baseline access"),
        ("role-engineering", "Engineering", "Engineering access"),
        ("role-finance", "Finance", "Finance access"),
    ]
    for rid, name, desc in roles:
        repo.insert("roles", {"id": rid, "name": name, "description": desc})

    # permissions
    perms = [
        ("perm-profile-read", "identity/profile", "read", 25),
        ("perm-payroll-read", "finance/payroll", "read", 80),
        ("perm-repo-read", "engineering/repositories", "read", 60),
    ]
    for pid, resource, action, sensitivity in perms:
        repo.insert(
            "permissions",
            {"id": pid, "resource": resource, "action": action, "sensitivity": sensitivity},
        )

    # identities
    identities = [
        ("usr-00001", "user001@example.test", "Synthetic User 001", "Engineering"),
        ("usr-00002", "user002@example.test", "Synthetic User 002", "Finance"),
        ("usr-00003", "user003@example.test", "Synthetic User 003", "Ops"),
    ]
    for iid, username, display_name, dept in identities:
        repo.insert(
            "identities",
            {
                "id": iid,
                "username": username,
                "display_name": display_name,
                "department": dept,
                "timezone": "UTC",
                "status": "active",
                "created_at": now,
            },
        )

    # association tables: use a single connection context
    with repo.connection() as db:
        assignments = [
            ("usr-00001", "role-engineering"),
            ("usr-00002", "role-finance"),
            ("usr-00003", "role-employee"),
        ]
        for identity_id, role_id in assignments:
            db.execute(
                "INSERT OR IGNORE INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES (?, ?, ?, ?, ?)",
                (identity_id, role_id, now, "generate_users", 1),
            )

        rp = [
            ("role-engineering", "perm-repo-read"),
            ("role-finance", "perm-payroll-read"),
            ("role-employee", "perm-profile-read"),
        ]
        for role_id, permission_id in rp:
            db.execute(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, granted_at) VALUES (?, ?, ?)",
                (role_id, permission_id, now),
            )

    print("generate_users: done")

if __name__ == "__main__":
    main()