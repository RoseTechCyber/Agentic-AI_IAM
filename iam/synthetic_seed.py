#!/usr/bin/env python3
"""
Programmatic synthetic seeder that aligns with iam/schema.sql (canonical tables).
This script uses Repository.insert so it is safe (non-destructive) and idempotent
for development use. It creates a small, useful demo dataset.
"""

from __future__ import annotations
from datetime import datetime, timezone
import json
from iam.repository import Repository

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def seed(repo: Repository) -> None:
    now = now_iso()

    # Roles
    roles = [
        ("role-finance", "Finance Analyst", "Finance reporting and payroll access"),
        ("role-iam", "IAM Administrator", "Identity and access administration"),
        ("role-engineering", "Engineering", "Engineering systems access"),
        ("role-audit", "Auditor", "Read-only audit and compliance access"),
        ("role-support", "Support Analyst", "Customer and support operations"),
        ("role-employee", "Employee", "Baseline employee access"),
    ]
    for rid, name, desc in roles:
        repo.insert("roles", {"id": rid, "name": name, "description": desc})

    # Permissions
    perms = [
        ("perm-payroll-read", "finance/payroll", "read", 80),
        ("perm-payroll-write", "finance/payroll", "write", 95),
        ("perm-iam-admin", "iam/admin", "admin", 100),
        ("perm-iam-read", "iam/directory", "read", 70),
        ("perm-engineering-read", "engineering/repositories", "read", 60),
        ("perm-engineering-write", "engineering/repositories", "write", 85),
        ("perm-audit-read", "audit/cases", "read", 65),
        ("perm-support-read", "support/tickets", "read", 45),
        ("perm-profile-read", "identity/profile", "read", 25),
    ]
    for pid, resource, action, sensitivity in perms:
        repo.insert(
            "permissions",
            {
                "id": pid,
                "resource": resource,
                "action": action,
                "sensitivity": sensitivity,
            },
        )

    # Create a few identities
    identities = [
        ("usr-00001", "user001@example.test", "Synthetic User 001", "Engineering"),
        ("usr-00002", "user002@example.test", "Synthetic User 002", "Finance"),
        ("usr-00003", "user003@example.test", "Synthetic User 003", "Support"),
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

    # Assign roles to identities
    assignments = [
        ("usr-00001", "role-engineering"),
        ("usr-00002", "role-finance"),
        ("usr-00003", "role-support"),
        ("usr-00001", "role-employee"),
        ("usr-00002", "role-employee"),
    ]
    for identity_id, role_id in assignments:
        repo.insert(
            "identity_roles",
            {
                "identity_id": identity_id,
                "role_id": role_id,
                "assigned_at": now,
                "assigned_by": "synthetic-seed",
                "is_primary": 1,
            },
        )

    # Grant role_permissions (note: uses existing permission ids)
    rp = [
        ("role-finance", "perm-payroll-read"),
        ("role-finance", "perm-profile-read"),
        ("role-iam", "perm-iam-admin"),
        ("role-iam", "perm-iam-read"),
        ("role-engineering", "perm-engineering-read"),
        ("role-engineering", "perm-engineering-write"),
        ("role-audit", "perm-audit-read"),
        ("role-support", "perm-support-read"),
        ("role-employee", "perm-profile-read"),
    ]
    for role_id, permission_id in rp:
        repo.insert(
            "role_permissions",
            {
                "role_id": role_id,
                "permission_id": permission_id,
                "granted_at": now,
            },
        )

    # Policies
    policies = [
        (
            "policy-mfa",
            "MFA requirement",
            "authentication",
            json.dumps({"mfa_required": True}),
            "Authentication requires MFA for protected resources.",
            110,
        ),
        (
            "policy-device-trust",
            "Device trust requirement",
            "authentication",
            json.dumps({"minimum_device_trust": 0.5}),
            "Low device trust increases identity risk and requires review.",
            105,
        ),
        (
            "policy-privileged-access",
            "Privileged access review",
            "authorization",
            json.dumps({"sensitive_resource": True}),
            "Privileged access requires verified authorization and preserved evidence.",
            100,
        ),
        (
            "policy-off-hours",
            "Off-hours review",
            "audit",
            json.dumps({"outside_local_hours": True}),
            "Off-hours activity requires shift verification and review.",
            100,
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

    # Playbooks
    playbooks = [
        (
            "pb-contain",
            "High risk identity containment",
            "any",
            json.dumps({"risk_score_gte": 70}),
            json.dumps(
                ["revoke active sessions", "require step-up MFA", "notify IAM owner"]
            ),
            110,
        ),
        (
            "pb-time",
            "Wrong-time check-in",
            "audit",
            json.dumps({"outside_local_hours": True}),
            json.dumps(
                ["verify shift or exception", "compare device and IP history", "open review case"]
            ),
            105,
        ),
    ]
    for pb in playbooks:
        repo.insert(
            "playbooks",
            {
                "id": pb[0],
                "name": pb[1],
                "stage": pb[2],
                "trigger_json": pb[3],
                "steps_json": pb[4],
                "priority": pb[5],
                "enabled": 1,
            },
        )

    print("Synthetic seed complete.")

if __name__ == "__main__":
    repo = Repository()
    seed(repo)
