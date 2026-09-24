from __future__ import annotations

"""Generate deterministic, privacy-safe IAM data for the current SQLite schema.

Usage:
    python -m iam.synthetic_seed --reset --users 100 --events 2000

The generator creates only synthetic identifiers and reserved documentation IPs.
It does not create passwords, tokens, email addresses, or real employee data.
"""

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any

from .repository import Repository


DEPARTMENTS = ["Finance", "Engineering", "Human Resources", "Sales", "Security", "Operations"]
TIMEZONES = ["UTC", "America/New_York", "Europe/London", "Africa/Lagos"]
EVENT_TYPES = ["login", "mfa_challenge", "authorize", "checkin", "logout"]
RESERVED_IPS = ["192.0.2.10", "198.51.100.20", "203.0.113.30"]


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def insert_links(repo: Repository, table: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    placeholders = ",".join("?" for _ in columns)
    column_sql = ",".join(columns)
    with repo.connection() as db:
        db.executemany(
            f"INSERT OR REPLACE INTO {table} ({column_sql}) VALUES ({placeholders})",
            rows,
        )


def reset(repo: Repository) -> None:
    # Delete dependants first so this remains safe if foreign keys are enabled later.
    with repo.connection() as db:
        for table in (
            "anomaly_cases", "access_events", "playbooks", "policies",
            "role_entitlements", "user_roles", "entitlements", "roles", "users",
        ):
            db.execute(f"DELETE FROM {table}")


def seed(users_count: int, events_count: int, seed_value: int, should_reset: bool) -> dict[str, int]:
    rng = random.Random(seed_value)
    repo = Repository()
    if should_reset:
        reset(repo)

    now = datetime.now(timezone.utc).replace(microsecond=0)

    roles = [
        ("r-employee", "employee", "Standard workforce role"),
        ("r-finance", "finance-approver", "Approves finance transactions"),
        ("r-engineer", "engineer", "Build and service operations role"),
        ("r-hr", "hr-specialist", "Human resources data role"),
        ("r-security", "security-analyst", "Security monitoring role"),
        ("r-admin", "iam-administrator", "Privileged IAM administration role"),
    ]
    for role_id, name, description in roles:
        repo.insert("roles", {"id": role_id, "name": name, "description": description})

    entitlements = [
        ("e-hr-read", "hr/profile", "read", 70),
        ("e-finance-read", "finance/payroll", "read", 90),
        ("e-finance-approve", "finance/payroll", "approve", 95),
        ("e-engineering-read", "engineering/source", "read", 60),
        ("e-engineering-deploy", "engineering/production", "deploy", 95),
        ("e-security-read", "security/alerts", "read", 80),
        ("e-iam-admin", "iam/directory", "admin", 100),
        ("e-report-read", "analytics/reports", "read", 50),
    ]
    for entitlement_id, resource, action, sensitivity in entitlements:
        repo.insert("entitlements", {
            "id": entitlement_id, "resource": resource, "action": action,
            "sensitivity": sensitivity,
        })

    role_entitlements = {
        "r-employee": ["e-hr-read", "e-report-read"],
        "r-finance": ["e-finance-read", "e-finance-approve", "e-report-read"],
        "r-engineer": ["e-engineering-read", "e-engineering-deploy"],
        "r-hr": ["e-hr-read", "e-report-read"],
        "r-security": ["e-security-read", "e-report-read"],
        "r-admin": ["e-iam-admin", "e-security-read", "e-report-read"],
    }
    insert_links(repo, "role_entitlements", ("role_id", "entitlement_id"), [
        (role_id, entitlement_id)
        for role_id, entitlement_ids in role_entitlements.items()
        for entitlement_id in entitlement_ids
    ])

    user_ids: list[str] = []
    user_roles: list[tuple[str, str]] = []
    for number in range(1, users_count + 1):
        user_id = f"u-{number:04d}"
        user_ids.append(user_id)
        department = DEPARTMENTS[(number - 1) % len(DEPARTMENTS)]
        active = 0 if number % 37 == 0 else 1
        created = now - timedelta(days=rng.randint(30, 900))
        repo.insert("users", {
            "id": user_id,
            "display_name": f"Synthetic User {number:04d}",
            "department": department,
            "timezone": TIMEZONES[(number - 1) % len(TIMEZONES)],
            "active": active,
            "created_at": iso(created),
        })

        user_roles.append((user_id, "r-employee"))
        department_role = {
            "Finance": "r-finance", "Engineering": "r-engineer",
            "Human Resources": "r-hr", "Security": "r-security",
        }.get(department)
        if department_role:
            user_roles.append((user_id, department_role))
        if number % 29 == 0:
            user_roles.append((user_id, "r-admin"))

    insert_links(repo, "user_roles", ("user_id", "role_id"), user_roles)

    policies = [
        ("p-identification", "Active identity required", "identification",
         {"active_identity_required": True}, "Only active identities may access services."),
        ("p-authentication", "Strong authentication", "authentication",
         {"mfa_required": True, "minimum_device_trust": 0.5}, "Sensitive access requires MFA and a trusted device."),
        ("p-least-privilege", "Least privilege", "authorization",
         {"deny_unknown_resource": True, "risk_points": 35}, "Unknown resources are denied by default."),
        ("p-work-hours", "Approved work hours", "audit",
         {"allowed_start": 7, "allowed_end": 19, "risk_points": 30}, "Off-hours activity requires review."),
    ]
    for policy_id, name, stage, rule, text in policies:
        repo.insert("policies", {
            "id": policy_id, "name": name, "stage": stage,
            "rule_json": json.dumps(rule), "text": text, "priority": 100,
        })

    playbooks = [
        ("pb-contain", "High risk identity containment", "any",
         {"risk_score_gte": 70}, ["revoke active sessions", "require step-up MFA", "notify IAM owner"]),
        ("pb-off-hours", "Off-hours access review", "audit",
         {"outside_local_hours": True}, ["verify shift exception", "compare IP history", "open review case"]),
        ("pb-privilege", "Privileged access review", "authorization",
         {"sensitive_resource": True}, ["verify approval", "review entitlement", "preserve evidence"]),
    ]
    for playbook_id, name, stage, trigger, steps in playbooks:
        repo.insert("playbooks", {
            "id": playbook_id, "name": name, "stage": stage,
            "trigger_json": json.dumps(trigger), "steps_json": json.dumps(steps),
            "priority": 100,
        })

    resources = [row[1] for row in entitlements]
    event_ids: list[tuple[str, str, float, str]] = []
    for number in range(1, events_count + 1):
        user_id = rng.choice(user_ids)
        event_id = f"evt-{number:06d}"
        event_type = rng.choice(EVENT_TYPES)
        suspicious = number % 23 == 0
        trust = round(rng.uniform(0.05, 0.45) if suspicious else rng.uniform(0.65, 1.0), 3)
        mfa = 0 if suspicious else int(rng.random() > 0.12)
        resource = "finance/payroll" if suspicious and number % 2 == 0 else rng.choice(resources)
        occurred = now - timedelta(minutes=rng.randint(0, 60 * 24 * 90))
        metadata = {"synthetic": True, "generator_seed": seed_value, "suspicious_sample": suspicious}
        repo.insert("access_events", {
            "id": event_id, "user_id": user_id, "event_type": event_type,
            "source_ip": rng.choice(RESERVED_IPS), "device_trust": trust,
            "mfa_satisfied": mfa, "requested_resource": resource,
            "occurred_at": iso(occurred), "metadata_json": json.dumps(metadata),
        })
        score = round((35 if suspicious else 0) + (25 if not mfa else 0) + (20 if trust < 0.5 else 0), 2)
        if score >= 70:
            event_ids.append((event_id, user_id, score, iso(occurred)))

    for case_number, (event_id, user_id, score, occurred_at) in enumerate(event_ids, 1):
        repo.insert("anomaly_cases", {
            "id": f"case-{case_number:05d}", "event_id": event_id, "user_id": user_id,
            "stage": "authorization", "score": score,
            "severity": "critical" if score >= 90 else "high",
            "reasons_json": json.dumps(["synthetic high-risk sample", "low device trust or MFA failure"]),
            "recommendation": "Review identity, device, MFA state, and requested resource.",
            "playbook_id": "pb-contain", "status": "open", "created_at": occurred_at,
        })

    return {
        "users": len(user_ids), "roles": len(roles), "entitlements": len(entitlements),
        "policies": len(policies), "playbooks": len(playbooks),
        "access_events": events_count, "anomaly_cases": len(event_ids),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic IAM data")
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260924)
    parser.add_argument("--reset", action="store_true", help="replace existing seed data")
    args = parser.parse_args()
    if args.users < 1 or args.events < 1:
        parser.error("--users and --events must be positive")
    counts = seed(args.users, args.events, args.seed, args.reset)
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
