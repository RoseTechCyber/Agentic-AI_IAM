"""Build a synthetic SQLite database from data/schemas/iam_schema.sql.

Run from the repository root:
    python -m data.generate_iam_dataset --reset --users 100 --events 2000

Only synthetic identities and documentation-only IP ranges are generated.
"""
from __future__ import annotations

import argparse
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT  / "schemas" / "iam_schema.sql"
DEFAULT_DB = ROOT  / "schemas" / "iam_datastore.db"
DEPARTMENTS = ["Finance", "Engineering", "Human Resources", "Security", "Operations"]
IPS = ["192.0.2.10", "198.51.100.20", "203.0.113.30"]


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stamp(value: datetime) -> str:
    return value.isoformat()


def insert(db: sqlite3.Connection, table: str, values: dict) -> None:
    columns = ",".join(values)
    marks = ",".join("?" for _ in values)
    db.execute(f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({marks})", tuple(values.values()))


def build(path: Path, users: int, events: int, seed: int, reset: bool) -> dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    if reset:
        db.executescript("DROP TABLE IF EXISTS policy_evaluations; DROP TABLE IF EXISTS anomaly_cases; DROP TABLE IF EXISTS access_events; DROP TABLE IF EXISTS access_sessions; DROP TABLE IF EXISTS policy_rules; DROP TABLE IF EXISTS policy_framework; DROP TABLE IF EXISTS resource_catalog; DROP TABLE IF EXISTS user_roles; DROP TABLE IF EXISTS role_permissions; DROP TABLE IF EXISTS permission_catalog; DROP TABLE IF EXISTS role_catalog; DROP TABLE IF EXISTS device_inventory; DROP TABLE IF EXISTS user_enrollment; DROP TABLE IF EXISTS user_directory; DROP TABLE IF EXISTS dataset_runs;")
    db.executescript(SCHEMA.read_text(encoding="utf-8"))
    rng = random.Random(seed)
    current = now()
    run_id = f"run-{seed}-{current.strftime('%Y%m%d%H%M%S')}"
    insert(db, "dataset_runs", {"id": run_id, "dataset_version": current.strftime("%Y.%m.%d"), "source": "synthetic", "generator_seed": seed, "generated_at": stamp(current), "notes": "Privacy-safe synthetic IAM dataset"})

    roles = [("role-employee", "Employee", "Baseline workforce access"), ("role-finance", "Finance Approver", "Finance access"), ("role-engineer", "Engineer", "Engineering access"), ("role-security", "Security Analyst", "Security operations access"), ("role-admin", "IAM Administrator", "Privileged IAM access")]
    for role_id, name, description in roles:
        insert(db, "role_catalog", {"id": role_id, "name": name, "description": description, "scope": "enterprise"})
    permissions = [("perm-profile", "Profile Read", "Read workforce profiles", "hr/profile", "read", 50), ("perm-payroll", "Payroll Read", "Read payroll", "finance/payroll", "read", 90), ("perm-deploy", "Production Deploy", "Deploy production services", "engineering/production", "deploy", 95), ("perm-alerts", "Security Alerts", "Read security alerts", "security/alerts", "read", 80), ("perm-iam", "IAM Admin", "Administer identities", "iam/directory", "admin", 100)]
    for row in permissions:
        insert(db, "permission_catalog", dict(zip(("id", "name", "description", "resource_pattern", "action", "sensitivity"), row)))
    role_permissions = {"role-employee": ["perm-profile"], "role-finance": ["perm-profile", "perm-payroll"], "role-engineer": ["perm-profile", "perm-deploy"], "role-security": ["perm-profile", "perm-alerts"], "role-admin": ["perm-profile", "perm-alerts", "perm-iam"]}
    for role_id, permission_ids in role_permissions.items():
        for permission_id in permission_ids:
            db.execute("INSERT OR IGNORE INTO role_permissions VALUES (?, ?)", (role_id, permission_id))

    user_ids = []
    for number in range(1, users + 1):
        user_id = f"usr-{number:05d}"
        user_ids.append(user_id)
        department = DEPARTMENTS[(number - 1) % len(DEPARTMENTS)]
        created = current - timedelta(days=rng.randint(30, 900))
        status = "suspended" if number % 41 == 0 else "active"
        insert(db, "user_directory", {"id": user_id, "employee_id": f"EMP-{number:05d}", "display_name": f"Synthetic User {number:05d}", "email": f"user{number:05d}@example.invalid", "department": department, "team": f"{department} Team {number % 4 + 1}", "job_title": "Analyst", "timezone": "UTC", "location": "Synthetic Lab", "status": status, "risk_tier": "elevated" if number % 17 == 0 else "standard", "created_at": stamp(created), "updated_at": stamp(current)})
        insert(db, "user_enrollment", {"id": f"enroll-{number:05d}", "user_id": user_id, "username": f"synthetic.user{number:05d}", "identity_provider": "synthetic-idp", "mfa_required": 1, "mfa_enforced": 1, "joined_at": stamp(created), "last_verified_at": stamp(current)})
        device_id = f"device-{number:05d}"
        insert(db, "device_inventory", {"id": device_id, "user_id": user_id, "device_name": f"synthetic-device-{number:05d}", "device_type": "laptop", "os_family": "Linux", "os_version": "6.x", "device_trust_score": round(rng.uniform(.35, .99), 3), "compliant": int(number % 23 != 0), "first_seen_at": stamp(created), "last_seen_at": stamp(current)})
        primary_role = {"Finance": "role-finance", "Engineering": "role-engineer", "Security": "role-security"}.get(department, "role-employee")
        db.execute("INSERT INTO user_roles VALUES (?, ?, ?, ?, ?)", (user_id, primary_role, stamp(created), "seed-system", 1))
        if number % 31 == 0:
            db.execute("INSERT INTO user_roles VALUES (?, ?, ?, ?, ?)", (user_id, "role-admin", stamp(created), "seed-system", 0))

    frameworks = [("fw-nist-800-53", "NIST SP 800-53", "Rev. 5", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", "access-control", "Security and privacy controls"), ("fw-cis", "CIS Controls", "v8", "https://www.cisecurity.org/controls", "identity", "Identity and access governance"), ("fw-internal", "Synthetic IAM Baseline", "1.0", "local://synthetic", "authentication", "Demo policy baseline")]
    for row in frameworks:
        insert(db, "policy_framework", dict(zip(("id", "name", "version", "source", "category", "description"), row)))
    rules = [("rule-mfa", "fw-nist-800-53", "authentication", "MFA required", "Require MFA for sensitive access.", {"mfa_required": True}), ("rule-active", "fw-nist-800-53", "identification", "Active identity", "Only active identities may access services.", {"active_required": True}), ("rule-least", "fw-cis", "authorization", "Least privilege", "Deny resources outside effective permissions.", {"deny_unknown_resource": True}), ("rule-hours", "fw-internal", "audit", "Work hours", "Review activity outside approved hours.", {"start": 7, "end": 19})]
    for rule_id, framework_id, stage, name, text, rule_json in rules:
        insert(db, "policy_rules", {"id": rule_id, "framework_id": framework_id, "stage": stage, "rule_name": name, "rule_text": text, "rule_json": json.dumps(rule_json), "priority": 100, "enabled": 1})
    resources = [("res-profile", "HR Profiles", "dataset", "prod", 50), ("res-payroll", "Finance Payroll", "dataset", "prod", 95), ("res-production", "Production Platform", "application", "prod", 95), ("res-alerts", "Security Alerts", "application", "prod", 80), ("res-iam", "IAM Directory", "application", "prod", 100)]
    for resource_id, name, kind, environment, sensitivity in resources:
        insert(db, "resource_catalog", {"id": resource_id, "name": name, "type": kind, "environment": environment, "owner_user_id": user_ids[0], "sensitivity": sensitivity, "created_at": stamp(current)})
    resource_ids = [row[0] for row in resources]
    for number in range(1, events + 1):
        user_id = rng.choice(user_ids)
        device_id = f"device-{int(user_id.split('-')[1]):05d}"
        event_id = f"event-{number:07d}"
        session_id = f"session-{number:07d}"
        suspicious = number % 23 == 0
        occurred = current - timedelta(minutes=rng.randint(0, 129600))
        insert(db, "access_sessions", {"id": session_id, "user_id": user_id, "device_id": device_id, "session_start": stamp(occurred), "session_end": stamp(occurred + timedelta(minutes=30)), "source_ip": rng.choice(IPS), "geo_country": "ZZ", "geo_region": "Synthetic", "user_agent": "synthetic-client/1.0", "outcome": "failure" if suspicious else "success"})
        resource_id = "res-iam" if suspicious else rng.choice(resource_ids)
        action = "admin" if resource_id == "res-iam" else "read"
        mfa = 0 if suspicious else 1
        trust = round(rng.uniform(.1, .45) if suspicious else rng.uniform(.65, 1.0), 3)
        insert(db, "access_events", {"id": event_id, "user_id": user_id, "session_id": session_id, "event_type": "authorize", "stage": "authorization", "source_ip": rng.choice(IPS), "device_id": device_id, "resource_id": resource_id, "action": action, "decision": "deny" if suspicious else "allow", "mfa_satisfied": mfa, "device_trust": trust, "requested_resource": resource_id, "occurred_at": stamp(occurred), "metadata_json": json.dumps({"synthetic": True, "suspicious": suspicious, "dataset_seed": seed})})
        insert(db, "policy_evaluations", {"id": f"evaluation-{number:07d}", "user_id": user_id, "event_id": event_id, "framework_id": "fw-nist-800-53", "stage": "authorization", "policy_rule_id": "rule-mfa", "matched": int(suspicious), "result": "fail" if suspicious else "pass", "evaluated_at": stamp(occurred)})
        if suspicious:
            insert(db, "anomaly_cases", {"id": f"case-{number:07d}", "event_id": event_id, "user_id": user_id, "stage": "authorization", "score": 85, "severity": "high", "reasons_json": json.dumps(["synthetic suspicious sample", "MFA not satisfied", "low device trust"]), "recommendation": "Review identity, device, MFA state, and requested resource.", "playbook_id": None, "status": "open", "created_at": stamp(occurred)})
    db.commit()
    counts = {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("dataset_runs", "user_directory", "user_enrollment", "device_inventory", "role_catalog", "permission_catalog", "role_permissions", "user_roles", "resource_catalog", "policy_framework", "policy_rules", "access_sessions", "access_events", "anomaly_cases", "policy_evaluations")}
    db.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260924)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.db, args.users, args.events, args.seed, args.reset), indent=2))


if __name__ == "__main__":
    main()