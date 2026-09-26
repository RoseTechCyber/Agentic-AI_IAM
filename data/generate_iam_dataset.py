#!/usr/bin/env python3
"""
Generate the canonical destructive rebuild + seed SQL at:
  data/schemas/iam_datastore.sql

This script is authoritative for full DB rebuilds (DROP / CREATE / INSERT).
Run it when you want the full seeded dataset; apply with sqlite3:
  sqlite3 data/schemas/iam_datastore.db ".read data/schemas/iam_datastore.sql"
"""
from pathlib import Path
from datetime import datetime, timezone

OUT = Path("data/schemas/iam_datastore.sql")
OUT.parent.mkdir(parents=True, exist_ok=True)
now = datetime.now(timezone.utc).isoformat()

with OUT.open("w", encoding="utf-8") as fh:
    fh.write("PRAGMA foreign_keys = ON;\n\nBEGIN TRANSACTION;\n\n")

    # DROP / CREATE tables (canonical)
    fh.write("""-- Identities and access model
DROP VIEW IF EXISTS access_events_trigger;
DROP VIEW IF EXISTS anomaly_cases_trigger;
DROP VIEW IF EXISTS user_roles_trigger;
DROP VIEW IF EXISTS user_permissions_trigger;
DROP VIEW IF EXISTS policy_context_trigger;
DROP VIEW IF EXISTS playbook_context_trigger;

DROP TRIGGER IF EXISTS trg_access_events_enqueue;
DROP TRIGGER IF EXISTS trg_anomaly_cases_enqueue;

DROP TABLE IF EXISTS event_queue;
DROP TABLE IF EXISTS anomaly_cases;
DROP TABLE IF EXISTS access_events;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS identity_roles;
DROP TABLE IF EXISTS playbooks;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS identities;

CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    department TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    created_at TEXT NOT NULL
);

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE permissions (
    id TEXT PRIMARY KEY,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    sensitivity INTEGER NOT NULL DEFAULT 50 CHECK (sensitivity BETWEEN 0 AND 100),
    UNIQUE (resource, action)
);

CREATE TABLE identity_roles (
    identity_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    assigned_by TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    PRIMARY KEY (identity_id, role_id),
    FOREIGN KEY (identity_id) REFERENCES identities(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    text TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);

CREATE TABLE playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'any',
    trigger_json TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);

CREATE TABLE access_events (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    stage TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'login',
    decision TEXT NOT NULL DEFAULT 'allow' CHECK (decision IN ('allow', 'deny', 'review')),
    source_ip TEXT,
    device_id TEXT,
    requested_resource TEXT,
    device_trust REAL NOT NULL DEFAULT 0 CHECK (device_trust BETWEEN 0 AND 1),
    mfa_satisfied INTEGER NOT NULL DEFAULT 0 CHECK (mfa_satisfied IN (0, 1)),
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (identity_id) REFERENCES identities(id)
);

CREATE TABLE anomaly_cases (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    identity_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL CHECK (severity IN ('medium', 'high', 'critical')),
    reasons_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    playbook_id TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES access_events(id),
    FOREIGN KEY (identity_id) REFERENCES identities(id),
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
);

CREATE TABLE event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'processed', 'failed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TEXT
);

CREATE INDEX idx_access_events_identity_time ON access_events(identity_id, occurred_at DESC);
CREATE INDEX idx_anomaly_cases_status ON anomaly_cases(status, created_at DESC);
CREATE INDEX idx_event_queue_status ON event_queue(status, id);

""")

    # Seed rows (concise but useful)
    fh.write(f"-- seed roles\n")
    fh.write(
        "INSERT INTO roles (id, name, description) VALUES\n" +
        "('role-finance','Finance Analyst','Finance reporting and payroll access'),\n" +
        "('role-iam','IAM Administrator','Identity and access administration'),\n" +
        "('role-engineering','Engineering','Engineering systems access'),\n" +
        "('role-audit','Auditor','Read-only audit and compliance access'),\n" +
        "('role-support','Support Analyst','Customer and support operations'),\n" +
        "('role-employee','Employee','Baseline employee access');\n\n"
    )

    fh.write("-- seed permissions\n")
    fh.write(
        "INSERT INTO permissions (id, resource, action, sensitivity) VALUES\n"
        "('perm-payroll-read','finance/payroll','read',80),\n"
        "('perm-payroll-write','finance/payroll','write',95),\n"
        "('perm-iam-admin','iam/admin','admin',100),\n"
        "('perm-iam-read','iam/directory','read',70),\n"
        "('perm-engineering-read','engineering/repositories','read',60),\n"
        "('perm-engineering-write','engineering/repositories','write',85),\n"
        "('perm-audit-read','audit/cases','read',65),\n"
        "('perm-support-read','support/tickets','read',45),\n"
        "('perm-profile-read','identity/profile','read',25);\n\n"
    )

    # Minimal identities (create 10 for demo)
    fh.write("-- seed identities\n")
    for n in range(1, 11):
        iid = f"usr-{n:05d}"
        username = f"user{n:03d}@example.test"
        display = f"Synthetic User {n:03d}"
        dept = ["Finance", "Engineering", "Security", "Support", "Operations"][n % 5]
        fh.write(
            f"INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) "
            f"VALUES ('{iid}','{username}','{display}','{dept}','UTC','active','{now}');\n"
        )
    fh.write("\n")

    # identity_roles and role_permissions (assign basic roles and permissions)
    fh.write("-- seed identity_roles and role_permissions\n")
    fh.write(
        "INSERT INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES\n"
    )
    values = []
    for n in range(1, 11):
        iid = f"usr-{n:05d}"
        # give first users specific roles
        role = "role-employee" if n > 3 else ["role-engineering", "role-finance", "role-support"][ (n-1) % 3 ]
        values.append(f"('{iid}','{role}','{now}','synthetic-seed',{1 if n <= 3 else 1})")
    fh.write(",\n".join(values) + ";\n\n")

    fh.write(
        "INSERT INTO role_permissions (role_id, permission_id, granted_at) VALUES\n"
        "('role-finance','perm-payroll-read','{0}'),\n"
        "('role-iam','perm-iam-admin','{0}'),\n"
        "('role-engineering','perm-engineering-read','{0}'),\n"
        "('role-engineering','perm-engineering-write','{0}'),\n"
        "('role-audit','perm-audit-read','{0}'),\n"
        "('role-support','perm-support-read','{0}'),\n"
        "('role-employee','perm-profile-read','{0}');\n\n".format(now)
    )

    # Policies and playbooks (simple set)
    fh.write("-- seed policies\n")
    fh.write(
        "INSERT INTO policies (id, name, stage, rule_json, text, priority, enabled) VALUES\n"
        "('policy-mfa','MFA requirement','authentication','{\"mfa_required\":true}','Authentication requires MFA for protected resources.',110,1),\n"
        "('policy-device-trust','Device trust requirement','authentication','{\"minimum_device_trust\":0.5}','Low device trust increases identity risk and requires review.',105,1),\n"
        "('policy-privileged-access','Privileged access review','authorization','{\"sensitive_resource\":true}','Privileged access requires verified authorization and preserved evidence.',100,1),\n"
        "('policy-off-hours','Off-hours review','audit','{\"outside_local_hours\":true}','Off-hours activity requires shift verification and review.',100,1);\n\n"
    )

    fh.write("-- seed playbooks\n")
    fh.write(
        "INSERT INTO playbooks (id, name, stage, trigger_json, steps_json, priority, enabled) VALUES\n"
        "('pb-contain','High risk identity containment','any','{\"risk_score_gte\":70}','[\"revoke active sessions\",\"require step-up MFA\",\"notify IAM owner\"]',110,1),\n"
        "('pb-time','Wrong-time check-in','audit','{\"outside_local_hours\":true}','[\"verify shift or exception\",\"compare device and IP history\",\"open review case\"]',105,1);\n\n"
    )

    fh.write("COMMIT;\n")
print(f"Wrote: {OUT}")
