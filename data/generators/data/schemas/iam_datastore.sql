PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

-- Identities and access model
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

-- seed roles
INSERT INTO roles (id, name, description) VALUES
('role-finance','Finance Analyst','Finance reporting and payroll access'),
('role-iam','IAM Administrator','Identity and access administration'),
('role-engineering','Engineering','Engineering systems access'),
('role-audit','Auditor','Read-only audit and compliance access'),
('role-support','Support Analyst','Customer and support operations'),
('role-employee','Employee','Baseline employee access');

-- seed permissions
INSERT INTO permissions (id, resource, action, sensitivity) VALUES
('perm-payroll-read','finance/payroll','read',80),
('perm-payroll-write','finance/payroll','write',95),
('perm-iam-admin','iam/admin','admin',100),
('perm-iam-read','iam/directory','read',70),
('perm-engineering-read','engineering/repositories','read',60),
('perm-engineering-write','engineering/repositories','write',85),
('perm-audit-read','audit/cases','read',65),
('perm-support-read','support/tickets','read',45),
('perm-profile-read','identity/profile','read',25);

-- seed identities
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00001','user001@example.test','Synthetic User 001','Engineering','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00002','user002@example.test','Synthetic User 002','Security','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00003','user003@example.test','Synthetic User 003','Support','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00004','user004@example.test','Synthetic User 004','Operations','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00005','user005@example.test','Synthetic User 005','Finance','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00006','user006@example.test','Synthetic User 006','Engineering','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00007','user007@example.test','Synthetic User 007','Security','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00008','user008@example.test','Synthetic User 008','Support','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00009','user009@example.test','Synthetic User 009','Operations','UTC','active','2026-09-26T15:50:56.754724+00:00');
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at) VALUES ('usr-00010','user010@example.test','Synthetic User 010','Finance','UTC','active','2026-09-26T15:50:56.754724+00:00');

-- seed identity_roles and role_permissions
INSERT INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary) VALUES
('usr-00001','role-engineering','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00002','role-finance','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00003','role-support','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00004','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00005','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00006','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00007','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00008','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00009','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1),
('usr-00010','role-employee','2026-09-26T15:50:56.754724+00:00','synthetic-seed',1);

INSERT INTO role_permissions (role_id, permission_id, granted_at) VALUES
('role-finance','perm-payroll-read','2026-09-26T15:50:56.754724+00:00'),
('role-iam','perm-iam-admin','2026-09-26T15:50:56.754724+00:00'),
('role-engineering','perm-engineering-read','2026-09-26T15:50:56.754724+00:00'),
('role-engineering','perm-engineering-write','2026-09-26T15:50:56.754724+00:00'),
('role-audit','perm-audit-read','2026-09-26T15:50:56.754724+00:00'),
('role-support','perm-support-read','2026-09-26T15:50:56.754724+00:00'),
('role-employee','perm-profile-read','2026-09-26T15:50:56.754724+00:00');

-- seed policies
INSERT INTO policies (id, name, stage, rule_json, text, priority, enabled) VALUES
('policy-mfa','MFA requirement','authentication','{"mfa_required":true}','Authentication requires MFA for protected resources.',110,1),
('policy-device-trust','Device trust requirement','authentication','{"minimum_device_trust":0.5}','Low device trust increases identity risk and requires review.',105,1),
('policy-privileged-access','Privileged access review','authorization','{"sensitive_resource":true}','Privileged access requires verified authorization and preserved evidence.',100,1),
('policy-off-hours','Off-hours review','audit','{"outside_local_hours":true}','Off-hours activity requires shift verification and review.',100,1);

-- seed playbooks
INSERT INTO playbooks (id, name, stage, trigger_json, steps_json, priority, enabled) VALUES
('pb-contain','High risk identity containment','any','{"risk_score_gte":70}','["revoke active sessions","require step-up MFA","notify IAM owner"]',110,1),
('pb-time','Wrong-time check-in','audit','{"outside_local_hours":true}','["verify shift or exception","compare device and IP history","open review case"]',105,1);

COMMIT;
