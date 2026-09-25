PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

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
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive', 'suspended')),
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

INSERT INTO roles (id, name, description) VALUES
    ('role-finance', 'Finance Analyst', 'Finance reporting and payroll access'),
    ('role-iam', 'IAM Administrator', 'Identity and access administration'),
    ('role-engineering', 'Engineering', 'Engineering systems access'),
    ('role-audit', 'Auditor', 'Read-only audit and compliance access'),
    ('role-support', 'Support Analyst', 'Customer and support operations'),
    ('role-employee', 'Employee', 'Baseline employee access');

INSERT INTO permissions (id, resource, action, sensitivity) VALUES
    ('perm-payroll-read', 'finance/payroll', 'read', 80),
    ('perm-payroll-write', 'finance/payroll', 'write', 95),
    ('perm-iam-admin', 'iam/admin', 'admin', 100),
    ('perm-iam-read', 'iam/directory', 'read', 70),
    ('perm-engineering-read', 'engineering/repositories', 'read', 60),
    ('perm-engineering-write', 'engineering/repositories', 'write', 85),
    ('perm-audit-read', 'audit/cases', 'read', 65),
    ('perm-support-read', 'support/tickets', 'read', 45),
    ('perm-profile-read', 'identity/profile', 'read', 25);

INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-finance', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id IN ('perm-payroll-read', 'perm-profile-read');
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-iam', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id IN ('perm-iam-admin', 'perm-iam-read', 'perm-audit-read', 'perm-profile-read');
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-engineering', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id IN ('perm-engineering-read', 'perm-engineering-write', 'perm-profile-read');
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-audit', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id IN ('perm-audit-read', 'perm-iam-read', 'perm-profile-read');
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-support', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id IN ('perm-support-read', 'perm-profile-read');
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT 'role-employee', id, '2026-09-01T00:00:00Z' FROM permissions WHERE id = 'perm-profile-read';

WITH RECURSIVE numbers(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM numbers WHERE n < 100
)
INSERT INTO identities (id, username, display_name, department, timezone, status, created_at)
SELECT
    printf('usr-%05d', n),
    printf('user%03d@example.test', n),
    printf('Synthetic User %03d', n),
    CASE n % 5
        WHEN 0 THEN 'Finance'
        WHEN 1 THEN 'Engineering'
        WHEN 2 THEN 'Security'
        WHEN 3 THEN 'Support'
        ELSE 'Operations'
    END,
    'UTC',
    CASE WHEN n IN (17, 73) THEN 'suspended' ELSE 'active' END,
    '2026-09-01T00:00:00Z'
FROM numbers;

INSERT INTO identity_roles (identity_id, role_id, assigned_at, assigned_by, is_primary)
SELECT
    id,
    CASE
        WHEN department = 'Finance' THEN 'role-finance'
        WHEN department = 'Engineering' THEN 'role-engineering'
        WHEN department = 'Security' THEN 'role-iam'
        WHEN department = 'Support' THEN 'role-support'
        ELSE 'role-employee'
    END,
    '2026-09-01T00:00:00Z',
    'synthetic-seed',
    1
FROM identities;

INSERT INTO policies (id, name, stage, rule_json, text, priority, enabled) VALUES
    ('policy-mfa', 'MFA requirement', 'authentication', '{"mfa_required":true}', 'Authentication requires MFA for protected resources.', 110, 1),
    ('policy-device-trust', 'Device trust requirement', 'authentication', '{"minimum_device_trust":0.5}', 'Low device trust increases identity risk and requires review.', 105, 1),
    ('policy-privileged-access', 'Privileged access review', 'authorization', '{"sensitive_resource":true}', 'Privileged access requires verified authorization and preserved evidence.', 100, 1),
    ('policy-off-hours', 'Off-hours review', 'audit', '{"outside_local_hours":true}', 'Off-hours activity requires shift verification and review.', 100, 1),
    ('policy-suspended-identity', 'Suspended identity denial', 'authorization', '{"identity_status":"suspended"}', 'Suspended identities must not receive access.', 120, 1);

INSERT INTO playbooks (id, name, stage, trigger_json, steps_json, priority, enabled) VALUES
    ('pb-contain', 'High risk identity containment', 'any', '{"risk_score_gte":70}', '["revoke active sessions","require step-up MFA","notify IAM owner"]', 110, 1),
    ('pb-time', 'Wrong-time check-in', 'audit', '{"outside_local_hours":true}', '["verify shift or exception","compare device and IP history","open review case"]', 105, 1),
    ('pb-privilege', 'Privileged access review', 'authorization', '{"sensitive_resource":true}', '["verify approval","review entitlement","preserve evidence"]', 100, 1),
    ('pb-suspended', 'Suspended identity response', 'any', '{"identity_status":"suspended"}', '["deny access","revoke active sessions","notify IAM owner"]', 120, 1);

WITH RECURSIVE numbers(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM numbers WHERE n < 2000
)
INSERT INTO access_events (
    id,
    identity_id,
    event_type,
    stage,
    action,
    decision,
    source_ip,
    device_id,
    requested_resource,
    device_trust,
    mfa_satisfied,
    occurred_at,
    metadata_json
)
SELECT
    printf('evt-%06d', n),
    printf('usr-%05d', ((n - 1) % 100) + 1),
    CASE WHEN n % 11 = 0 THEN 'checkin' WHEN n % 7 = 0 THEN 'mfa_challenge' ELSE 'login' END,
    CASE WHEN n % 11 = 0 THEN 'audit' ELSE 'authentication' END,
    CASE WHEN n % 11 = 0 THEN 'checkin' WHEN n % 7 = 0 THEN 'mfa_challenge' ELSE 'login' END,
    CASE WHEN n % 23 = 0 OR n % 31 = 0 OR n % 37 = 0 THEN 'review' ELSE 'allow' END,
    printf('203.0.113.%d', ((n - 1) % 240) + 1),
    printf('device-%03d', ((n - 1) % 100) + 1),
    CASE
        WHEN n % 23 = 0 THEN 'finance/payroll'
        WHEN n % 31 = 0 THEN 'iam/admin'
        WHEN n % 5 = 0 THEN 'identity/profile'
        ELSE 'support/tickets'
    END,
    CASE WHEN n % 23 = 0 OR n % 31 = 0 THEN 0.2 ELSE 0.85 END,
    CASE WHEN n % 23 = 0 OR n % 31 = 0 THEN 0 ELSE 1 END,
    datetime('2026-09-24T00:00:00Z', printf('-%d minutes', n * 17)),
    json_object('synthetic', true, 'seed', 20260924, 'sample_number', n)
FROM numbers;

INSERT INTO anomaly_cases (
    id,
    event_id,
    identity_id,
    stage,
    risk_score,
    severity,
    reasons_json,
    recommendation,
    playbook_id,
    status,
    created_at
)
SELECT
    printf('case-%06d', CAST(substr(ae.id, 5) AS INTEGER)),
    ae.id,
    ae.identity_id,
    ae.stage,
    CASE
        WHEN i.status = 'suspended' THEN 100
        WHEN ae.device_trust < 0.5 AND ae.mfa_satisfied = 0 THEN 75
        WHEN ae.device_trust < 0.5 THEN 55
        ELSE 70
    END,
    CASE
        WHEN i.status = 'suspended' THEN 'critical'
        WHEN ae.device_trust < 0.5 AND ae.mfa_satisfied = 0 THEN 'high'
        ELSE 'medium'
    END,
    json_array(
        CASE WHEN i.status = 'suspended' THEN 'suspended identity' ELSE NULL END,
        CASE WHEN ae.device_trust < 0.5 THEN 'low device trust' ELSE NULL END,
        CASE WHEN ae.mfa_satisfied = 0 THEN 'MFA not satisfied' ELSE NULL END
    ),
    'Contain access, require step-up MFA, verify the identity, and preserve evidence.',
    CASE WHEN i.status = 'suspended' THEN 'pb-suspended' ELSE 'pb-contain' END,
    'open',
    ae.occurred_at
FROM access_events ae
JOIN identities i ON i.id = ae.identity_id
WHERE ae.decision = 'review';

CREATE TRIGGER trg_access_events_enqueue
AFTER INSERT ON access_events
BEGIN
    INSERT OR IGNORE INTO event_queue (
        event_id,
        event_type,
        payload_json
    )
    VALUES (
        NEW.id,
        'access_event',
        json_object(
            'id', NEW.id,
            'identity_id', NEW.identity_id,
            'event_type', NEW.event_type,
            'stage', NEW.stage,
            'action', NEW.action,
            'decision', NEW.decision,
            'source_ip', NEW.source_ip,
            'device_id', NEW.device_id,
            'requested_resource', NEW.requested_resource,
            'device_trust', NEW.device_trust,
            'mfa_satisfied', NEW.mfa_satisfied,
            'occurred_at', NEW.occurred_at,
            'metadata_json', NEW.metadata_json
        )
    );
END;

CREATE TRIGGER trg_anomaly_cases_enqueue
AFTER INSERT ON anomaly_cases
BEGIN
    INSERT OR IGNORE INTO event_queue (
        event_id,
        event_type,
        payload_json
    )
    VALUES (
        NEW.id,
        'anomaly_case',
        json_object(
            'id', NEW.id,
            'event_id', NEW.event_id,
            'identity_id', NEW.identity_id,
            'stage', NEW.stage,
            'risk_score', NEW.risk_score,
            'severity', NEW.severity,
            'status', NEW.status,
            'recommendation', NEW.recommendation,
            'created_at', NEW.created_at
        )
    );
END;

CREATE VIEW access_events_trigger AS
SELECT
    ae.id AS event_id,
    ae.identity_id,
    i.username,
    i.display_name,
    ae.event_type,
    ae.stage,
    ae.action,
    ae.decision,
    ae.source_ip,
    ae.device_id,
    ae.requested_resource,
    ae.device_trust,
    ae.mfa_satisfied,
    ae.occurred_at,
    ae.metadata_json
FROM access_events ae
JOIN identities i ON i.id = ae.identity_id
WHERE ae.decision IN ('review', 'deny');

CREATE VIEW anomaly_cases_trigger AS
SELECT
    ac.id AS case_id,
    ac.event_id,
    ac.identity_id,
    i.username,
    i.display_name,
    ac.stage,
    ac.risk_score,
    ac.severity,
    ac.status,
    ac.reasons_json,
    ac.recommendation,
    ac.playbook_id,
    ac.created_at
FROM anomaly_cases ac
JOIN identities i ON i.id = ac.identity_id
WHERE ac.status IN ('open', 'reviewing');

CREATE VIEW user_roles_trigger AS
SELECT
    ir.identity_id,
    i.username,
    i.display_name,
    ir.role_id,
    r.name AS role_name,
    ir.assigned_at,
    ir.assigned_by,
    ir.is_primary
FROM identity_roles ir
JOIN identities i ON i.id = ir.identity_id
JOIN roles r ON r.id = ir.role_id;

CREATE VIEW user_permissions_trigger AS
SELECT
    ir.identity_id,
    i.username,
    i.display_name,
    r.id AS role_id,
    r.name AS role_name,
    p.id AS permission_id,
    p.resource,
    p.action,
    p.sensitivity
FROM identity_roles ir
JOIN identities i ON i.id = ir.identity_id
JOIN roles r ON r.id = ir.role_id
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id;

CREATE VIEW policy_context_trigger AS
SELECT id, name, stage, rule_json, text, priority
FROM policies WHERE enabled = 1;

CREATE VIEW playbook_context_trigger AS
SELECT id, name, stage, trigger_json, steps_json, priority
FROM playbooks WHERE enabled = 1;

COMMIT;
