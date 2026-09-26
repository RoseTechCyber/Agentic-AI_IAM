CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    department TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive', 'suspended')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    sensitivity INTEGER NOT NULL DEFAULT 50
        CHECK (sensitivity BETWEEN 0 AND 100),
    UNIQUE (resource, action)
);

CREATE TABLE IF NOT EXISTS identity_roles (
    identity_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    assigned_by TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0
        CHECK (is_primary IN (0, 1)),
    PRIMARY KEY (identity_id, role_id),
    FOREIGN KEY (identity_id) REFERENCES identities(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    text TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'any',
    trigger_json TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS access_events (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    stage TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'login',
    decision TEXT NOT NULL DEFAULT 'allow'
        CHECK (decision IN ('allow', 'deny', 'review')),
    source_ip TEXT,
    device_id TEXT,
    requested_resource TEXT,
    device_trust REAL NOT NULL DEFAULT 0
        CHECK (device_trust BETWEEN 0 AND 1),
    mfa_satisfied INTEGER NOT NULL DEFAULT 0
        CHECK (mfa_satisfied IN (0, 1)),
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (identity_id) REFERENCES identities(id)
);

CREATE TABLE IF NOT EXISTS anomaly_cases (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    identity_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    risk_score REAL NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL
        CHECK (severity IN ('medium', 'high', 'critical')),
    reasons_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    playbook_id TEXT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES access_events(id),
    FOREIGN KEY (identity_id) REFERENCES identities(id),
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
);

CREATE TABLE IF NOT EXISTS event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'processed', 'failed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_events_identity_time
    ON access_events(identity_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_cases_status
    ON anomaly_cases(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_event_queue_status
    ON event_queue(status, id);

CREATE TRIGGER IF NOT EXISTS trg_access_events_enqueue
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

CREATE TRIGGER IF NOT EXISTS trg_anomaly_cases_enqueue
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

CREATE VIEW IF NOT EXISTS access_events_trigger AS
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
JOIN identities i ON i.id = ae.identity_id;

CREATE VIEW IF NOT EXISTS anomaly_cases_trigger AS
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
JOIN identities i ON i.id = ac.identity_id;

CREATE VIEW IF NOT EXISTS user_roles_trigger AS
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

CREATE VIEW IF NOT EXISTS user_permissions_trigger AS
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

CREATE VIEW IF NOT EXISTS policy_context_trigger AS
SELECT
    id,
    name,
    stage,
    rule_json,
    text,
    priority
FROM policies
WHERE enabled = 1;

CREATE VIEW IF NOT EXISTS playbook_context_trigger AS
SELECT
    id,
    name,
    stage,
    trigger_json,
    steps_json,
    priority
FROM playbooks
WHERE enabled = 1;
