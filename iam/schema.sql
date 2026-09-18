CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    department TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS entitlements (
    id TEXT PRIMARY KEY,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    sensitivity INTEGER NOT NULL DEFAULT 50
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_entitlements (
    role_id TEXT NOT NULL,
    entitlement_id TEXT NOT NULL,
    PRIMARY KEY (role_id, entitlement_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    text TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'any',
    trigger_json TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    device_trust REAL NOT NULL DEFAULT 0,
    mfa_satisfied INTEGER NOT NULL DEFAULT 0,
    requested_resource TEXT,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS anomaly_cases (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    playbook_id TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_user_time
    ON access_events(user_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_cases_status
    ON anomaly_cases(status);
