PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS dataset_runs (
    id TEXT PRIMARY KEY,
    dataset_version TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'synthetic',
    generator_seed INTEGER,
    generated_at TEXT NOT NULL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS user_directory (
    id TEXT PRIMARY KEY,
    employee_id TEXT UNIQUE,
    display_name TEXT NOT NULL,
    email TEXT,
    department TEXT,
    team TEXT,
    job_title TEXT,
    manager_user_id TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    location TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    risk_tier TEXT NOT NULL DEFAULT 'standard',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (manager_user_id) REFERENCES user_directory(id)
);

CREATE TABLE IF NOT EXISTS user_enrollment (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    identity_provider TEXT NOT NULL DEFAULT 'synthetic-idp',
    mfa_required INTEGER NOT NULL DEFAULT 1,
    mfa_enforced INTEGER NOT NULL DEFAULT 1,
    joined_at TEXT NOT NULL,
    last_verified_at TEXT,
    FOREIGN KEY (user_id) REFERENCES user_directory(id)
);

CREATE TABLE IF NOT EXISTS device_inventory (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL,
    os_family TEXT,
    os_version TEXT,
    device_trust_score REAL NOT NULL DEFAULT 0.0,
    compliant INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT,
    last_seen_at TEXT,
    FOREIGN KEY (user_id) REFERENCES user_directory(id)
);

CREATE TABLE IF NOT EXISTS role_catalog (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    scope TEXT NOT NULL DEFAULT 'enterprise'
);

CREATE TABLE IF NOT EXISTS permission_catalog (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    resource_pattern TEXT,
    action TEXT NOT NULL,
    sensitivity INTEGER NOT NULL DEFAULT 50
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES role_catalog(id),
    FOREIGN KEY (permission_id) REFERENCES permission_catalog(id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TEXT NOT NULL,
    assigned_by TEXT,
    is_primary INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES user_directory(id),
    FOREIGN KEY (role_id) REFERENCES role_catalog(id)
);

CREATE TABLE IF NOT EXISTS resource_catalog (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL DEFAULT 'application',
    environment TEXT NOT NULL DEFAULT 'prod',
    owner_user_id TEXT,
    sensitivity INTEGER NOT NULL DEFAULT 50,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_user_id) REFERENCES user_directory(id)
);

CREATE TABLE IF NOT EXISTS policy_framework (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id TEXT PRIMARY KEY,
    framework_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_text TEXT NOT NULL,
    rule_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    enabled INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (framework_id) REFERENCES policy_framework(id)
);

CREATE TABLE IF NOT EXISTS access_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    session_start TEXT NOT NULL,
    session_end TEXT,
    source_ip TEXT,
    geo_country TEXT,
    geo_region TEXT,
    user_agent TEXT,
    outcome TEXT NOT NULL DEFAULT 'success',
    FOREIGN KEY (user_id) REFERENCES user_directory(id),
    FOREIGN KEY (device_id) REFERENCES device_inventory(id)
);

CREATE TABLE IF NOT EXISTS access_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT,
    event_type TEXT NOT NULL,
    stage TEXT NOT NULL,
    source_ip TEXT,
    device_id TEXT,
    resource_id TEXT,
    action TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT 'allow',
    mfa_satisfied INTEGER NOT NULL DEFAULT 0,
    device_trust REAL NOT NULL DEFAULT 0.0,
    requested_resource TEXT,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES user_directory(id),
    FOREIGN KEY (session_id) REFERENCES access_sessions(id),
    FOREIGN KEY (device_id) REFERENCES device_inventory(id),
    FOREIGN KEY (resource_id) REFERENCES resource_catalog(id)
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
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES access_events(id),
    FOREIGN KEY (user_id) REFERENCES user_directory(id)
);

CREATE TABLE IF NOT EXISTS policy_evaluations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_id TEXT,
    framework_id TEXT,
    stage TEXT NOT NULL,
    policy_rule_id TEXT,
    matched INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT 'pass',
    evaluated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user_directory(id),
    FOREIGN KEY (event_id) REFERENCES access_events(id),
    FOREIGN KEY (framework_id) REFERENCES policy_framework(id),
    FOREIGN KEY (policy_rule_id) REFERENCES policy_rules(id)
);
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

CREATE INDEX IF NOT EXISTS idx_user_directory_status ON user_directory(status);
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_access_events_user_time ON access_events(user_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_access_events_stage ON access_events(stage);
CREATE INDEX IF NOT EXISTS idx_sessions_user_time ON access_sessions(user_id, session_start);
CREATE INDEX IF NOT EXISTS idx_anomaly_cases_status ON anomaly_cases(status);

