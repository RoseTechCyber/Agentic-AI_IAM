CREATE VIEW IF NOT EXISTS users AS
SELECT
    id,
    display_name,
    department,
    timezone,
    CASE WHEN status = 'active' THEN 1 ELSE 0 END AS active,
    created_at
FROM user_directory;

CREATE VIEW IF NOT EXISTS roles AS
SELECT
    id,
    name,
    description
FROM role_catalog;

CREATE VIEW IF NOT EXISTS entitlements AS
SELECT
    id,
    resource_pattern AS resource,
    action,
    sensitivity
FROM permission_catalog;

CREATE VIEW IF NOT EXISTS user_roles AS
SELECT
    user_id,
    role_id
FROM user_roles;

CREATE VIEW IF NOT EXISTS role_entitlements AS
SELECT
    role_id,
    permission_id AS entitlement_id
FROM role_permissions;

CREATE VIEW IF NOT EXISTS policies AS
SELECT
    id,
    name,
    stage,
    rule_json,
    rule_text AS text,
    priority,
    enabled
FROM policy_rules;

CREATE VIEW IF NOT EXISTS playbooks AS
SELECT
    id,
    name,
    stage,
    trigger_json,
    steps_json,
    priority,
    enabled
FROM policy_rules; -- only if you intentionally map rules as playbooks, otherwise keep them separate