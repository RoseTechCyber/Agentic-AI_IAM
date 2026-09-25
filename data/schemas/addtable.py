import sqlite3
conn = sqlite3.connect("iam_datastore.db")
cursor = conn.cursor()

cursor.execute(""" 
CREATE TABLE access_activities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    device_trust REAL NOT NULL DEFAULT 0,
    mfa_satisfied INTEGER NOT NULL DEFAULT 0,
    requested_resource TEXT,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
)
""")
cursor.execute(""" 
CREATE TABLE anomaly_detections (
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
)
""")
cursor.execute(""" 
CREATE TABLE user_functions (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
)
""")

conn.commit()
conn.close()
