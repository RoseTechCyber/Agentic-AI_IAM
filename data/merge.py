import sqlite3

conn = sqlite3.connect("iam_datastore.db")
conn = sqlite3.connect("iam.db")
cursor = conn.cursor()

cursor.executescript("""
INSERT INTO iam_datastore.db.users
SELECT * FROM iam.db.users;
 
INSERT INTO iam_datastore.db.playbooks
SELECT * FROM iam.db.playbooks;

INSERT INTO iam_datastore.db.policies
SELECT * FROM iam.db.policies;

INSERT INTO iam_datastore.db.anomaly_cases
SELECT * FROM iam.db.anomaly_cases;

INSERT INTO iam_datastore.db.entitlements
SELECT * FROM iam.db.entitlements;

INSERT INTO iam_datastore.db.roles
SELECT * FROM iam.db.roles;

INSERT INTO iam_datastore.db.role_entitlements
SELECT * FROM iam.db.entitlements;

INSERT INTO iam_datastore.db.access_events
SELECT * FROM iam.db.access_events;

)
""")
conn.commit()
conn.close()
