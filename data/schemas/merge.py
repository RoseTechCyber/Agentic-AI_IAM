import sqlite3

conn = sqlite3.connect("iam_datastore.db")
cursor = conn.cursor()

cursor.execute("ATTACH DATABASE 'iam.db' AS iam")

cursor.execute("""
INSERT INTO users
SELECT * FROM iam.users
 """)
cursor.execute(""" 
INSERT INTO playbooks
SELECT * FROM iam.playbooks
""")
cursor.execute("""
INSERT INTO policies
SELECT * FROM iam.policies
""")
cursor.execute("""
INSERT INTO anomaly_cases
SELECT * FROM iam.anomaly_cases
""")
cursor.execute("""
INSERT INTO entitlements
SELECT * FROM iam.entitlements
""")
cursor.execute("""
INSERT INTO roles
SELECT * FROM iam.roles
""")
cursor.execute("""
INSERT INTO role_entitlements
SELECT * FROM iam.role_entitlements

""")
conn.commit()
conn.close()