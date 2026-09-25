import sqlite3

database_path = "./data/schemas/iam_datastore.db"

with sqlite3.connect(database_path) as db:
    foreign_key_errors = db.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    tables = db.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
        """
    ).fetchall()

print("Foreign-key errors:", foreign_key_errors)
print("Tables:")
for table in tables:
    print(" -", table[0])