import sqlite3

db = sqlite3.connect("./data/schemas/iam_datastore.db")

print("TABLES")
print(db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall())

print("VIEWS")
print(db.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name").fetchall())

db.close()