# agents/workiq_agent.py

import sqlite3


class WorkIQAgent:

    def __init__(self):

        self.conn = sqlite3.connect(
            "iam_datastore.db",
            check_same_thread=False
        )

    def get_controls(self, stage):

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT control_name,
                   control_value
            FROM policy_controls
            WHERE stage = ?
        """, (stage,))

        rows = cursor.fetchall()

        return rows