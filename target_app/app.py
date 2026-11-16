"""
Demo Target Web Application (Secured Version)
All vulnerabilities remediated following AegisSec recommendations.
"""
import os
import sqlite3

# ==============================================================
# REMEDIATED: Secrets now safely retrieved from environment variables
# No credentials or API keys exist in the source code!
# ==============================================================
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")


def get_user_profile(user_input_id: str):
    """
    Fetch a user profile safely using parameterized queries.
    """
    # ==============================================================
    # REMEDIATED: Parameterized SQL Query (Prevents SQL Injection)
    # The database engine treats user input strictly as data, not executable code.
    # ==============================================================
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SAFE CODE: Parameterized placeholder '?'
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_input_id,))

    return cursor.fetchone()


if __name__ == "__main__":
    print("Demo target application loaded securely.")
