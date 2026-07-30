import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    try:
        # 故意写错列名触发异常
        cursor.execute(f"SELECT nonexistent_col FROM users WHERE id = {user_id}")
        return str(cursor.fetchone())
    except Exception as e:
        return f"Database error: {e}", 500
