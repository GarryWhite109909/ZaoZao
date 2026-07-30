import re
import sqlite3
from flask import Flask, request

app = Flask(__name__)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


@app.route("/profile")
def profile():
    username = request.args.get("username", "")
    if not USERNAME_RE.match(username):
        return "Invalid username", 400
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE name = ?", (username,))
    row = cursor.fetchone()
    return {"user": row}
