import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM users WHERE name = ? AND pass = ?",
            (username, password),
        )
    except Exception:
        pass
    return "processed"
