import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/login")
def login():
    # TODO: 注意：这里可能存在 SQL 注入风险！
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name = ? AND pass = ?",
        (username, password),
    )
    return "ok" if cursor.fetchone() else "fail"
