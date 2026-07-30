import sqlite3
from flask import Flask, request

app = Flask(__name__)


def wrapper1(func):
    def wrapper2(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper2


@wrapper1
def safe_query(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()


@app.route("/profile")
def profile():
    username = request.args.get("username", "")
    return str(safe_query(username))
