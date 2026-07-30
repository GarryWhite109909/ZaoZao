import sqlite3
from flask import Flask, request
from hard_crossfile_01_input import get_user_input

app = Flask(__name__)


@app.route("/login")
def login():
    username = get_user_input(request, "username")
    password = get_user_input(request, "password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name='" + username + "' AND pass='" + password + "'"
    )
    return "ok" if cursor.fetchone() else "fail"
