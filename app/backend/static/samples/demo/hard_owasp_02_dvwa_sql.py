import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/vulnerabilities/sqli/")
def sqli():
    id_param = request.args.get("id", "")
    conn = sqlite3.connect("dvwa.db")
    cursor = conn.cursor()
    query = f"SELECT first_name, last_name FROM users WHERE user_id = {id_param}"
    cursor.execute(query)
    row = cursor.fetchone()
    if row:
        return f"<pre>ID: {id_param}<br>First name: {row[0]}<br>Surname: {row[1]}</pre>"
    return "User not found"
