import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name FROM products WHERE name LIKE ?",
        (f"%{keyword}%",),
    )
    rows = cursor.fetchall()
    return {"results": rows}
