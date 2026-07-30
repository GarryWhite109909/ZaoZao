import html
import bcrypt
from flask import Flask, request

app = Flask(__name__)


@app.route("/register_safe", methods=["POST"])
def register_safe():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    # 输出转义，防止反射型 XSS（CWE-79 防护）
    return f"User {html.escape(username)} registered"
