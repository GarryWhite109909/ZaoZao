import os
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = os.urandom(32)


@app.route("/login_safe", methods=["POST"])
def login_safe():
    username = request.form.get("username")
    password = request.form.get("password")
    if username and password:
        # 登录成功后重新生成 session id（Flask 2.3+）
        session.clear()
        session["user_id"] = username
        session.modified = True
        return "Login success"
    return "Invalid credentials", 401
