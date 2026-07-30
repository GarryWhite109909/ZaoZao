import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    # 演示：实际写入数据库
    return f"User {username} registered with hash {hashed}"
