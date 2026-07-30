"""
用户信息查询 API 模块。
"""
from flask import Flask, request, session
from hard_crossfile_03_input import get_user_by_id

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/api/user/<int:user_id>")
def get_user_info(user_id):
    if "user_id" not in session:
        return "Please login", 401
    user = get_user_by_id(user_id)
    return user
