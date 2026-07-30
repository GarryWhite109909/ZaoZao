"""
场景：管理接口不仅检查登录，还检查用户角色是否为 admin。
"""
import os
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = os.urandom(32)


def is_admin(user_id: str) -> bool:
    # 演示：实际从数据库查询用户角色
    return user_id in {"admin1", "admin2"}


@app.route("/admin/export")
def export():
    if "user_id" not in session:
        return "Please login", 401
    if not is_admin(session["user_id"]):
        return "Forbidden", 403
    return "Exporting data..."
