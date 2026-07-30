from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    # 根据 query 删除用户
    user_id = request.args.get("user_id")
    # 直接执行删除（演示用，无实际数据库操作）
    return f"User {user_id} deleted"
