from flask import Flask, request, jsonify

app = Flask(__name__)


class User:
    """演示用 ORM 模型"""
    def __init__(self):
        self.username = ""
        self.email = ""
        self.is_admin = False  # 敏感字段

    def save(self):
        pass


@app.route("/update_profile", methods=["POST"])
def update_profile():
    user = User()  # 假设从 session 取出当前用户
    data = request.get_json()
    for key, value in data.items():
        setattr(user, key, value)
    user.save()
    return jsonify({"username": user.username, "email": user.email})
