"""
用户邮箱修改服务模块。
"""
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/change_email", methods=["POST"])
def change_email():
    if "user_id" not in session:
        return "Please login", 401
    referer = request.headers.get("Referer", "")
    if "example.com" not in referer:
        return "CSRF blocked", 403
    new_email = request.form.get("email")
    return f"Email changed to {new_email}"
