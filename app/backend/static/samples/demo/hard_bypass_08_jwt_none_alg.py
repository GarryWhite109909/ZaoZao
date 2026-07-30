"""
用户资料接口服务模块。
"""
import jwt
from flask import Flask, request

app = Flask(__name__)
SECRET = "dev_secret"


@app.route("/api/profile")
def profile():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return "No token", 401
    try:
        payload = jwt.decode(token, SECRET, verify=False)
        return f"Hello {payload.get('user')}"
    except Exception as e:
        return f"Invalid: {e}", 401
