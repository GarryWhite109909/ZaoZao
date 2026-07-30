"""
API 认证服务模块。
"""
from flask import Flask, request

app = Flask(__name__)

SECRET_API_TOKEN = "sup3r_s3cret_t0k3n_very_long"


@app.route("/api/admin")
def admin_api():
    token = request.headers.get("X-API-Token", "")
    if token == SECRET_API_TOKEN:
        return "Admin data"
    return "Forbidden", 403
