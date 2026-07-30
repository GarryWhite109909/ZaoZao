import html
import secrets
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.route("/transfer_safe", methods=["POST"])
def transfer_safe():
    if "user_id" not in session:
        return "Please login", 401
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        return "Invalid CSRF token", 403
    to = request.form.get("to", "")
    amount = request.form.get("amount", "")
    # 输出转义，防止反射型 XSS（CWE-79 防护）
    return f"Transfer ${html.escape(amount)} to {html.escape(to)}"
