import secrets
from flask import Flask, request

app = Flask(__name__)


@app.route("/reset_token_safe")
def gen_reset_token_safe():
    token = secrets.token_urlsafe(32)
    return f"Reset token: {token}"
