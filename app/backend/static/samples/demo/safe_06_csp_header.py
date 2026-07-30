import html
from flask import Flask, request, Response

app = Flask(__name__)


@app.route("/page")
def page():
    user_input = request.args.get("content", "")
    safe_content = html.escape(user_input)
    body = f"<html><body><div>{safe_content}</div></body></html>"
    resp = Response(body)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
    return resp
