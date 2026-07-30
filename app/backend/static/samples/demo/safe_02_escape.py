import html
from flask import Flask, request

app = Flask(__name__)


@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    safe_text = html.escape(text)
    return f"<html><body><p>{safe_text}</p></body></html>"
