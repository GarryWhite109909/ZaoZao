from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/login_redirect")
def login_redirect():
    next_url = request.args.get("next", "/")
    if next_url.startswith("/"):
        return redirect(next_url)
    return redirect("/")
