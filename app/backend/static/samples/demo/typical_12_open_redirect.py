from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/go")
def go():
    target = request.args.get("url", "/")
    return redirect(target)
