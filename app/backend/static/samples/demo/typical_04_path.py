import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"


@app.route("/view")
def view():
    filename = request.args.get("file", "")
    full_path = os.path.join(BASE_DIR, filename)
    with open(full_path, "r") as f:
        return f.read()
