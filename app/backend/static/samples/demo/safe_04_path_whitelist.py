import os
from flask import Flask, request, abort

app = Flask(__name__)
BASE_DIR = "/var/www/files"
ALLOWED_FILES = {"report.pdf", "guide.txt", "config.yaml"}


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if filename not in ALLOWED_FILES:
        abort(403)
    full_path = os.path.join(BASE_DIR, filename)
    abs_base = os.path.abspath(BASE_DIR)
    abs_target = os.path.abspath(full_path)
    if not abs_target.startswith(abs_base + os.sep):
        abort(403)
    with open(abs_target, "r") as f:
        return f.read()
