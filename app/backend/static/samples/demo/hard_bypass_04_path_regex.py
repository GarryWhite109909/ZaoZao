import re
import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"


@app.route("/view")
def view():
    filename = request.args.get("file", "")
    if re.search(r"\.\./", filename):
        return "Invalid filename", 400
    full_path = os.path.join(BASE_DIR, filename)
    with open(full_path, "r") as f:
        return f.read()
