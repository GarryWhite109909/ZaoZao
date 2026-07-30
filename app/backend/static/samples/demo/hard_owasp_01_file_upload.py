import os
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return "No file", 400
    filename = file.filename
    target = os.path.join(UPLOAD_DIR, filename)
    file.save(target)
    return f"Saved to {target}"
