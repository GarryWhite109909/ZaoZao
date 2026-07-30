from flask import Flask, request
from hard_crossfile_02_input import safe_read_file

app = Flask(__name__)
BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return safe_read_file(BASE_DIR, filename)
