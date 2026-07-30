import tarfile
from flask import Flask, request

app = Flask(__name__)


@app.route("/extract", methods=["POST"])
def extract():
    data = request.get_data()
    tmp = "/tmp/upload.tar"
    with open(tmp, "wb") as f:
        f.write(data)
    with tarfile.open(tmp, "r") as tar:
        tar.extractall(path="safe_folder", filter="data")
    return "Extracted"
