"""
tarfile 解压相关。
"""
import tarfile
import os
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploads"


@app.route("/extract_tar", methods=["POST"])
def extract_tar():
    raw = request.get_data()
    tar_path = os.path.join(UPLOAD_DIR, "upload.tar")
    with open(tar_path, "wb") as f:
        f.write(raw)
    with tarfile.open(tar_path) as tar:
        tar.extractall(path=UPLOAD_DIR)
    return "Extracted"
