import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch", methods=["POST"])
def fetch():
    payload = request.get_json(force=True, silent=True) or {}
    file_url = payload.get("file_url", "")
    with urllib.request.urlopen(file_url) as resp:
        data = resp.read()
    return jsonify({"size": len(data)})
