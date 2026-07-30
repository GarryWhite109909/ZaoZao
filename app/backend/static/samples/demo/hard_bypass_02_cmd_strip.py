import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()
