import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)
    return result.stdout.decode()
