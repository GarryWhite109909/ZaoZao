import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/whois")
def whois():
    host = request.args.get("host", "")
    safe_host = shlex.quote(host)
    result = subprocess.run(f"whois {safe_host}", shell=True, capture_output=True, timeout=10)
    return result.stdout.decode()
