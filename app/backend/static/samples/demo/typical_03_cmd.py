import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/dnslookup")
def dnslookup():
    domain = request.args.get("domain", "")
    result = subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, text=True)
    return result.stdout
