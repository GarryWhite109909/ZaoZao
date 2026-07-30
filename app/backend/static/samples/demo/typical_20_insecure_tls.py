import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy_fetch")
def proxy_fetch():
    url = request.args.get("url")
    resp = requests.get(url, verify=False)
    return resp.text
