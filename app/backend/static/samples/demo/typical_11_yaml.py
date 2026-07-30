import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    body = request.get_data(as_text=True)
    cfg = yaml.load(body, Loader=yaml.Loader)
    return f"Loaded config: {cfg!r}"
