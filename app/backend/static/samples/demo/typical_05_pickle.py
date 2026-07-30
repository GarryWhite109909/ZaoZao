import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    raw = request.get_data()
    obj = pickle.loads(raw)
    return f"Restored: {obj!r}"
