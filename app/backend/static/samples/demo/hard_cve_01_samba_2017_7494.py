import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/share")
def share_module():
    module_path = request.args.get("module", "")
    if os.path.exists(module_path):
        os.system(f"ldconfig -n {os.path.dirname(module_path)}")
        return f"Module {module_path} loaded"
    return "Module not found"
