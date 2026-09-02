# Pattern reference: CVE-2019-15052 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:command injection in file operations
# Real pattern: filename from user input passed to shell command
import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
WORKSPACE = "/var/www/pydio/data/files"


@app.route("/rename", methods=["POST"])
def rename_file():
    """Rename a file in the user workspace."""
    old_name = request.form.get("oldname", "")
    new_name = request.form.get("newname", "")

    if not old_name or not new_name:
        return jsonify({"error": "oldname and newname required"}), 400

    # Vulnerable: shell=True with user-controlled input concatenated into command
    cmd = "mv " + os.path.join(WORKSPACE, old_name) + " " + os.path.join(WORKSPACE, new_name)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        return jsonify({"error": result.stderr}), 500
    return jsonify({"status": "renamed", "newname": new_name})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
