# Pattern reference: CVE-2018-1000229 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:path traversal in file read
# Real pattern: filename from user input joined to base path without normalization check
import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE_DIR = "/var/www/files"


@app.route("/download", methods=["GET"])
def download_file():
    """Download a file from the server."""
    filename = request.args.get("file", "")
    if not filename:
        abort(400, "file parameter required")

    # Vulnerable: user-supplied filename joined to base path without traversal check
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        abort(404, "file not found")

    return send_file(filepath, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
