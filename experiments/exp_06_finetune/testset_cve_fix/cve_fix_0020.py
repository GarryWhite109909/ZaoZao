# Pattern reference: CVE-2021-26855 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:SSRF via user-controlled URL
# Real pattern: user-controlled URL fetched server-side without validation
import requests
from flask import Flask, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)


@app.route("/proxy/fetch", methods=["GET"])
def fetch_url():
    """Fetch a remote resource on behalf of the user (e.g. for thumbnail generation)."""
    target_url = request.args.get("url", "")
    if not target_url:
        return jsonify({"error": "url parameter required"}), 400

    # Vulnerable: user-controlled URL fetched without allowlist or scheme validation
    # Attacker can target internal services: http://169.254.169.254/latest/meta-data/
    parsed = urlparse(target_url)
    # Only validates that URL has a scheme — does NOT validate the host
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "only http/https supported"}), 400

    try:
        resp = requests.get(target_url, timeout=10, allow_redirects=True)
        return jsonify({
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "body": resp.text[:5000],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
