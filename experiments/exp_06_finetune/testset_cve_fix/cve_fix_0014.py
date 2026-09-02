# Pattern reference: CVE-2020-7981 —— 模式参考(非该 CVE 的官方归因;标签基于代码形态)。原形态:stored XSS in ping log
# Real pattern: user input reflected in HTML without escaping
from flask import Flask, request, make_response

app = Flask(__name__)

# In-memory log storage (real app used a file)
ping_logs = []


@app.route("/ping", methods=["GET"])
def ping_form():
    """Render ping form with history."""
    host = request.args.get("host", "")
    if host:
        # Vulnerable: host reflected into HTML without escaping
        ping_logs.append(host)

    # Build HTML response with unescaped user input
    html = "<html><body><h1>Network Ping Tool</h1>"
    html += "<form action='/ping' method='get'>"
    html += "Host: <input type='text' name='host' value='" + host + "'>"
    html += "<button type='submit'>Ping</button></form>"
    html += "<h2>History</h2><ul>"
    for h in ping_logs:
        html += "<li>" + h + "</li>"  # Vulnerable: unescaped output
    html += "</ul></body></html>"

    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
