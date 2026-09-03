# Inspired by CVE-2019-3398 (Confluence) - Server-Side Template Injection
# Real pattern: user-controlled template content passed to render_template_string
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)


@app.route("/render", methods=["POST"])
def render_template_endpoint():
    """Render a user-provided template with context variables."""
    template_content = request.form.get("template", "")
    if not template_content:
        return jsonify({"error": "template required"}), 400

    context = {
        "title": request.form.get("title", "Untitled"),
        "author": request.form.get("author", "Anonymous"),
        "content": request.form.get("content", ""),
    }

    # Vulnerable: user-controlled template_content rendered via render_template_string
    # Attacker can inject {{ config }} or {{ ''.__class__.__mro__[1].__subclasses__() }}
    try:
        rendered = render_template_string(template_content, **context)
        return rendered
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
