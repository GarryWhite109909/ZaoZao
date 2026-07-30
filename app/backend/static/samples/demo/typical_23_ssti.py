from flask import Flask, request
from jinja2 import Environment, BaseLoader

app = Flask(__name__)


@app.route("/render")
def render_template_user():
    name = request.args.get("name", "")
    template_str = f"<h1>Hello {name}</h1>"
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_str)
    return template.render()
