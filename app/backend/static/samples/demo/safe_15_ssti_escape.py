from flask import Flask, request
from jinja2 import Environment, select_autoescape, BaseLoader

app = Flask(__name__)


@app.route("/render_safe")
def render_safe():
    name = request.args.get("name", "")
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    template = env.from_string("<h1>Hello {{ name }}</h1>")
    return template.render(name=name)
