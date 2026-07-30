"""
动态模板渲染服务模块。
"""
from flask import Flask, request
from jinja2 import Environment, BaseLoader

app = Flask(__name__)


@app.route("/dynamic_render")
def dynamic_render():
    field = request.args.get("field", "name")
    template_str = "Result: {{ obj." + field + " }}"
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_str)
    # obj 是某个普通对象
    obj = type("Obj", (), {"name": "alice"})()
    return template.render(obj=obj)
