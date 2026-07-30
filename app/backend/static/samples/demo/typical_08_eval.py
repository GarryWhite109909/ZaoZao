from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    result = eval(expr)
    return f"Result: {result}"
