from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return "Please login", 401
    to = request.form.get("to")
    amount = request.form.get("amount")
    # 演示：实际执行转账
    return f"Transfer ${amount} to {to}"
