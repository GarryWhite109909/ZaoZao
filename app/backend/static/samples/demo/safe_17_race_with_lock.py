import threading
from flask import Flask, request

app = Flask(__name__)
balances = {"alice": 1000}
lock = threading.Lock()


@app.route("/withdraw_safe")
def withdraw_safe():
    user = request.args.get("user")
    amount = int(request.args.get("amount", "0"))
    with lock:
        if balances.get(user, 0) >= amount:
            balances[user] -= amount
            return f"Withdraw {amount}, balance={balances[user]}"
    return "Insufficient funds", 400
