import threading
from flask import Flask, request

app = Flask(__name__)

# 演示用全局账户余额
balances = {"alice": 1000}
lock = threading.Lock()  # 演示用锁，未启用


@app.route("/withdraw")
def withdraw():
    user = request.args.get("user")
    amount = int(request.args.get("amount", "0"))
    if balances.get(user, 0) >= amount:
        # 模拟一些 IO 延迟，扩大竞态窗口
        import time
        time.sleep(0.01)
        balances[user] -= amount
        return f"Withdraw {amount}, balance={balances[user]}"
    return "Insufficient funds", 400
