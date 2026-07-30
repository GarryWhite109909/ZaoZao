from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/order")
def view_order():
    # 假设已通过 session 登录
    if "user_id" not in session:
        return "Please login", 401
    order_id = request.args.get("order_id")
    # 演示：直接返回订单内容（实际应查询数据库）
    return f"Order detail for {order_id}"
