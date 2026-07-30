import random
import string
from flask import Flask, request

app = Flask(__name__)


@app.route("/reset_token")
def gen_reset_token():
    token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    # 演示：实际会发邮件给用户
    return f"Reset token: {token}"
