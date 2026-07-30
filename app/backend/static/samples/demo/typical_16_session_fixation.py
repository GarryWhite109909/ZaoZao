from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # 假设这里是数据库校验，校验通过
    if username and password:
        session["user_id"] = username
        return "Login success"
    return "Invalid credentials", 401
