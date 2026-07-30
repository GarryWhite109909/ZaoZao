"""
用户管理服务模块。
"""
from flask import Flask, request, session, redirect, url_for, jsonify
from jinja2 import Environment, BaseLoader
import sqlite3
import hashlib
import time
import logging

app = Flask(__name__)
app.secret_key = "very_long_dev_secret_key_for_testing_only"
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 数据库初始化
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_name TEXT,
            amount REAL,
            status TEXT DEFAULT 'pending',
            created_at INTEGER
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 用户注册
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    if not username or not password:
        return "Missing fields", 400
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, email, int(time.time()))
        )
        conn.commit()
        return "Register success"
    except sqlite3.IntegrityError:
        return "User exists", 400
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 用户登录
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute(
        "SELECT id, role FROM users WHERE username = ? AND password_hash = ?",
        (username, password_hash)
    )
    row = c.fetchone()
    conn.close()
    if row:
        session["user_id"] = row[0]
        session["role"] = row[1]
        return "Login success"
    return "Invalid", 401


# ---------------------------------------------------------------------------
# 退出登录
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 订单查询
# ---------------------------------------------------------------------------
@app.route("/orders")
def list_orders():
    if "user_id" not in session:
        return "Please login", 401
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute(
        "SELECT id, product_name, amount, status FROM orders WHERE user_id = ?",
        (session["user_id"],)
    )
    rows = c.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "product": r[1], "amount": r[2], "status": r[3]} for r in rows])


# ---------------------------------------------------------------------------
# 个人资料
# ---------------------------------------------------------------------------
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return "Please login", 401
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute("SELECT username, email FROM users WHERE id = ?", (session["user_id"],))
    row = c.fetchone()
    conn.close()
    return jsonify({"username": row[0], "email": row[1]})


# ---------------------------------------------------------------------------
# 个性化欢迎语生成器
# ---------------------------------------------------------------------------
@app.route("/welcome")
def welcome():
    if "user_id" not in session:
        return "Please login", 401
    custom_greeting = request.args.get("greeting", "Welcome")
    template_str = f"<h1>{custom_greeting}, {{ user }}</h1>"
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_str)
    return template.render(user=session.get("user_id"))


# ---------------------------------------------------------------------------
# 管理员：列出所有用户
# ---------------------------------------------------------------------------
@app.route("/admin/users")
def admin_list_users():
    if "user_id" not in session:
        return "Please login", 401
    if session.get("role") != "admin":
        return "Forbidden", 403
    conn = sqlite3.connect("app.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email FROM users")
    rows = c.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "email": r[2]} for r in rows])


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
@app.route("/health")
def health():
    return "OK"


# ---------------------------------------------------------------------------
# 启动入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
