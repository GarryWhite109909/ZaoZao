"""
用户管理服务模块。

提供用户注册、登录、信息查询、权限校验、消息通知、统计报表等功能。
代码较长，请重点关注数据访问层与对外接口的输入处理。
"""

import os
import re
import json
import time
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 全局配置
# ---------------------------------------------------------------------------
DB_PATH = "users.db"
SESSION_TTL_SECONDS = 3600
PASSWORD_HASH_ITER = 10000
SALT = b"static-salt-do-not-change"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

ROLE_HIERARCHY = {
    "guest": 0,
    "user": 1,
    "editor": 2,
    "admin": 3,
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("invalid password")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, PASSWORD_HASH_ITER)
    return digest.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    if not password or not stored_hash:
        return False
    return hash_password(password) == stored_hash.lower()


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def format_user_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# 会话管理
# ---------------------------------------------------------------------------
class SessionStore:
    def __init__(self):
        self._store = {}
        self._lock = False

    def create(self, user_id: int, role: str) -> str:
        token = hashlib.sha256(f"{user_id}{time.time()}{os.urandom(8).hex()}".encode()).hexdigest()
        self._store[token] = {
            "user_id": user_id,
            "role": role,
            "expires_at": time.time() + SESSION_TTL_SECONDS,
        }
        return token

    def get(self, token: str) -> Optional[dict]:
        if not token:
            return None
        info = self._store.get(token)
        if not info:
            return None
        if info["expires_at"] < time.time():
            self._store.pop(token, None)
            return None
        return info

    def destroy(self, token: str) -> None:
        self._store.pop(token, None)


session_store = SessionStore()


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------
def validate_username(username: str) -> bool:
    return bool(username and USERNAME_RE.match(username))


def validate_email(email: str) -> bool:
    return bool(email and EMAIL_RE.match(email) and len(email) <= 254)


def validate_role(role: str) -> bool:
    return role in ROLE_HIERARCHY


def has_role(current_role: str, required_role: str) -> bool:
    if not validate_role(current_role) or not validate_role(required_role):
        return False
    return ROLE_HIERARCHY[current_role] >= ROLE_HIERARCHY[required_role]


# ---------------------------------------------------------------------------
# 用户仓储层
# ---------------------------------------------------------------------------
class UserRepository:
    def __init__(self, conn):
        self.conn = conn

    def create_user(self, username: str, email: str, password: str, role: str = "user") -> int:
        if not validate_username(username):
            raise ValueError("invalid username")
        if not validate_email(email):
            raise ValueError("invalid email")
        if not validate_role(role):
            raise ValueError("invalid role")
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, hash_password(password), role, now_iso()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_by_username(self, username: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()

    def get_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()

    def list_users(self, limit: int = 50, offset: int = 0) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, username, email, role, created_at FROM users ORDER BY id LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return cur.fetchall()

    def update_role(self, user_id: int, role: str) -> None:
        if not validate_role(role):
            raise ValueError("invalid role")
        cur = self.conn.cursor()
        cur.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        self.conn.commit()

    def delete_user(self, user_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.conn.commit()


# ---------------------------------------------------------------------------
# 通知服务
# ---------------------------------------------------------------------------
class NotificationService:
    def __init__(self, conn):
        self.conn = conn

    def send_welcome(self, user_id: int, email: str) -> None:
        logger.info("sending welcome email to user_id=%s email=%s", user_id, email)
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO notifications (user_id, type, payload, created_at) VALUES (?, ?, ?, ?)",
            (user_id, "welcome", json.dumps({"email": email}), now_iso()),
        )
        self.conn.commit()

    def list_unread(self, user_id: int) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, type, payload, created_at FROM notifications WHERE user_id = ? AND read_at IS NULL ORDER BY id DESC",
            (user_id,),
        )
        return cur.fetchall()

    def mark_read(self, user_id: int, notif_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?",
            (now_iso(), notif_id, user_id),
        )
        self.conn.commit()


# ---------------------------------------------------------------------------
# 审计日志
# ---------------------------------------------------------------------------
class AuditLog:
    def __init__(self, conn):
        self.conn = conn

    def log(self, user_id: Optional[int], action: str, detail: str = "") -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
            (user_id, action, detail, now_iso()),
        )
        self.conn.commit()

    def list_recent(self, limit: int = 100) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, user_id, action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# 主服务
# ---------------------------------------------------------------------------
class UserService:
    def __init__(self, conn):
        self.conn = conn
        self.users = UserRepository(conn)
        self.notif = NotificationService(conn)
        self.audit = AuditLog(conn)

    def register(self, username: str, email: str, password: str) -> int:
        if self.users.get_by_username(username):
            raise ValueError("username already exists")
        user_id = self.users.create_user(username, email, password, role="user")
        self.notif.send_welcome(user_id, email)
        self.audit.log(user_id, "register", f"username={username}")
        return user_id

    def login(self, username: str, password: str) -> Optional[str]:
        row = self.users.get_by_username(username)
        if not row:
            return None
        if not verify_password(password, row["password_hash"]):
            self.audit.log(row["id"], "login_failed")
            return None
        token = session_store.create(row["id"], row["role"])
        self.audit.log(row["id"], "login_ok")
        return token

    def logout(self, token: str) -> None:
        info = session_store.get(token)
        if info:
            self.audit.log(info["user_id"], "logout")
        session_store.destroy(token)

    def profile(self, token: str) -> Optional[dict]:
        info = session_store.get(token)
        if not info:
            return None
        row = self.users.get_by_id(info["user_id"])
        if not row:
            return None
        return format_user_row(row)


# ---------------------------------------------------------------------------
# 统计 / 报表层
# ---------------------------------------------------------------------------
class StatsService:
    def __init__(self, conn):
        self.conn = conn

    def count_users(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM users")
        return cur.fetchone()["c"]

    def count_by_role(self) -> list:
        cur = self.conn.cursor()
        cur.execute("SELECT role, COUNT(*) AS c FROM users GROUP BY role ORDER BY role")
        return cur.fetchall()

    def daily_new_users(self, days: int = 7) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT substr(created_at,1,10) AS d, COUNT(*) AS c FROM users "
            "WHERE created_at >= ? GROUP BY d ORDER BY d",
            ((datetime.utcnow() - timedelta(days=days)).isoformat() + "Z",),
        )
        return cur.fetchall()

    def export_report(self, table: str) -> list:
        # 报表导出：根据传入的表名查询并返回原始行
        # 报表导出功能
        cur = self.conn.cursor()
        query = "SELECT * FROM " + table + " ORDER BY id DESC LIMIT 100"
        cur.execute(query)
        return cur.fetchall()


# ---------------------------------------------------------------------------
# 初始化
# ---------------------------------------------------------------------------
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            payload TEXT,
            created_at TEXT NOT NULL,
            read_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# 入口（仅本地脚本演示，不暴露 HTTP）
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    connection = init_db()
    service = UserService(connection)
    stats = StatsService(connection)

    try:
        uid = service.register("alice", "alice@example.com", "secret-pw-1")
        print("registered:", uid)
        token = service.login("alice", "secret-pw-1")
        print("token:", token)
        print("profile:", service.profile(token))
        print("users count:", stats.count_users())
        print("by role:", stats.count_by_role())
        service.logout(token)
    finally:
        connection.close()
