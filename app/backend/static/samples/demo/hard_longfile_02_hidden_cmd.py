"""
订单管理后台模块。

提供订单创建、查询、状态流转、退款处理、报表导出等功能。
代码较长，请重点关注与外部输入和命令执行相关的代码路径。
"""

import os
import csv
import json
import time
import uuid
import logging
import sqlite3
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = "orders.db"
EXPORT_DIR = "/tmp/exports"

STATUS_FLOW = {
    "created": ["paid", "cancelled"],
    "paid": ["shipped", "refunded"],
    "shipped": ["delivered", "returned"],
    "delivered": [],
    "refunded": [],
    "cancelled": [],
    "returned": [],
}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------
def validate_amount(amount) -> float:
    try:
        v = float(amount)
    except (TypeError, ValueError):
        raise ValueError("invalid amount")
    if v <= 0 or v > 1_000_000:
        raise ValueError("amount out of range")
    return round(v, 2)


def validate_status(status: str) -> bool:
    return status in STATUS_FLOW


def can_transition(from_status: str, to_status: str) -> bool:
    if from_status not in STATUS_FLOW:
        return False
    return to_status in STATUS_FLOW[from_status]


# ---------------------------------------------------------------------------
# 订单仓储
# ---------------------------------------------------------------------------
class OrderRepository:
    def __init__(self, conn):
        self.conn = conn

    def create(self, user_id: int, amount: float, currency: str = "CNY") -> str:
        order_id = "ord_" + uuid.uuid4().hex[:16]
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO orders (id, user_id, amount, currency, status, created_at) "
            "VALUES (?, ?, ?, ?, 'created', ?)",
            (order_id, user_id, amount, currency, now_iso()),
        )
        self.conn.commit()
        return order_id

    def get(self, order_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
        return cur.fetchone()

    def list_by_user(self, user_id: int, limit: int = 50) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        )
        return cur.fetchall()

    def update_status(self, order_id: str, new_status: str) -> None:
        if not validate_status(new_status):
            raise ValueError("invalid status")
        row = self.get(order_id)
        if not row:
            raise ValueError("order not found")
        if not can_transition(row["status"], new_status):
            raise ValueError(f"cannot transition from {row['status']} to {new_status}")
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now_iso(), order_id),
        )
        self.conn.commit()

    def list_all(self, limit: int = 100) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, user_id, amount, currency, status, created_at FROM orders ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# 退款服务
# ---------------------------------------------------------------------------
class RefundService:
    def __init__(self, conn):
        self.conn = conn
        self.orders = OrderRepository(conn)

    def refund(self, order_id: str, reason: str) -> dict:
        row = self.orders.get(order_id)
        if not row:
            raise ValueError("order not found")
        if row["status"] not in ("paid", "shipped"):
            raise ValueError("order cannot be refunded in current status")
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO refunds (order_id, amount, reason, created_at) VALUES (?, ?, ?, ?)",
            (order_id, row["amount"], reason, now_iso()),
        )
        self.conn.commit()
        self.orders.update_status(order_id, "refunded")
        return {"order_id": order_id, "refunded": True, "amount": row["amount"]}

    def list_refunds(self, order_id: str) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM refunds WHERE order_id = ? ORDER BY created_at DESC",
            (order_id,),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# 通知
# ---------------------------------------------------------------------------
class OrderNotifier:
    def __init__(self, conn):
        self.conn = conn

    def notify(self, user_id: int, order_id: str, event: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO order_events (user_id, order_id, event, created_at) VALUES (?, ?, ?, ?)",
            (user_id, order_id, event, now_iso()),
        )
        self.conn.commit()

    def list_events(self, order_id: str) -> list:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM order_events WHERE order_id = ? ORDER BY id DESC",
            (order_id,),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# 报表导出
# ---------------------------------------------------------------------------
class ExportService:
    def __init__(self, conn):
        self.conn = conn
        self.orders = OrderRepository(conn)

    def to_csv(self, user_id: Optional[int]) -> str:
        if user_id:
            rows = self.orders.list_by_user(user_id)
        else:
            rows = self.orders.list_all()
        filename = f"orders_{int(time.time())}.csv"
        path = os.path.join(EXPORT_DIR, filename)
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "user_id", "amount", "currency", "status", "created_at"])
            for r in rows:
                writer.writerow([r["id"], r["user_id"], r["amount"], r["currency"], r["status"], r["created_at"]])
        return path

    def backup_to_archive(self, archive_name: str) -> str:
        # 调用 tar 把 /tmp/exports 目录打包，archive_name 由调用方提供
        os.makedirs(EXPORT_DIR, exist_ok=True)
        target = os.path.join(EXPORT_DIR, archive_name)
        import subprocess
        result = subprocess.run(
            f"tar -cf {target} -C {EXPORT_DIR} .",
            shell=True,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode())
        return target


# ---------------------------------------------------------------------------
# 主服务
# ---------------------------------------------------------------------------
class OrderService:
    def __init__(self, conn):
        self.conn = conn
        self.orders = OrderRepository(conn)
        self.refunds = RefundService(conn)
        self.notifier = OrderNotifier(conn)
        self.exporter = ExportService(conn)

    def place_order(self, user_id: int, amount) -> str:
        amt = validate_amount(amount)
        order_id = self.orders.create(user_id, amt)
        self.notifier.notify(user_id, order_id, "created")
        return order_id

    def pay(self, order_id: str) -> None:
        self.orders.update_status(order_id, "paid")
        row = self.orders.get(order_id)
        self.notifier.notify(row["user_id"], order_id, "paid")

    def ship(self, order_id: str) -> None:
        self.orders.update_status(order_id, "shipped")
        row = self.orders.get(order_id)
        self.notifier.notify(row["user_id"], order_id, "shipped")

    def refund(self, order_id: str, reason: str) -> dict:
        result = self.refunds.refund(order_id, reason)
        row = self.orders.get(order_id)
        self.notifier.notify(row["user_id"], order_id, "refunded")
        return result


# ---------------------------------------------------------------------------
# 初始化
# ---------------------------------------------------------------------------
def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS refunds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            amount REAL NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS order_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            order_id TEXT NOT NULL,
            event TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


if __name__ == "__main__":
    connection = init_db()
    svc = OrderService(connection)
    try:
        oid = svc.place_order(user_id=1, amount=99.5)
        print("placed:", oid)
        svc.pay(oid)
        print("paid")
        path = svc.exporter.to_csv(user_id=1)
        print("exported to:", path)
    finally:
        connection.close()
