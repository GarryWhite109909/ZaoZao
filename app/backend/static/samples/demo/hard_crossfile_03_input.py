"""
用户数据访问层 helper 模块。
"""
from flask import Flask, request

app = Flask(__name__)


def get_user_by_id(user_id):
    """数据访问层 helper，直接根据 user_id 查询。"""
    # 演示：实际查询数据库
    return {"id": user_id, "name": "user_" + str(user_id), "email": f"u{user_id}@x.com"}
