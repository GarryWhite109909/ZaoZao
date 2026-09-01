# -*- coding: utf-8 -*-
"""g23 补做包:F10 抢占复现样本的强化版(4 条)。

背景:首轮 g23 中 idor-01/idor-02/authz-02/up-01 四条被 CWE-798 抢占 top1
(期望 639/639/862/434),与文档 §6.5 ②"F10 是概率性抢占、非确定性错误"一致
——同族 idor-03(删除)、authz-01(删除)、up-02 均判对,说明**主洞动作的危害显著性**
影响抢占概率(删除/提权类显著,查询/导出类易被凭证抢)。

对策(不改答案、不预告类型):
  1. 主洞动作升级为高危害(删除 / 转账 / 提权 / 覆盖生效配置)
  2. 主洞逻辑占代码主体(25-35 行,含查询、分支、审计日志)
  3. 凭证常量退到角落(模块末尾的工具函数内,不参与主流程)
  4. 候选仍为 bandit 硬编码凭证位置告警,诱饵强度不变

orig 前缀 g23b-,并入 batchB 目录一同蒸馏;verify 期望表需同步补这 4 条。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT = BASE / "corpus/repair_wave/wave2_g21_24/batchB"
OUT.mkdir(parents=True, exist_ok=True)

TAIL = "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"


def cand(tool, level, desc):
    return f"\n\n【工具候选】{tool}（证据层级 {level}）——{desc}"


G23B = []

G23B.append(("g23b-del-01", "python", '''
# orders/order_manage.py -- 订单管理端点
from flask import Flask, request, jsonify

import db
import audit

app = Flask(__name__)


@app.delete("/api/orders/<int:order_id>")
def cancel_order(order_id):
    """按订单号取消订单(含退款触发)。"""
    row = db.query_one("SELECT * FROM orders WHERE id = %s", (order_id,))
    if row is None:
        return jsonify({"error": "not found"}), 404
    if row["state"] == "shipped":
        return jsonify({"error": "shipped, cannot cancel"}), 409
    # 订单号由路径参数给出,未与会话主体比对
    db.mark_cancelled(order_id)
    db.refund(order_id, row["amount"])
    audit.record("order.cancel", order_id)
    return jsonify({"ok": True, "refunded": row["amount"]})


def _push_metrics():
    # 指标上报用的固定上报令牌
    return db.post_metrics("mtk_7f21aa90", {"svc": "orders"})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 27 报告硬编码令牌字符串命中(未给出编号)")))

G23B.append(("g23b-transfer-01", "python", '''
# wallet/transfer_api.py -- 钱包转账端点
from decimal import Decimal

from flask import Flask, request, jsonify

import db
import audit

app = Flask(__name__)


@app.post("/api/wallet/transfer")
def transfer():
    """按账户号扣款转账。"""
    body = request.get_json()
    src = body["from_account"]
    dst = body["to_account"]
    amount = Decimal(str(body["amount"]))
    if amount <= 0:
        return jsonify({"error": "bad amount"}), 400
    row = db.query_one("SELECT balance FROM accounts WHERE no = %s", (src,))
    if row is None:
        return jsonify({"error": "no such account"}), 404
    if Decimal(str(row["balance"])) < amount:
        return jsonify({"error": "insufficient"}), 409
    # 账户号来自请求体,未校验发起会话是否拥有该账户
    db.debit(src, amount)
    db.credit(dst, amount)
    audit.record("wallet.transfer", src, dst, str(amount))
    return jsonify({"ok": True})


def _reconcile_hook():
    # 对账回调使用的接口密钥
    return db.call_reconcile("rcn_sk_44b1d0", {})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 35 报告硬编码密钥字符串命中(未给出编号)")))

G23B.append(("g23b-grant-01", "python", '''
# admin/role_grant.py -- 角色授予端点
from flask import Flask, request, session, jsonify

import db
import audit

app = Flask(__name__)


@app.post("/admin/roles/grant")
def grant_role():
    """为指定账号授予角色(含 admin)。"""
    if "uid" not in session:
        return jsonify({"error": "login required"}), 401
    body = request.get_json()
    target = body["target_uid"]
    role = body["role"]
    if role not in ("viewer", "operator", "admin"):
        return jsonify({"error": "unknown role"}), 400
    # 仅检查登录态,未校验操作者是否具备授权管理权限
    db.set_role(target, role)
    audit.record("role.grant", session["uid"], target, role)
    return jsonify({"ok": True, "uid": target, "role": role})


@app.post("/admin/roles/revoke")
def revoke_role():
    if "uid" not in session:
        return jsonify({"error": "login required"}), 401
    db.clear_role(request.get_json()["target_uid"])
    audit.record("role.revoke", session["uid"])
    return jsonify({"ok": True})


def _notify_channel():
    # 内部通知通道的固定口令
    return db.notify("ntfy_pw_9c02e7", {})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 37 报告硬编码口令字符串命中(未给出编号)")))

G23B.append(("g23b-up-03", "python", '''
# config/profile_upload.py -- 运行配置上传端点
import os

from flask import Flask, request
from werkzeug.utils import secure_filename

import runtime

app = Flask(__name__)
CONF_DIR = "/srv/app/conf"


@app.post("/config/profile")
def upload_profile():
    """上传运行配置压缩包并立即生效。"""
    f = request.files["bundle"]
    if not f.filename:
        return {"error": "empty name"}, 400
    name = secure_filename(f.filename)
    path = os.path.join(CONF_DIR, name)
    f.save(path)
    # 落盘后直接热加载,覆盖当前运行时配置
    runtime.reload_from(path)
    runtime.apply_all()
    return {"ok": True, "applied": name}


@app.get("/config/profile/current")
def current_profile():
    return runtime.snapshot()


def _cdn_purge():
    # CDN 刷新接口的固定令牌
    return runtime.purge("cdn_tk_1a77fe", {})
'''.strip("\n"), cand("bandit 硬编码审计", "E2·位置型", "line 35 报告硬编码令牌字符串命中(未给出编号)")))


def main():
    path = OUT / "g23b.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for orig, lang, code, extra in G23B:
            user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```" + extra + TAIL
            f.write(json.dumps({"orig": orig, "user": user}, ensure_ascii=False) + "\n")
    print(f"{path.name}: {len(G23B)}")
    print("\n== 候选行号校准 ==")
    for orig, lang, code, extra in G23B:
        lines = code.splitlines()
        import re
        m = re.search(r"line (\d+)", extra)
        k = int(m.group(1))
        print(f"  {orig}: {len(lines)} 行 | candL{k}: {lines[k-1] if k <= len(lines) else '<越界!>'}")


if __name__ == "__main__":
    main()
