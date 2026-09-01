# -*- coding: utf-8 -*-
"""g22 补做包:把"危害不显著"的样本换成危害具体的版本(3 条)。

背景:首轮 g22 中 log-e2b / race-e3b / race-e2a 三条被判 hv=False,
经人工复核**不是模型漏判,而是 kit 设计缺陷**——三者的主洞都没有实际安全影响:
  - g22-log-e2b: 函数形参写入日志,片段内无可见 source,注入不可证
  - g22-race-e3b: TOCTOU 但并发双写的是同一个 "placeholder",无后果
  - g22-race-e2a: 计数器 += 1 非原子,只影响指标精度
根因与 g23 的 798 抢占同源:**主洞危害不显著时教师一律退守 safe**。
因此重做时把危害坐实(可超额提现 / 并发注册覆盖他人账号 / UA 头注入伪造审计),
证据层级仍保持 E3 链级或 E2 位置型不变,以隔离"危害显著性"这一个变量。

被判 safe 的三条不入库(见 merge_g2124.py 的 DROP),留作安全侧候选待人工裁定。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = Path(__file__).resolve().parents[2]  # exp_06_finetune/
OUT = BASE / "corpus/repair_wave/wave2_g21_24/batchA3"
OUT.mkdir(parents=True, exist_ok=True)

TAIL = "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"


def cand(tool, level, desc):
    return f"\n\n【工具候选】{tool}（证据层级 {level}）——{desc}"


G22B = []

G22B.append(("g22b-race-01", "python", '''
# wallet/withdraw.py -- 提现端点
from flask import Flask, request, jsonify

import db

app = Flask(__name__)
DAILY_LIMIT = 5000


@app.post("/withdraw")
def withdraw():
    uid = request.json["uid"]
    amount = int(request.json["amount"])
    used = db.withdrawn_today(uid)
    # 限额查询与记账之间没有事务、也没有行锁
    if used + amount > DAILY_LIMIT:
        return jsonify({"error": "over limit"}), 403
    db.record_withdrawal(uid, amount)
    db.pay(uid, amount)
    return jsonify({"ok": True, "used": used + amount})
'''.strip("\n"), cand("并发竞态检查器", "E3·链级",
                    "并发可达报告: 请求入口 line 10 → 共享状态非原子 check-then-act "
                    "line 14-18(限额查询与记账之间无事务/行锁,并发提现可突破每日限额)")))

G22B.append(("g22b-race-02", "python", '''
# account/register.py -- 注册端点
from flask import Flask, request, jsonify

import db

app = Flask(__name__)


@app.post("/register")
def register():
    name = request.json["username"]
    if db.user_exists(name):
        return jsonify({"error": "taken"}), 409
    db.create_user(name, request.json["password"])
    db.grant_default_role(name)
    return jsonify({"ok": True, "user": name})
'''.strip("\n"), cand("并发竞态检查器", "E3·链级",
                    "并发可达报告: 请求入口 line 9 → TOCTOU line 12-14"
                    "(存在性检查与建号之间无唯一约束/锁,并发同名注册可覆盖已注册账号的口令)")))

G22B.append(("g22b-log-01", "python", '''
# audit/access_log.py -- 访问日志记录
from flask import Flask, request

app = Flask(__name__)


@app.after_request
def log_access(resp):
    ua = request.headers.get("User-Agent", "")
    with open("/var/log/access.log", "a") as fh:
        fh.write(request.remote_addr + " " + ua + "\\n")
    return resp
'''.strip("\n"), cand("污点分析", "E3·链级",
                    "完整污点链: source line 9 (request.headers.get(\"User-Agent\")) "
                    "→ sink line 11 (fh.write 写入行式日志)")))


def main():
    path = OUT / "g22b.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for orig, lang, code, extra in G22B:
            user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```" + extra + TAIL
            f.write(json.dumps({"orig": orig, "user": user}, ensure_ascii=False) + "\n")
    print(f"{path.name}: {len(G22B)}")
    print("\n== 候选行号校准 ==")
    for orig, lang, code, extra in G22B:
        lines = code.splitlines()
        print(f"  {orig}: {len(lines)} 行")
        for k in sorted({int(x) for x in re.findall(r"line (\d+)", extra)}):
            print(f"    L{k}: {lines[k-1] if k <= len(lines) else '<越界!>'}")


if __name__ == "__main__":
    main()
