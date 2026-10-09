# -*- coding: utf-8 -*-
"""§1.2 复核采信门分级放行——离线单测（2026-10-09）。

不依赖 LLM：直接测三态门 / 自动采信护栏 / 工单结构 / 监控键注册。
运行：python experiments/exp_06_finetune/audit/test_gate_20261009.py
"""
import os
import sys

sys.path.insert(0, r"D:\code\毕业设计\Graduation-Project")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from graduation_project.two_stage_scanner import TwoStageScanner, _MONITOR

scanner = TwoStageScanner.__new__(TwoStageScanner)  # 不走重初始化

FAILS = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    if not cond:
        FAILS.append(name)


# ---- 三态门：缺失型 → unverified（862 无确定性验证手段）
st, why = scanner._recheck_type_plausible(
    "def f(user_id):\n    return db.query(user_id)\n", "python", "CWE-862 Missing Authorization")
check("三态门·缺失型→unverified", st == "unverified", why)

# ---- 三态门：无编号标签（归一后 798 仍属缺失型）→ unverified
st, why = scanner._recheck_type_plausible(
    'API_KEY = "sk-1234567890abcd"\n', "python", "Secret Keyword")
check("三态门·无号归一798→unverified", st == "unverified", why)

# ---- 三态门：注入型有 sink 无防御 → plausible
st, why = scanner._recheck_type_plausible(
    'q = request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE x=" + q)\n',
    "python", "CWE-89 SQL Injection")
check("三态门·注入有sink无防御→plausible", st == "plausible", why)

# ---- 三态门：注入型唯一 sink 已参数化 → implausible
st, why = scanner._recheck_type_plausible(
    'q = request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE x=?", (q,))\n',
    "python", "CWE-89 SQL Injection")
check("三态门·参数化全防御→implausible", st == "implausible", why)

# ---- 三态门：判 XSS 但无任何渲染 sink → implausible
st, why = scanner._recheck_type_plausible(
    "x = 1 + 1\nprint(x)\n", "python", "CWE-79 XSS")
check("三态门·无sink→implausible", st == "implausible", why)

# ---- 自动采信护栏：T3/F0 + 有 sink → 放行
ok, note = scanner._unverified_autopass_ok(
    {"n": 3, "votes_true": 3, "votes_false": 0, "votes_invalid": 0},
    'q = request.args.get("q")\ncursor.execute("SELECT * FROM t WHERE x=" + q)\n')
check("autopass·T3F0有sink→True", ok is True, note)

# ---- 自动采信护栏：T3/F0 但无 sink 无外调 → §1.4 守卫拦截
ok, note = scanner._unverified_autopass_ok(
    {"n": 3, "votes_true": 3, "votes_false": 0, "votes_invalid": 0},
    "def helper(a):\n    return a + 1\n")
check("autopass·T3F0无sink无外调→False", ok is False, note)

# ---- 自动采信护栏：非严格全票 → 拒绝
for votes in ({"n": 3, "votes_true": 2, "votes_false": 1, "votes_invalid": 0},
              {"n": 3, "votes_true": 3, "votes_false": 0, "votes_invalid": 1},
              {"n": 1, "votes_true": 1, "votes_false": 0, "votes_invalid": 0}):
    ok, _ = scanner._unverified_autopass_ok(votes, "open(__file__).read()")
    check(f"autopass·票型{votes['votes_true']}/{votes['votes_false']}/{votes['votes_invalid']}→False",
          ok is False)

# ---- 工单结构（与 §3.3 裁决训据 schema 对齐的字段齐全）
ticket = scanner._recheck_ticket(
    {"n": 3, "votes_true": 3, "votes_false": 0, "votes_invalid": 0,
     "has_vulnerability": True, "vulnerability_type": "CWE-862", "risk_level": "high",
     "source": "line 3: user_id", "sink": "line 4: db.query", "explanation": "...",
     "types": ["CWE-862"]},
    "demo.php", "unverified", "缺失型，无确定性验证手段")
check("ticket·schema字段齐全",
      ticket["schema"] == "adjudication_ticket_v1"
      and ticket["votes"]["votes_true"] == 3
      and ticket["true_verdict"]["vulnerability_type"] == "CWE-862"
      and ticket["gate"]["state"] == "unverified")

# ---- 监控键注册（缺键会 KeyError，历史事故）
for k in ("recheck_unverified_autopass", "recheck_unverified_review",
          "recheck_unverified_guard_downgrade", "recheck_majority_true_review"):
    check(f"监控键注册·{k}", k in _MONITOR)

print()
if FAILS:
    print(f"== {len(FAILS)} 个用例失败: {FAILS}")
    sys.exit(1)
print("== §1.2 门控单测全部通过 ==")
